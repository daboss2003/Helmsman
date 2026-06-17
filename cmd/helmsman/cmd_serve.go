package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/daboss2003/Helmsman/internal/alertengine"
	"github.com/daboss2003/Helmsman/internal/alertstore"
	"github.com/daboss2003/Helmsman/internal/apitoken"
	"github.com/daboss2003/Helmsman/internal/backupstore"
	"github.com/daboss2003/Helmsman/internal/cfgstore"
	"github.com/daboss2003/Helmsman/internal/config"
	"github.com/daboss2003/Helmsman/internal/docker"
	"github.com/daboss2003/Helmsman/internal/dockerexec"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/envstore"
	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/hostmon"
	"github.com/daboss2003/Helmsman/internal/l4"
	"github.com/daboss2003/Helmsman/internal/monitor"
	"github.com/daboss2003/Helmsman/internal/ops"
	"github.com/daboss2003/Helmsman/internal/opsclient"
	"github.com/daboss2003/Helmsman/internal/provision"
	"github.com/daboss2003/Helmsman/internal/provstore"
	"github.com/daboss2003/Helmsman/internal/retention"
	"github.com/daboss2003/Helmsman/internal/sandbox"
	"github.com/daboss2003/Helmsman/internal/scale"
	"github.com/daboss2003/Helmsman/internal/selfheal"
	"github.com/daboss2003/Helmsman/internal/setupstore"
	"github.com/daboss2003/Helmsman/internal/socketproxy"
	"github.com/daboss2003/Helmsman/internal/store"
	"github.com/daboss2003/Helmsman/internal/web"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err // fail-closed: refuse to boot
	}

	db, err := store.Open(filepath.Join(cfg.DataDir, "helmsman.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	// Fail-closed key/DB sentinel check (plan §5.1; review #21): if a key-check
	// sentinel exists, the configured key MUST open it, else refuse to boot rather
	// than seal future writes under a key that can't read existing rows.
	if err := checkKeySentinel(cfg, db); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Master cipher for secrets at rest (ops shared secrets in M3, env in M5).
	cipher, err := openCipher(cfg)
	if err != nil {
		return err
	}

	// Read plane (M2/M3): poll Docker via the loopback socket-proxy, sample host,
	// and probe the App Ops Interface (M3). The poller is joined before the
	// deferred db.Close() so no DB write can race the close (review #8).
	dockerCli := docker.New(cfg.Docker.ProxyAddr)
	hostSampler := hostmon.New(cfg.DataDir)
	opsStore := ops.NewConfigStore(db, cipher)
	prober := ops.NewProber(opsStore, opsclient.New(), db)
	envStore := envstore.New(db, cipher)
	cfgStore := cfgstore.New(db, cipher)
	gitStore := gitstore.New(db, cipher)
	provStore := provstore.New(db)
	// Clear any stale staging/aside dirs from an interrupted provision commit
	// (plan §7 boot-time sweep). The apps root is a sibling of DataDir.
	provision.SweepStaging(cfg.DataDir + "-apps")
	mon := monitor.New(db, dockerCli, hostSampler, cfg.Monitor.PollInterval.D(),
		cfg.Monitor.MetricsRetention.D(), log, prober)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mon.Run(ctx) }()

	// Write plane (M4): the §0 ≥1 GB resource gate + the global one-docker-child
	// semaphore + static-argv exec wrapper.
	var memTotal uint64
	if hs, herr := hostSampler.Sample(); herr == nil {
		memTotal = hs.MemTotal
	}
	writeAllowed, writeReason := dockerexec.WritePlaneGate(memTotal)
	if !writeAllowed {
		log.Warn("write plane disabled", "reason", writeReason)
	} else if writeReason != "" {
		log.Info("write plane armed", "note", writeReason)
	}
	// The global one-docker-child semaphore is SHARED by the write-plane runner and
	// the setup sandbox (plan §4: one docker child across poller+deploy+sandbox).
	dockerSem := dockerexec.NewSemaphore()
	runner := dockerexec.NewRunner(dockerSem, writeAllowed, writeReason)

	// Helmsman MANAGES its own read-only socket-proxy (plan §3) so the operator never
	// runs a docker command — they only ever write helmsman.yaml. Bring it up in the
	// background (the first run may pull the image) and ungated (the read plane must
	// work even on a sub-1 GB box). Best-effort: a failure just leaves the read plane
	// "unavailable" until it is up. Set docker.external_proxy to opt out (you run your
	// own proxy/endpoint at docker.proxy_addr).
	// The managed proxy is the read-plane SECURITY BOUNDARY, and because Helmsman now
	// runs it as a compose project it shows up as a normal app in the snapshot. Protect
	// it from EVERY write path (lifecycle stop/redeploy, self-heal restart, auto-scale)
	// exactly like the edge — it must never be a target. This must not depend on the
	// operator remembering to list it, so seed it BEFORE the web server and the
	// self-heal watcher read cfg.ProtectedProjects (review finding).
	protectManagedProxy(cfg)

	if !cfg.Docker.ExternalProxy {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec, cancel := context.WithTimeout(ctx, 90*time.Second) // allow a first-run image pull
			defer cancel()
			log.Info("ensuring the managed read-only docker socket-proxy is running")
			if err := socketproxy.EnsureRunning(ec, runner, cfg.DataDir, func(line string) { log.Debug("socket-proxy", "out", line) }); err != nil {
				log.Warn("could not start the managed socket-proxy; the read plane stays unavailable until it is up", "err", err)
			} else {
				log.Info("managed read-only docker socket-proxy is up", "addr", cfg.Docker.ProxyAddr)
			}
		}()
	} else {
		log.Info("docker.external_proxy set; Helmsman will NOT manage the socket-proxy", "addr", cfg.Docker.ProxyAddr)
	}

	// Setup sandbox (M9, Mode 3 — OFF by default, hard-gated). Fail-closed boot
	// precondition: if setup is enabled the host MUST provide a working sandbox
	// (plan §5.1) or we refuse to boot.
	setupStore := setupstore.New(db, cipher)
	if cfg.Setup.Enabled {
		if ok, why := sandbox.Available(); !ok {
			return fmt.Errorf("setup.enabled but no working sandbox: %s", why)
		}
	}

	// Audit/events retention (M7, plan §16.1): bounds the events table so it can
	// never wedge the disk, while NEVER silently dropping a security row. Joined
	// before the deferred db.Close() (review #8).
	retentionRunner := retention.New(db, log, cfg.DataDir, toRetentionConfig(cfg))
	wg.Add(1)
	go func() { defer wg.Done(); retentionRunner.Run(ctx) }()

	// Alert engine (M10, plan §8): read-and-notify only. Runs only when enabled;
	// the evaluator + notifier + heartbeat are joined before the deferred db.Close.
	alertStore := alertstore.New(db, cipher)
	if cfg.Alerting.Enabled {
		// The "open in dashboard" link in notifications is derived from admin.hostname
		// (we already know where the dashboard lives) — no separate admin_url.
		adminURL := ""
		if cfg.Admin.Hostname != "" {
			adminURL = "https://" + cfg.Admin.Hostname
		}
		eng := alertengine.New(alertStore, mon.Snapshot, alertengine.Config{
			EvalInterval:      cfg.Alerting.EvalInterval.D(),
			NotifyMinInterval: cfg.Alerting.NotifyMinInterval.D(),
			QuietStartHour:    cfg.Alerting.QuietStartHour,
			QuietEndHour:      cfg.Alerting.QuietEndHour,
			DeadMansURL:       cfg.Alerting.DeadMansURL,
			DeadMansInterval:  cfg.Alerting.DeadMansInterval.D(),
			AdminURL:          adminURL,
		}, log)
		wg.Add(3)
		go func() { defer wg.Done(); eng.RunEvaluator(ctx) }()
		go func() { defer wg.Done(); eng.RunNotifier(ctx) }()
		go func() { defer wg.Done(); eng.RunHeartbeat(ctx) }()
		log.Info("alert engine started", "eval_interval", cfg.Alerting.EvalInterval.D())
	}

	// Managed edge (M11, plan §6): Helmsman owns a child Caddy. The route set is
	// declarative; the whole Caddy config is rendered from typed structs + pushed
	// via the admin API. Fail-closed: in external mode, or on a host that can't own
	// the edge (non-Linux / no caddy), the edge isn't started — routes still save
	// and apply once the edge is up. The supervisor is joined before db.Close.
	edgeRoutes := edge.NewRouteStore(db)
	selfHealStore := selfheal.NewStore(db)
	scalingStore := scale.NewStore(db)
	apiTokenStore := apitoken.NewStore(db)
	// Encrypted Helmsman-state backups (master key reused as the AES-256 key; restore
	// needs the same key, which the operator already backs up out-of-band).
	var backupStore *backupstore.Store
	if key, kerr := config.DecodeKey(cfg.EncryptionKey); kerr == nil {
		backupStore = backupstore.New(db, filepath.Join(cfg.DataDir, "backups"), key)
	}
	var edgeRecon *edge.Reconciler
	edgeReason := ""
	if cfg.Edge.Mode == config.EdgeManaged {
		base := edge.BaseConfig{
			AdminListen:    edgeAdminListen(cfg),
			ACMEEmail:      cfg.Edge.ACMEEmail,
			ACMECA:         cfg.Edge.ACMECA,
			AdminHostname:  cfg.Admin.Hostname,
			AdminAllowlist: cfg.IPAllowlist,
			AdminUpstream:  cfg.BindAddr,
		}
		if ok, why := edge.Available(""); ok {
			admin := edge.NewAdmin(base.AdminListen)
			edgeRecon = edge.NewReconciler(edgeRoutes, admin, base, log)
			// cert_bindings: the edge issues a cert-only ACME subject per hostname.
			edgeRecon.SetCertHosts(cfgStore.AllCertHostnames)
			sup := &edge.Supervisor{CaddyBin: "caddy", AdminListen: base.AdminListen, Log: log}
			if initCfg, rerr := edge.Render(base, nil, nil); rerr == nil {
				sup.InitialCfg = initCfg
			}
			wg.Add(1)
			go func() { defer wg.Done(); sup.Run(ctx) }()
			log.Info("managed edge started", "admin", base.AdminListen)
		} else {
			edgeReason = why
			log.Warn("managed edge not owned on this host", "reason", why)
		}
	} else {
		edgeReason = "external edge mode — Helmsman does not own the edge"
	}

	// Managed L4 (TCP/UDP) load balancer (opt-in via edge.l4_enabled): a supervised
	// child nginx-stream fronting fixed public ports (DNS/DoT/MQTTS) for internal
	// replica pools. Off by default; fail-closed if the host can't own it.
	var l4Routes *l4.RouteStore
	var l4Reconcile func(context.Context) error
	if cfg.Edge.Mode == config.EdgeManaged && cfg.Edge.L4Enabled {
		if ok, why := l4.Available(); ok {
			l4Routes = l4.NewRouteStore(db)
			l4dir := filepath.Join(cfg.DataDir, "l4")
			sup := &l4.Supervisor{
				ConfigPath: filepath.Join(l4dir, "nginx.conf"),
				Prefix:     l4dir,
				Digest:     cfg.Edge.L4NginxDigest,
				Log:        log,
			}
			l4Reconcile = func(c context.Context) error {
				rs, lerr := l4Routes.List()
				if lerr != nil {
					return lerr
				}
				return sup.Reconcile(c, rs)
			}
			if rerr := l4Reconcile(ctx); rerr != nil { // write the initial config from the store
				log.Warn("l4: initial reconcile failed", "err", rerr)
			}
			wg.Add(1)
			go func() { defer wg.Done(); sup.Run(ctx) }()
			log.Info("managed L4 LB started")
		} else {
			log.Warn("managed L4 LB not owned on this host", "reason", why)
		}
	}

	srv, err := web.New(cfg, web.Deps{
		DB:          db,
		ConfigPath:  *configPath,
		Log:         log,
		Monitor:     mon,
		OpsStore:    opsStore,
		Prober:      prober,
		Runner:      runner,
		Docker:      dockerCli,
		EnvStore:    envStore,
		CfgStore:    cfgStore,
		GitStore:    gitStore,
		ProvStore:   provStore,
		SetupStore:  setupStore,
		AlertStore:  alertStore,
		EdgeRoutes:  edgeRoutes,
		EdgeRecon:   edgeRecon,
		EdgeReason:  edgeReason,
		L4Routes:    l4Routes,
		L4Reconcile: l4Reconcile,
		SelfHeal:    selfHealStore,
		Scaling:     scalingStore,
		DockerSem:   dockerSem,
		APITokens:   apiTokenStore,
		Backups:     backupStore,
	})
	if err != nil {
		return err
	}

	// Self-healing supervisor (M13, plan §8.5): a bounded watcher at the poll cadence
	// that acts ONLY through the gated write path (srv.Remediate via RunHeld) behind
	// the four safety gates — it can only reduce pressure or page. Joined before the
	// deferred db.Close(). Infra alerts route through the engine only when alerting is
	// enabled; otherwise a give-up is logged.
	shPolicy := selfheal.DefaultPolicy()
	protected := map[string]bool{}
	for _, p := range cfg.ProtectedProjects {
		protected[p] = true
	}
	var shAlerts *alertstore.Store
	if cfg.Alerting.Enabled {
		shAlerts = alertStore
	}
	watcher := selfheal.New(selfheal.Config{
		Store:        selfHealStore,
		Alerts:       shAlerts,
		Snap:         mon.Snapshot,
		Sem:          dockerSem,
		Act:          srv,
		Policy:       shPolicy,
		Log:          log,
		Interval:     cfg.Monitor.PollInterval.D(),
		FloorBytes:   256 << 20, // memory-headroom floor for a momentary old+new during a restart
		WritePlaneOK: writeAllowed,
		Protected:    protected,
	})
	srv.SetCircuitClearer(func(p, svc string) { watcher.ClearCircuit(selfheal.Key{App: p, Service: svc}) })
	wg.Add(1)
	go func() { defer wg.Done(); watcher.Run(ctx) }()

	// Opt-in auto-scaler (M14, plan §8A): one controller goroutine. OFF unless a
	// per-service policy is enabled; the host-capacity guard caps every decision and
	// collapses to effective_max=1 on a near-OOM box. Scaler = the gated web write
	// path (srv via RunHeld); edge pool reconcile is left to DNS round-robin in v1.
	// Joined before the deferred db.Close.
	scaler := scale.New(scale.Config{
		Store:        scalingStore,
		Alerts:       shAlerts,
		Snap:         mon.Snapshot,
		Sem:          dockerSem,
		Scaler:       srv,
		Log:          log,
		Interval:     cfg.Monitor.PollInterval.D(),
		WritePlaneOK: writeAllowed,
		HostCPUMilli: uint64(runtime.NumCPU() * 1000),
		// Runtime candidacy re-check (C3/C4) from docker inspect, every tick: a
		// service that gains a shared RW volume or now runs a stateful image loses
		// candidacy and is scaled back to the floor (closes a post-enable compose
		// change). C1/C2/C6 stay operator-attested at enable time (full compose-
		// derived candidacy lands with the typed model in M15).
		IsCandidate: func(app, service string) (scale.ServiceSpec, bool) {
			spec := scale.ServiceSpec{EdgeUpstream: true, StatelessContract: true}
			if snap := mon.Snapshot(); snap != nil {
				if a := snap.AppByProject(app); a != nil {
					for _, svc := range a.Services {
						if svc.Service == service {
							spec.RWVolume = svc.HasRWVolume
							spec.Stateful = scale.StatefulImage(svc.Image)
						}
					}
				}
			}
			return spec, true
		},
		Reserves: scale.Reserves{
			MemReserveBytes:    384 << 20, // control plane + edge slice + headroom
			MemFreeFloor:       256 << 20,
			NearOOMFreeBytes:   256 << 20,
			PerReplicaMemFloor: 16 << 20,
			CPUReserveMilli:    500,
		},
	})
	wg.Add(1)
	go func() { defer wg.Done(); scaler.Run(ctx) }()

	// Connected-repo auto-fetch poller (Netlify-style): a repo connected in the
	// dashboard "just works" with no webhook — Helmsman FETCHES every connected repo on
	// a cadence (read-plane only; it never deploys, it surfaces an "update available"
	// the operator deploys with a click). Joined before db.Close.
	wg.Add(1)
	go func() { defer wg.Done(); srv.RunGitPoller(ctx, cfg.Git.PollIntervalD()) }()

	// SIGHUP hot-reloads the allowlist + auth (plan §5.1), never keys/bind.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := srv.Reload(ctx); err != nil {
					log.Error("config reload rejected; keeping previous", "err", err)
				} else {
					log.Info("config reloaded (allowlist + auth)")
					// srv.Reload already validated the file; re-read it to hot-swap the
					// Tier-1 retention policy too (plan §16.1 SIGHUP-reloadable).
					if newCfg, lerr := config.Load(*configPath); lerr == nil {
						retentionRunner.SetConfig(toRetentionConfig(newCfg))
						log.Info("retention policy reloaded")
					}
				}
			}
		}
	}()

	log.Info("helmsman serving",
		"bind", cfg.BindAddr, "edge_mode", string(cfg.Edge.Mode), "db", db.Path)
	runErr := srv.Run(ctx)
	// Cancel ctx (idempotent if a signal already did) so the poller exits, then
	// join it before the deferred db.Close() runs (review #8).
	stop()
	wg.Wait()
	if runErr != nil {
		return fmt.Errorf("server: %w", runErr)
	}
	log.Info("helmsman stopped")
	return nil
}

// protectManagedProxy seeds the managed socket-proxy's compose project into the
// protected set so it can never be a lifecycle/self-heal/scale target. It is a no-op
// when the operator runs their own proxy (external_proxy) or when the project is
// already listed (idempotent). The proxy is the read-plane security boundary;
// protection must not depend on the operator remembering to list it.
func protectManagedProxy(cfg *config.Config) {
	if cfg.Docker.ExternalProxy {
		return
	}
	for _, p := range cfg.ProtectedProjects {
		if p == socketproxy.Project {
			return
		}
	}
	cfg.ProtectedProjects = append(cfg.ProtectedProjects, socketproxy.Project)
}

// edgeAdminListen returns the Caddy admin listen address — the operator's
// admin.listen if set (must be a unix socket / loopback, validated at boot), else
// the preferred unix socket (SBD-2).
func edgeAdminListen(cfg *config.Config) string {
	if cfg.Admin.Listen != "" {
		return cfg.Admin.Listen
	}
	return "unix//run/helmsman/caddy-admin.sock"
}

// toRetentionConfig maps the validated Tier-1 config block to the runner's policy
// (durations unwrapped, archive cap converted MB→bytes).
func toRetentionConfig(cfg *config.Config) retention.Config {
	return retention.Config{
		Interval:        cfg.Retention.Interval.D(),
		EventsMaxAge:    cfg.Retention.EventsMaxAge.D(),
		EventsMaxRows:   cfg.Retention.EventsMaxRows,
		ArchiveMaxBytes: int64(cfg.Retention.ArchiveMaxMB) << 20,
	}
}
