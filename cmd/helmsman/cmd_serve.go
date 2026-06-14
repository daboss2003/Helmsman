package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/helmsman/helmsman/internal/alertengine"
	"github.com/helmsman/helmsman/internal/alertstore"
	"github.com/helmsman/helmsman/internal/cfgstore"
	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/docker"
	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/edge"
	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/gitstore"
	"github.com/helmsman/helmsman/internal/hostmon"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
	"github.com/helmsman/helmsman/internal/opsclient"
	"github.com/helmsman/helmsman/internal/provision"
	"github.com/helmsman/helmsman/internal/provstore"
	"github.com/helmsman/helmsman/internal/retention"
	"github.com/helmsman/helmsman/internal/sandbox"
	"github.com/helmsman/helmsman/internal/setupstore"
	"github.com/helmsman/helmsman/internal/store"
	"github.com/helmsman/helmsman/internal/web"
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
		eng := alertengine.New(alertStore, mon.Snapshot, alertengine.Config{
			EvalInterval:      cfg.Alerting.EvalInterval.D(),
			NotifyMinInterval: cfg.Alerting.NotifyMinInterval.D(),
			QuietStartHour:    cfg.Alerting.QuietStartHour,
			QuietEndHour:      cfg.Alerting.QuietEndHour,
			DeadMansURL:       cfg.Alerting.DeadMansURL,
			DeadMansInterval:  cfg.Alerting.DeadMansInterval.D(),
			AdminURL:          cfg.Alerting.AdminURL,
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
			sup := &edge.Supervisor{CaddyBin: "caddy", AdminListen: base.AdminListen, Log: log}
			if initCfg, rerr := edge.Render(base, nil); rerr == nil {
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

	srv, err := web.New(cfg, web.Deps{
		DB:         db,
		ConfigPath: *configPath,
		Log:        log,
		Monitor:    mon,
		OpsStore:   opsStore,
		Prober:     prober,
		Runner:     runner,
		Docker:     dockerCli,
		EnvStore:   envStore,
		CfgStore:   cfgStore,
		GitStore:   gitStore,
		ProvStore:  provStore,
		SetupStore: setupStore,
		AlertStore: alertStore,
		EdgeRoutes: edgeRoutes,
		EdgeRecon:  edgeRecon,
		EdgeReason: edgeReason,
		DockerSem:  dockerSem,
	})
	if err != nil {
		return err
	}

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
