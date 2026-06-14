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

	"github.com/helmsman/helmsman/internal/cfgstore"
	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/docker"
	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/gitstore"
	"github.com/helmsman/helmsman/internal/hostmon"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
	"github.com/helmsman/helmsman/internal/opsclient"
	"github.com/helmsman/helmsman/internal/provision"
	"github.com/helmsman/helmsman/internal/provstore"
	"github.com/helmsman/helmsman/internal/retention"
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
	runner := dockerexec.NewRunner(dockerexec.NewSemaphore(), writeAllowed, writeReason)

	// Audit/events retention (M7, plan §16.1): bounds the events table so it can
	// never wedge the disk, while NEVER silently dropping a security row. Joined
	// before the deferred db.Close() (review #8).
	retentionRunner := retention.New(db, log, cfg.DataDir, toRetentionConfig(cfg))
	wg.Add(1)
	go func() { defer wg.Done(); retentionRunner.Run(ctx) }()

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
