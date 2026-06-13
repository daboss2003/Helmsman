package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/helmsman/helmsman/internal/config"
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

	srv, err := web.New(cfg, db, *configPath, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
				}
			}
		}
	}()

	log.Info("helmsman serving",
		"bind", cfg.BindAddr, "edge_mode", string(cfg.Edge.Mode), "db", db.Path)
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	log.Info("helmsman stopped")
	return nil
}
