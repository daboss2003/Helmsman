package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/edge"
	"github.com/helmsman/helmsman/internal/store"
)

// cmdEdge is the SSH-only edge recovery surface (plan §6.2 "iron escape hatch").
// It runs from the trusted root-of-trust context, never the web. The one
// subcommand today is restore-default.
func cmdEdge(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: helmsman edge restore-default [--config PATH]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "restore-default":
		return cmdEdgeRestoreDefault(rest)
	default:
		return fmt.Errorf("unknown edge subcommand %q (try: restore-default)", sub)
	}
}

// cmdEdgeRestoreDefault is the iron escape hatch: it DROPS the Layer-2 operator
// overlay (saving an empty overlay version) and re-derives + re-applies Layer 0
// (the protected base + admin allowlist, from typed structs) ⊕ Layer 1 (the
// app routes) — so the edge is never irrecoverable from a bad overlay. App routes
// are KEPT. If the child Caddy is reachable the clean config is pushed now;
// otherwise the dropped overlay simply means the next reconcile is clean.
func cmdEdgeRestoreDefault(args []string) error {
	fs := flag.NewFlagSet("edge restore-default", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "helmsman.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	// Validate the key against the DB sentinel before any write (consistent with serve).
	if err := checkKeySentinel(cfg, db); err != nil {
		return err
	}
	encKey, err := config.DecodeKey(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	// Drop the overlay (save an empty version). An empty overlay is always valid,
	// so the managed-host set is irrelevant here.
	overlay := edge.NewOverlayStore(db, encKey)
	if err := overlay.Save(context.Background(), nil, nil, "restore-default (CLI)"); err != nil {
		return fmt.Errorf("drop overlay: %w", err)
	}
	fmt.Println("edge: Layer-2 operator overlay dropped (app routes kept).")

	if cfg.Edge.Mode != config.EdgeManaged {
		fmt.Println("edge: external mode — nothing to re-apply (Helmsman does not own the edge).")
		return nil
	}

	// Re-derive Layer 0 ⊕ 1 from typed structs and push it now, if the edge is up.
	base := edge.BaseConfig{
		AdminListen:    edgeAdminListen(cfg),
		ACMEEmail:      cfg.Edge.ACMEEmail,
		ACMECA:         cfg.Edge.ACMECA,
		AdminHostname:  cfg.Admin.Hostname,
		AdminAllowlist: cfg.IPAllowlist,
		AdminUpstream:  cfg.BindAddr,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rec := edge.NewReconciler(edge.NewRouteStore(db), edge.NewAdmin(base.AdminListen), base, log).WithOverlay(overlay)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := rec.Reconcile(ctx); err != nil {
		// Not fatal: the overlay is already dropped, so the next serve reconcile is
		// clean. We report it so the operator knows the live push didn't land.
		fmt.Printf("edge: could not re-apply now (%v) — it applies on next start.\n", err)
		return nil
	}
	fmt.Println("edge: clean Layer 0 + app routes re-applied to the running edge.")
	return nil
}
