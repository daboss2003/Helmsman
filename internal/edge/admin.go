package edge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Admin talks to the child Caddy's admin API — the SINGLE source of truth for its
// config (SBD-2). It is reached ONLY over a unix socket (preferred) or loopback
// :2019; there is no on-disk config Caddy auto-loads. /load is transactional:
// Caddy validates + atomically swaps, and REJECTS a bad document while keeping the
// running config — so a failed apply never takes the edge down (SBD-8 floor).
type Admin struct {
	base   string // http base, e.g. "http://127.0.0.1:2019" or "http://unix"
	client *http.Client
}

// NewAdmin builds an admin client for a Caddy admin listen address:
// "unix//run/helmsman/caddy-admin.sock" (dialed over the socket) or "127.0.0.1:2019".
func NewAdmin(listen string) *Admin {
	if strings.HasPrefix(listen, "unix/") {
		sock := strings.TrimPrefix(listen, "unix/") // "unix//x" → "/x"
		d := &net.Dialer{Timeout: 5 * time.Second}
		return &Admin{
			base: "http://unix",
			client: &http.Client{
				Timeout:       15 * time.Second,
				CheckRedirect: noRedirect,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return d.DialContext(ctx, "unix", sock)
					},
				},
			},
		}
	}
	return &Admin{base: "http://" + listen, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect}}
}

// noRedirect refuses to follow any redirect (consistent with every other Helmsman
// outbound client) — a compromised child Caddy must not be able to 307 the config
// POST (which carries the whole edge config) to an attacker endpoint.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Load POSTs the WHOLE config document to /load (declarative, never incremental).
// A non-2xx response means Caddy rejected it (the previous config keeps running).
func (a *Admin) Load(ctx context.Context, configJSON []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/load", bytes.NewReader(configJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("edge: admin /load unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("edge: admin rejected config (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Reconciler renders the WHOLE edge config from the declarative route set and
// pushes it via the admin API. It retains the last-known-good document so a
// caller can revert (SBD-8).
type Reconciler struct {
	store    *RouteStore
	overlay  *OverlayStore // Layer 2 (optional; nil = no operator overlay)
	admin    *Admin
	base     BaseConfig
	log      *slog.Logger
	lastGood []byte
}

// NewReconciler builds a Reconciler.
func NewReconciler(store *RouteStore, admin *Admin, base BaseConfig, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, admin: admin, base: base, log: log}
}

// WithOverlay attaches the Layer-2 operator overlay store. The overlay is
// re-validated as untrusted on every reconcile and stripped fail-closed if it is
// tampered or now conflicts with the managed routes (the apps stay up regardless).
func (r *Reconciler) WithOverlay(o *OverlayStore) *Reconciler { r.overlay = o; return r }

// Reconcile renders the current route set and applies it. On a render error
// (an unsafe route) it does NOT touch the live config. On an apply error the
// previous config keeps running (Caddy /load is transactional).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	routes, err := r.store.List()
	if err != nil {
		return fmt.Errorf("edge: list routes: %w", err)
	}

	// Layer 2: load the operator overlay (re-validated as untrusted by
	// RenderComposite). A tampered overlay is dropped fail-closed here with a
	// security audit; a DB error aborts (we don't risk applying a wrong config).
	var overlay []byte
	if r.overlay != nil {
		overlay, err = r.overlay.Active(ctx)
		if errors.Is(err, ErrOverlayTampered) {
			r.log.Warn("edge overlay tampered — dropping it (serving Layer 0+1 only)", "level", "security")
			overlay = nil
		} else if err != nil {
			return fmt.Errorf("edge: load overlay: %w", err)
		}
	}

	cfg, err := RenderComposite(r.base, routes, overlay)
	if err != nil {
		// The composite failed. If the overlay was the cause (it re-validates as
		// untrusted and may now conflict with a newly-added app route), strip it
		// and render Layer 0+1 only — apps stay up, the overlay is dropped
		// fail-closed with a loud audit. If Layer 0+1 ALSO fails, a managed route
		// is genuinely unsafe → abort (never apply a partial/unsafe config).
		if overlay == nil {
			return fmt.Errorf("edge: render: %w", err)
		}
		base, berr := Render(r.base, routes)
		if berr != nil {
			return fmt.Errorf("edge: render: %w", berr)
		}
		r.log.Warn("edge overlay invalid against current routes — stripping it (serving Layer 0+1 only)", "level", "security", "err", err)
		cfg = base
	}
	if err := r.admin.Load(ctx, cfg); err != nil {
		return err
	}
	r.lastGood = cfg
	return nil
}

// RevertToLastGood re-applies the last successfully-loaded config (SBD-8 recovery
// path; the typed base render is the floor when there is no last-good yet).
func (r *Reconciler) RevertToLastGood(ctx context.Context) error {
	cfg := r.lastGood
	if cfg == nil {
		var err error
		if cfg, err = Render(r.base, nil); err != nil {
			return err
		}
	}
	return r.admin.Load(ctx, cfg)
}
