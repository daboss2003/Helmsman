package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Admin talks to the child Caddy's admin API — the SINGLE source of truth for its
// config (SBD-2). It is reached ONLY over a unix socket (preferred) or loopback
// :2019; there is no on-disk config Caddy auto-loads. /load is transactional:
// Caddy validates + atomically swaps, and REJECTS a bad document while keeping the
// running config — so a failed apply never takes the edge down (SBD-8 floor).
type Admin struct {
	base   string // http base, e.g. "http://127.0.0.1:2019" or "http://localhost" (unix socket)
	client *http.Client
}

// NewAdmin builds an admin client for a Caddy admin listen address:
// "unix//run/helmsman/caddy-admin.sock" (dialed over the socket) or "127.0.0.1:2019".
func NewAdmin(listen string) *Admin {
	if strings.HasPrefix(listen, "unix/") {
		sock := strings.TrimPrefix(listen, "unix/") // "unix//x" → "/x"
		d := &net.Dialer{Timeout: 5 * time.Second}
		return &Admin{
			// "localhost", NOT "unix": the DialContext below always dials the socket
			// (it ignores the URL host), so this only sets the request's Host header —
			// and Caddy's admin endpoint enforces an origin allow-list (enforce_origin:
			// 127.0.0.1/::1/localhost, see render.go). "http://unix" → Host: unix →
			// 403 "host not allowed: unix"; "localhost" is allowed and is Caddy's own
			// unix-admin convention (curl --unix-socket … http://localhost/…).
			base: "http://localhost",
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
	store     *RouteStore
	admin     *Admin
	base      BaseConfig
	log       *slog.Logger
	certHosts func() []string // cert-only ACME subjects (spec.cert_bindings); may be nil
	mu        sync.Mutex      // serializes Reconcile/Revert: read→render→Load→lastGood is atomic
	lastGood  []byte
}

// NewReconciler builds a Reconciler.
func NewReconciler(store *RouteStore, admin *Admin, base BaseConfig, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, admin: admin, base: base, log: log}
}

// SetCertHosts registers a provider for cert-only ACME subjects (hostnames Helmsman
// must obtain a cert for without a proxy route — spec.cert_bindings).
func (r *Reconciler) SetCertHosts(fn func() []string) { r.certHosts = fn }

func (r *Reconciler) certOnly() []string {
	if r.certHosts == nil {
		return nil
	}
	return r.certHosts()
}

// Reconcile renders the current route set and applies it. On a render error
// (an unsafe route) it does NOT touch the live config. On an apply error the
// previous config keeps running (Caddy /load is transactional).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	// Serialize the whole read→render→Load→lastGood sequence. Without this, two
	// concurrent reconciles (e.g. two route saves racing) could read different DB
	// snapshots and have their /load calls complete OUT OF ORDER, landing a stale
	// config after a newer one (and racing lastGood). With the lock, whichever
	// reconcile runs last re-reads the current state and wins.
	r.mu.Lock()
	defer r.mu.Unlock()
	routes, err := r.store.List()
	if err != nil {
		return fmt.Errorf("edge: list routes: %w", err)
	}
	cfg, err := Render(r.base, routes, r.certOnly())
	if err != nil {
		return fmt.Errorf("edge: render: %w", err) // unsafe route → never applied
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
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.lastGood
	if cfg == nil {
		var err error
		if cfg, err = Render(r.base, nil, nil); err != nil {
			return err
		}
	}
	return r.admin.Load(ctx, cfg)
}
