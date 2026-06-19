package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daboss2003/Helmsman/internal/store"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The reconciler renders the route set and POSTs the whole document to /load.
func TestReconcilePushesWholeConfig(t *testing.T) {
	var gotPath string
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gotPath != "/load" {
		t.Errorf("admin path = %q, want /load", gotPath)
	}
	if !strings.Contains(string(gotBody), "app.example.com") || !strings.Contains(string(gotBody), "web:8080") {
		t.Errorf("pushed config missing the route:\n%s", gotBody)
	}
}

// A non-2xx from the admin (Caddy rejected the config) surfaces as an error; the
// live config is unaffected (Caddy /load is transactional).
func TestLoadRejectionIsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad config"))
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String())
	if err := a.Load(context.Background(), []byte(`{}`)); err == nil {
		t.Error("a 4xx from the admin must be an error")
	}
}

// A render error (unsafe route) never reaches the admin.
func TestReconcileNeverAppliesUnsafe(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	// Insert an unsafe row directly (bypassing Save's validation) to prove render
	// is the backstop.
	_, _ = db.Exec(`INSERT INTO app_routes(hostname, upstream, upstream_scheme, enabled, created_at) VALUES('x.example.com','127.0.0.1:2019','http',1,0)`)
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	if err := rec.Reconcile(context.Background()); err == nil {
		t.Error("reconcile should fail on an unsafe route")
	}
	if called {
		t.Error("an unsafe config must never be pushed to the admin")
	}
}

// The admin client must NOT follow a redirect (a compromised Caddy could 307 the
// config POST elsewhere) — it surfaces the 3xx as a non-2xx error instead.
func TestAdminDoesNotFollowRedirects(t *testing.T) {
	hit := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		if r.URL.Path == "/load" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		t.Errorf("redirect was followed to %s", r.URL.Path)
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String())
	if err := a.Load(context.Background(), []byte(`{}`)); err == nil {
		t.Error("a 3xx must surface as an error, not be followed")
	}
	if hit != 1 {
		t.Errorf("expected exactly one request (no redirect follow), got %d", hit)
	}
}

// Concurrent reconciles must be serialized: no data race on lastGood, and the
// last writer's config is what ends up applied. Run with -race to catch the
// lastGood data race the mutex closes.
func TestReconcileConcurrentIsSerialized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rec.Reconcile(context.Background()) }()
	}
	wg.Wait()
	rec.mu.Lock()
	got := len(rec.lastGood)
	rec.mu.Unlock()
	if got == 0 {
		t.Error("lastGood should hold the latest applied config")
	}
}

// Over a unix socket the admin client always dials the socket regardless of URL host
// (the DialContext ignores the address), so the only thing Caddy sees is the request's
// Host header (= the base URL's host). Caddy's admin endpoint enforces an origin
// allow-list (enforce_origin: 127.0.0.1 / ::1 / localhost — see render.go); a Host of
// "unix" is rejected 403 "host not allowed: unix", and the edge config never loads.
// The unix-admin base host must therefore be one Caddy allows.
func TestUnixAdminHostIsAllowedOrigin(t *testing.T) {
	a := NewAdmin("unix//run/helmsman/caddy-admin.sock")
	allowed := map[string]bool{"http://127.0.0.1": true, "http://[::1]": true, "http://localhost": true}
	if !allowed[a.base] {
		t.Errorf("unix admin base = %q — its Host is not in Caddy's admin origin allow-list, so /load is 403'd (host not allowed). want one of %v", a.base, allowed)
	}
}

func TestAvailableFailClosedOffLinux(t *testing.T) {
	ok, why := Available("definitely-not-a-real-binary-xyz")
	if ok {
		t.Skip("host can own the edge")
	}
	if why == "" {
		t.Error("unavailable must carry a reason")
	}
}
