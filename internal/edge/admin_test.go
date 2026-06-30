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
	"sync/atomic"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
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

// A discovered replica pool replaces the single service-name dial and lights up the
// least-conn + passive-health machinery (auto-scaling edge pool).
func TestReconcileAppliesDiscoveredPool(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route) map[string][]string {
		return map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080", "172.18.0.6:8080"}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, want := range []string{"172.18.0.5:8080", "172.18.0.6:8080", "least_conn", "passive"} {
		if !strings.Contains(string(gotBody), want) {
			t.Errorf("pushed config missing %q:\n%s", want, gotBody)
		}
	}
	// The pool overrides the service-name selector — it must not also be dialed.
	if strings.Contains(string(gotBody), "web:8080") {
		t.Errorf("a pooled route should not also dial the service name:\n%s", gotBody)
	}
}

// An empty discovery result (no live replica IPs, or the socket-proxy down) is
// fail-safe: the route keeps its single service-name dial and gets no LB machinery.
func TestReconcileEmptyPoolKeepsSingleDial(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	_ = rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true})
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route) map[string][]string { return nil })
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !strings.Contains(string(gotBody), "web:8080") {
		t.Errorf("empty discovery must keep the single service-name dial:\n%s", gotBody)
	}
	if strings.Contains(string(gotBody), "least_conn") {
		t.Errorf("a single dial must not get LB machinery:\n%s", gotBody)
	}
}

// Reconcile is idempotent: re-rendering the same route set (the steady pool-refresh
// case) is byte-identical to the last applied config, so it skips the Caddy /load.
func TestReconcileIdempotentSkipsReload(t *testing.T) {
	var loads int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&loads, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	_ = rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true})
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	for i := 0; i < 3; i++ {
		if err := rec.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Errorf("3 identical reconciles → %d /load calls, want 1 (idempotent skip)", got)
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

// Caddy's admin endpoint enforces an origin allow-list (enforce_origin:
// 127.0.0.1 / ::1 / localhost, no port — see render.go) and checks BOTH the request's
// Host header AND its Origin header. Over a unix socket the DialContext always dials
// the socket (ignoring the URL host), so what Caddy sees is the Host (= base URL host)
// and the Origin header. Both must be in the allow-list: a Host of "unix" → 403 "host
// not allowed: unix"; an empty Origin → 403 "client is not allowed to access from
// origin ”". So base host and origin host must both be allowed.
func TestUnixAdminHostIsAllowedOrigin(t *testing.T) {
	a := NewAdmin("unix//run/mooring/caddy-admin.sock")
	allowed := map[string]bool{"http://127.0.0.1": true, "http://[::1]": true, "http://localhost": true}
	if !allowed[a.base] {
		t.Errorf("unix admin base = %q — its Host is not in Caddy's admin origin allow-list, so /load is 403'd (host not allowed). want one of %v", a.base, allowed)
	}
	if !allowed[a.origin] {
		t.Errorf("unix admin origin = %q — not in Caddy's allow-list, so /load is 403'd (origin ''). want one of %v", a.origin, allowed)
	}
}

// End-to-end: a /load request must carry a non-empty Origin header whose host is in
// Caddy's allow-list (the bare host, no admin port). Without it Caddy 403s "origin ”".
func TestAdminSendsAllowedOriginHeader(t *testing.T) {
	var gotOrigin, gotHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin, gotHost = r.Header.Get("Origin"), r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String()) // httptest binds 127.0.0.1:PORT
	if err := a.Load(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotOrigin != "http://127.0.0.1" { // host only, NO port (Caddy origins are bare hosts)
		t.Errorf("Origin header = %q, want http://127.0.0.1", gotOrigin)
	}
	if !strings.HasPrefix(gotHost, "127.0.0.1") {
		t.Errorf("Host header = %q, want 127.0.0.1[:port]", gotHost)
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
