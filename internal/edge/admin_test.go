package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helmsman/helmsman/internal/store"
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

func TestAvailableFailClosedOffLinux(t *testing.T) {
	ok, why := Available("definitely-not-a-real-binary-xyz")
	if ok {
		t.Skip("host can own the edge")
	}
	if why == "" {
		t.Error("unavailable must carry a reason")
	}
}
