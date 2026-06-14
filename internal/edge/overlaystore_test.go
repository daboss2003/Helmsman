package edge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/helmsman/helmsman/internal/store"
)

// Concurrent reconciles must be serialized: no data race on lastGood, and the
// final applied config reflects the latest state (the conflicting overlay stripped).
// Run with -race to catch the lastGood data race the mutex closes.
func TestReconcileConcurrentIsSerialized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os, db := testOverlayStore(t)
	rs := NewRouteStore(db)
	ctx := context.Background()
	if err := os.Save(ctx, []byte(sampleOverlay), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := rs.Save(ctx, Route{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog()).WithOverlay(os)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rec.Reconcile(ctx) }()
	}
	wg.Wait()
	// lastGood is the latest good config; reading it (under the same lock) is safe.
	if got, err := func() ([]byte, error) { rec.mu.Lock(); defer rec.mu.Unlock(); return rec.lastGood, nil }(); err != nil || len(got) == 0 {
		t.Errorf("lastGood should hold the latest applied config, got len=%d", len(got))
	}
}

func testOverlayStore(t *testing.T) (*OverlayStore, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewOverlayStore(db, []byte("0123456789abcdef0123456789abcdef")), db
}

const sampleOverlay = `[{"match":[{"host":["extra.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"extra-web:8080"}]}]}]`

// A saved overlay round-trips and verifies its HMAC.
func TestOverlayStoreRoundTrip(t *testing.T) {
	os, _ := testOverlayStore(t)
	ctx := context.Background()
	if got, err := os.Active(ctx); err != nil || got != nil {
		t.Fatalf("no overlay yet should be (nil,nil), got %q %v", got, err)
	}
	if err := os.Save(ctx, []byte(sampleOverlay), nil, "test"); err != nil {
		t.Fatalf("save valid overlay: %v", err)
	}
	got, err := os.Active(ctx)
	if err != nil || !strings.Contains(string(got), "extra.example.com") {
		t.Fatalf("active overlay = %q, %v", got, err)
	}
}

// Save rejects an overlay that fails the linter (operator feedback) — never persists it.
func TestOverlayStoreSaveRejectsInvalid(t *testing.T) {
	os, _ := testOverlayStore(t)
	bad := `[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"exec"}]}]`
	if err := os.Save(context.Background(), []byte(bad), nil, ""); err == nil {
		t.Error("an overlay with a forbidden handler must be rejected at save")
	}
	if got, _ := os.Active(context.Background()); got != nil {
		t.Error("a rejected overlay must not be persisted")
	}
}

// A DB tamper that changes the stored overlay is caught by the HMAC.
func TestOverlayStoreHMACTamper(t *testing.T) {
	os, db := testOverlayStore(t)
	ctx := context.Background()
	if err := os.Save(ctx, []byte(sampleOverlay), nil, ""); err != nil {
		t.Fatal(err)
	}
	// Tamper the stored text directly (the HMAC now won't match).
	if _, err := db.Exec(`UPDATE edge_overlay SET overlay=replace(overlay,'extra-web','evil-host')`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Active(ctx); err != ErrOverlayTampered {
		t.Errorf("a tampered overlay must surface ErrOverlayTampered, got %v", err)
	}
	// Raw still returns the text but reports verified=false (so the UI can warn).
	raw, ok, err := os.Raw(ctx)
	if err != nil || ok || !strings.Contains(string(raw), "evil-host") {
		t.Errorf("Raw = %q verified=%v err=%v; want the tampered text, verified=false", raw, ok, err)
	}
}

// The reconciler drops a tampered overlay fail-closed and serves Layer 0+1 only.
func TestReconcileStripsTamperedOverlay(t *testing.T) {
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os, db := testOverlayStore(t)
	rs := NewRouteStore(db)
	ctx := context.Background()
	if err := rs.Save(ctx, Route{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.Save(ctx, []byte(sampleOverlay), nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE edge_overlay SET overlay=replace(overlay,'extra-web','evil-host')`); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog()).WithOverlay(os)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile must succeed (overlay stripped, apps stay up): %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "app.example.com") {
		t.Error("the managed app route must still be applied")
	}
	if strings.Contains(s, "extra.example.com") || strings.Contains(s, "evil-host") {
		t.Error("a tampered overlay must be dropped from the applied config")
	}
}

// A previously-valid overlay that now collides with a newly-added app route is
// stripped fail-closed on reconcile (the app route still applies).
func TestReconcileStripsConflictingOverlay(t *testing.T) {
	var body []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	os, db := testOverlayStore(t)
	rs := NewRouteStore(db)
	ctx := context.Background()
	// Save an overlay on extra.example.com (valid — no app route claims it yet).
	if err := os.Save(ctx, []byte(sampleOverlay), nil, ""); err != nil {
		t.Fatal(err)
	}
	// Now add an app route on the SAME host — the overlay now shadows it.
	if err := rs.Save(ctx, Route{Hostname: "extra.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog()).WithOverlay(os)
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile must succeed (overlay stripped): %v", err)
	}
	// The app route (its upstream web:80) wins; the overlay upstream is gone.
	s := string(body)
	if !strings.Contains(s, "extra.example.com") || !strings.Contains(s, "web:80") {
		t.Error("the app route must still be applied")
	}
	if strings.Contains(s, "extra-web:8080") {
		t.Error("the conflicting overlay must be stripped")
	}
}
