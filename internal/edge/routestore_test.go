package edge

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/Helmsman/internal/store"
)

func newRouteStore(t *testing.T) *RouteStore {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRouteStore(db)
}

func TestRouteStoreRoundTripAndRender(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, Route{Hostname: "App.Example.com", Upstream: "shop-web:8080", UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	routes, err := s.List()
	if err != nil || len(routes) != 1 {
		t.Fatalf("list: %v %d", err, len(routes))
	}
	if routes[0].Hostname != "app.example.com" { // normalized lowercase
		t.Errorf("hostname not normalized: %q", routes[0].Hostname)
	}
	// The stored set renders to a valid config.
	if _, err := Render(baseCfg(), routes); err != nil {
		t.Fatalf("render stored routes: %v", err)
	}
	_ = s.Delete(ctx, routes[0].ID())
	if r, _ := s.List(); len(r) != 0 {
		t.Error("route not deleted")
	}
}

// The store refuses to persist an unsafe route (control-plane upstream).
func TestRouteStoreRejectsControlPlaneUpstream(t *testing.T) {
	s := newRouteStore(t)
	if err := s.Save(context.Background(), Route{Hostname: "x.example.com", Upstream: "127.0.0.1:9000", UpstreamScheme: "http", Enabled: true}); err == nil {
		t.Error("a control-plane upstream must be rejected at the store")
	}
}
