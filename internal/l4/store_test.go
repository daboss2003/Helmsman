package l4

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func newRouteStore(t *testing.T) *RouteStore {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "l4.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRouteStore(db)
}

func TestReplaceProjectAndList(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "dns", []Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353, LB: "hash_client_ip"},
		{Listen: 53, Protocol: "tcp", Service: "coredns", Port: 5353},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List()
	if err != nil || len(got) != 2 {
		t.Fatalf("list: n=%d err=%v", len(got), err)
	}
	// Re-applying the same project REPLACES (no duplicates), and can shrink the set.
	if err := s.ReplaceProject(ctx, "dns", []Route{
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853, LB: "least_conn"},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.List()
	if len(got) != 1 || got[0].Listen != 853 {
		t.Fatalf("re-apply must replace the project's routes, got %+v", got)
	}
}

func TestTwoProjectsCoexist(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "dns", []Route{{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceProject(ctx, "mqtt", []Route{{Listen: 8883, Protocol: "tcp", Service: "mosquitto", Port: 1883}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(); len(got) != 2 {
		t.Fatalf("two projects' routes should coexist, got %d", len(got))
	}
}

func TestListenerCollisionAcrossProjectsRejected(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "dns", []Route{{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353}}); err != nil {
		t.Fatal(err)
	}
	// A second app claiming the same listen+protocol must be rejected (UNIQUE),
	// and the first app's route must remain intact.
	err := s.ReplaceProject(ctx, "other", []Route{{Listen: 53, Protocol: "udp", Service: "x", Port: 5353}})
	if err == nil {
		t.Fatal("a cross-project listener collision must be rejected")
	}
	got, _ := s.List()
	if len(got) != 1 || got[0].Service != "coredns" {
		t.Fatalf("the original owner's route must survive a rejected collision, got %+v", got)
	}
}

func TestReplaceProjectRejectsInvalidRoute(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	err := s.ReplaceProject(ctx, "dns", []Route{{Listen: 443, Protocol: "tcp", Service: "x", Port: 5353}})
	if err == nil {
		t.Fatal("an invalid route (reserved port) must be rejected")
	}
	if got, _ := s.List(); len(got) != 0 {
		t.Fatalf("nothing should be inserted on a validation failure, got %d", len(got))
	}
}
