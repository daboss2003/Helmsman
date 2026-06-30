package provstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestProvStoreRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, App{Slug: "shop", Source: "generated", ComposePath: "docker-compose.yml", SpecJSON: `{"slug":"shop"}`}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("shop")
	if err != nil || !ok || got.Source != "generated" || got.SpecJSON != `{"slug":"shop"}` {
		t.Fatalf("get: %+v ok=%v err=%v", got, ok, err)
	}
	if got.CreatedAt == 0 || got.UpdatedAt == 0 {
		t.Error("timestamps not set")
	}
	apps, err := s.List()
	if err != nil || len(apps) != 1 {
		t.Fatalf("list: %v %d", err, len(apps))
	}
	if err := s.Delete(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("shop"); ok {
		t.Error("app should be gone after delete")
	}
}

func TestProvStoreRejectsBadInput(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, App{Slug: "Bad Slug", Source: "generated"}); err == nil {
		t.Error("bad slug accepted")
	}
	if err := s.Save(ctx, App{Slug: "shop", Source: "weird"}); err == nil {
		t.Error("bad source accepted")
	}
}
