package definition

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/Helmsman/internal/store"
)

func testStore(t *testing.T) (*Store, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db, []byte("0123456789abcdef0123456789abcdef")), db
}

func TestStoreRoundTripAndCurrent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	d := base()
	if got, err := s.Current("shop"); err != nil || got != nil {
		t.Fatalf("no version yet should be (nil,nil), got %v %v", got, err)
	}
	id1, err := s.SaveCanonical(ctx, d, "first")
	if err != nil {
		t.Fatal(err)
	}
	// A second version becomes the live canonical.
	d2 := base()
	d2.Spec.Scaling = []Scaling{{Service: "web", Max: 4}}
	if _, err := s.SaveCanonical(ctx, d2, "second"); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Current("shop")
	if err != nil || len(cur.Spec.Scaling) == 0 || cur.Spec.Scaling[0].Max != 4 {
		t.Fatalf("Current must return the latest version, got %+v err=%v", cur, err)
	}
	// Rollback re-derives an earlier version (re-parsed + re-validated).
	v1, err := s.Version("shop", id1)
	if err != nil || len(v1.Spec.Scaling) != 0 {
		t.Fatalf("Version(id1) should re-derive the first def, got %+v err=%v", v1, err)
	}
	if vs, _ := s.List("shop"); len(vs) != 2 {
		t.Errorf("expected 2 versions, got %d", len(vs))
	}
}

func TestStoreHMACTamperRejected(t *testing.T) {
	s, db := testStore(t)
	ctx := context.Background()
	if _, err := s.SaveCanonical(ctx, base(), ""); err != nil {
		t.Fatal(err)
	}
	// Tamper the stored YAML — the HMAC must catch it (a DB tamper can't be loaded).
	if _, err := db.Exec(`UPDATE definition_versions SET yaml=replace(yaml,'shop','evil')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current("shop"); err != ErrTampered {
		t.Errorf("a tampered definition must surface ErrTampered, got %v", err)
	}
}
