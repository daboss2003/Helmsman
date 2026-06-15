package selfheal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/Helmsman/internal/store"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

func TestFSMRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	k := Key{App: "shop", Service: "web"}
	f := FSM{Phase: CircuitOpen, Attempts: 3, LastRung: RungRecreate, BackoffUntil: 999, OOMStrikes: 2, Open: true, WindowStart: 5}
	if err := s.Save(ctx, k, f, 10); err != nil {
		t.Fatal(err)
	}
	all, err := s.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := all[k]
	if !ok {
		t.Fatal("FSM not persisted")
	}
	if got.Phase != CircuitOpen || got.LastRung != RungRecreate || !got.Open || got.OOMStrikes != 2 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// ClearCircuit resets to a clean HEALTHY.
	if err := s.ClearCircuit(ctx, k, 20); err != nil {
		t.Fatal(err)
	}
	all, _ = s.LoadAll()
	if all[k].Phase != Healthy || all[k].Open || all[k].Attempts != 0 {
		t.Errorf("ClearCircuit should reset to clean HEALTHY, got %+v", all[k])
	}
}

func TestExpectedDownLease(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.AcquireExpectedDown(ctx, "shop", 1000); err != nil {
		t.Fatal(err)
	}
	// Active before expiry, inactive after.
	active, _ := s.ActiveExpectedDown(500)
	if !active["shop"] {
		t.Error("lease should be active before its deadline")
	}
	expired, _ := s.ActiveExpectedDown(1000)
	if expired["shop"] {
		t.Error("lease must auto-expire at its deadline (until is exclusive)")
	}
	// Release clears it.
	if err := s.ReleaseExpectedDown(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	active, _ = s.ActiveExpectedDown(500)
	if active["shop"] {
		t.Error("released lease should be gone")
	}
}

func TestClearAllExpectedDownFailClosed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_ = s.AcquireExpectedDown(ctx, "shop", 1<<40) // far-future lease (a crashed deploy)
	_ = s.AcquireExpectedDown(ctx, "blog", 1<<40)
	// Boot-time fail-closed clear: no stale lease may survive a restart.
	if err := s.ClearAllExpectedDown(ctx); err != nil {
		t.Fatal(err)
	}
	active, _ := s.ActiveExpectedDown(0)
	if len(active) != 0 {
		t.Errorf("ClearAllExpectedDown must wipe every lease, got %v", active)
	}
}
