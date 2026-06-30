package scale

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

type fakeScaler struct {
	mu    sync.Mutex
	calls []int // target replica counts requested
}

func (f *fakeScaler) Scale(_ context.Context, _, _ string, replicas int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, replicas)
	return nil
}
func (f *fakeScaler) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *fakeScaler) last() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return -1
	}
	return f.calls[len(f.calls)-1]
}

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

const GiBw = 1 << 30

// snapWeb builds a snapshot of one app "shop" with `replicas` running "web"
// containers at the given per-replica CPU% and mem (bytes used / limit).
func snapWeb(replicas int, cpu float64, memUsed, memLimit uint64, hostTotal, hostUsed uint64) *monitor.Snapshot {
	var svcs []monitor.ServiceStatus
	for i := 0; i < replicas; i++ {
		svcs = append(svcs, monitor.ServiceStatus{Service: "web", State: "running", Health: "healthy", CPUPercent: cpu, MemBytes: memUsed, MemLimit: memLimit})
	}
	return &monitor.Snapshot{
		DockerOK: true, HostOK: true,
		Host: hostmon.Sample{MemTotal: hostTotal, MemUsed: hostUsed},
		Apps: []monitor.App{{Project: "shop", Services: svcs}},
	}
}

func enablePolicy(t *testing.T, st *Store, perReplicaMem uint64) {
	t.Helper()
	pr := PolicyRow{
		Policy:        Policy{Min: 1, Max: 5, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300},
		Enabled:       true,
		PerReplicaMem: perReplicaMem,
		PerReplicaCPU: 100,
	}
	if err := st.SavePolicy(context.Background(), Key{App: "shop", Service: "web"}, pr); err != nil {
		t.Fatal(err)
	}
}

func newWatcher(t *testing.T, st *Store, snapPtr **monitor.Snapshot, clock *int64, sc Scaler, alerts *alertstore.Store) *Watcher {
	return New(Config{
		Store: st, Alerts: alerts,
		Snap:   func() *monitor.Snapshot { return *snapPtr },
		Sem:    dockerexec.NewSemaphore(),
		Scaler: sc, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		WritePlaneOK: true, HostCPUMilli: 8000,
		Reserves: Reserves{MemReserveBytes: 512 << 20, MemFreeFloor: 256 << 20, PerReplicaMemFloor: 64 << 20, NearOOMFreeBytes: 128 << 20},
		Now:      func() int64 { return *clock },
	})
}

func TestWatcherScalesUpUnderLoad(t *testing.T) {
	st := testStore(t)
	enablePolicy(t, st, 256<<20) // 256 MiB/replica; plenty of room on an 8 GiB host
	var snap *monitor.Snapshot
	var clock int64
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	snap = snapWeb(1, 95, 100<<20, 512<<20, 8*GiBw, 1*GiBw) // hot CPU
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	// Up-eager: ramps one step each time the breach re-sustains past the cooldown.
	// First step must be to 2, and it must never exceed the policy max (5).
	if sc.count() == 0 || sc.calls[0] != 2 || sc.last() > 5 {
		t.Errorf("sustained load should ramp up from 2 (capped at 5), got calls=%v", sc.calls)
	}
}

func TestWatcherRefusesAtCapacity(t *testing.T) {
	st := testStore(t)
	// Huge per-replica reservation: an 8 GiB host can fund only ~1 → ceiling==current.
	enablePolicy(t, st, 6*GiBw)
	db := &alertstore.Store{}
	_ = db
	alerts := newAlertStore(t)
	var snap *monitor.Snapshot
	var clock int64
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, alerts)
	snap = snapWeb(1, 95, 100<<20, 512<<20, 8*GiBw, 1*GiBw)
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if sc.count() != 0 {
		t.Errorf("a capacity-blocked scale-up must not scale, got %v", sc.calls)
	}
	if n := pendingInfra(t, alerts); n == 0 {
		t.Error("a capacity-blocked scale-up must raise scale_refused_no_capacity")
	}
}

func TestWatcherSemaphoreBusySkips(t *testing.T) {
	st := testStore(t)
	enablePolicy(t, st, 256<<20)
	var snap *monitor.Snapshot
	var clock int64
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	if !w.cfg.Sem.TryAcquire() { // hold the one-docker-child semaphore elsewhere
		t.Fatal("pre-acquire")
	}
	defer w.cfg.Sem.Release()
	snap = snapWeb(1, 95, 100<<20, 512<<20, 8*GiBw, 1*GiBw)
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if sc.count() != 0 {
		t.Errorf("a busy semaphore must skip scaling (never queue), got %v", sc.calls)
	}
}

func TestWatcherWritePlaneOffSkips(t *testing.T) {
	st := testStore(t)
	enablePolicy(t, st, 256<<20)
	var snap *monitor.Snapshot
	var clock int64
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	w.cfg.WritePlaneOK = false
	snap = snapWeb(1, 95, 100<<20, 512<<20, 8*GiBw, 1*GiBw)
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if sc.count() != 0 {
		t.Errorf("a closed write plane must skip scaling, got %v", sc.calls)
	}
}

// Two services that both want to scale in the SAME tick must not JOINTLY over-commit
// the host (the live cross-app budget fix): on a host that can only fund one more
// replica, exactly one scales and the other is refused — never both.
func TestWatcherSameTickNoJointOvercommit(t *testing.T) {
	st := testStore(t)
	for _, app := range []string{"a", "b"} {
		pr := PolicyRow{
			Policy:  Policy{Min: 1, Max: 5, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300},
			Enabled: true, PerReplicaMem: 1 * GiBw, PerReplicaCPU: 100,
		}
		if err := st.SavePolicy(context.Background(), Key{App: app, Service: "web"}, pr); err != nil {
			t.Fatal(err)
		}
	}
	// 4 GiB host, mostly free (so the DECLARED reservation budget binds, not measured):
	// reserve 512 MiB + 1 GiB/replica ⇒ at most ~3 replicas total across both apps.
	twoApps := func() *monitor.Snapshot {
		mk := func() monitor.App {
			return monitor.App{Project: "", Services: []monitor.ServiceStatus{{Service: "web", State: "running", Health: "healthy", CPUPercent: 95, MemBytes: 100 << 20, MemLimit: 512 << 20}}}
		}
		a, b := mk(), mk()
		a.Project, b.Project = "a", "b"
		return &monitor.Snapshot{DockerOK: true, HostOK: true, Host: hostmon.Sample{MemTotal: 4 * GiBw, MemUsed: 256 << 20}, Apps: []monitor.App{a, b}}
	}
	var snap *monitor.Snapshot = twoApps()
	var clock int64
	sc := &fakeScaler{}
	w := New(Config{
		Store: st, Snap: func() *monitor.Snapshot { return snap }, Sem: dockerexec.NewSemaphore(),
		Scaler: sc, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), WritePlaneOK: true, HostCPUMilli: 16000,
		Reserves: Reserves{MemReserveBytes: 512 << 20, MemFreeFloor: 256 << 20, PerReplicaMemFloor: 16 << 20},
		Now:      func() int64 { return clock },
	})
	for i := 0; i < 6; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	total := w.states[Key{"a", "web"}].Replicas + w.states[Key{"b", "web"}].Replicas
	if total > 3 {
		t.Errorf("two same-tick scale-ups jointly over-committed the host: total desired=%d (max 3)", total)
	}
	if total < 2 {
		t.Errorf("at least one service should have scaled up, total=%d", total)
	}
}

// A service that gains a shared RW volume (C3) at runtime loses candidacy and is
// scaled back to the floor — the runtime re-check via IsCandidate.
func TestWatcherLostCandidacyScalesBackToMin(t *testing.T) {
	st := testStore(t)
	enablePolicy(t, st, 256<<20)
	// Pre-seed a desired of 3 (as if previously scaled up).
	_ = st.SaveState(context.Background(), Key{App: "shop", Service: "web"}, State{Replicas: 3}, 100)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := New(Config{
		Store: st, Snap: func() *monitor.Snapshot { return snap }, Sem: dockerexec.NewSemaphore(),
		Scaler: sc, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), WritePlaneOK: true, HostCPUMilli: 8000,
		Reserves: Reserves{MemReserveBytes: 256 << 20, MemFreeFloor: 128 << 20, PerReplicaMemFloor: 16 << 20},
		IsCandidate: func(_, _ string) (ServiceSpec, bool) {
			return ServiceSpec{EdgeUpstream: true, StatelessContract: true, RWVolume: true}, true
		},
		Now: func() int64 { return clock },
	})
	w.states = map[Key]State{{App: "shop", Service: "web"}: {Replicas: 3}}
	snap = snapWeb(3, 10, 100<<20, 512<<20, 8*GiBw, 1*GiBw) // cold; but candidacy lost
	w.Tick(context.Background())
	if sc.last() != 1 {
		t.Errorf("a service that lost candidacy (gained a RW volume) must be scaled back to min(1), got calls=%v", sc.calls)
	}
}

// --- helpers for the alert store ---

func newAlertStore(t *testing.T) *alertstore.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	c, err := secret.NewCipher(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return alertstore.New(db, c)
}

func pendingInfra(t *testing.T, a *alertstore.Store) int {
	t.Helper()
	rows, err := a.PendingOutbox(100)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}
