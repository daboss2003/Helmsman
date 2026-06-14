package alert

import (
	"testing"

	"github.com/helmsman/helmsman/internal/hostmon"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
)

func hostSnap(cpu float64) *monitor.Snapshot {
	return &monitor.Snapshot{HostOK: true, Host: hostmon.Sample{CPUPercent: cpu}}
}

// The state machine: pending → firing (after sustain) → resolved → ok, with one
// outbox row at each of the firing/resolved transitions.
func TestStateMachineSustainAndResolve(t *testing.T) {
	rule := Rule{ID: 1, Kind: KindHostCPU, Threshold: 80, ForSeconds: 60, Level: LevelWarning, Enabled: true}

	st, ob := Evaluate(0, []Rule{rule}, hostSnap(95), nil)
	if len(ob) != 0 || st[0].Phase != PhasePending {
		t.Fatalf("t=0 expected pending no page, got %s ob=%d", st[0].Phase, len(ob))
	}
	st, ob = Evaluate(30, []Rule{rule}, hostSnap(95), st)
	if len(ob) != 0 || st[0].Phase != PhasePending {
		t.Fatalf("t=30 expected still pending, got %s ob=%d", st[0].Phase, len(ob))
	}
	st, ob = Evaluate(61, []Rule{rule}, hostSnap(95), st)
	if st[0].Phase != PhaseFiring || len(ob) != 1 || ob[0].Transition != "firing" {
		t.Fatalf("t=61 expected firing+page, got %s ob=%+v", st[0].Phase, ob)
	}
	st, ob = Evaluate(120, []Rule{rule}, hostSnap(10), st)
	if st[0].Phase != PhaseResolved || len(ob) != 1 || ob[0].Transition != "resolved" {
		t.Fatalf("t=120 expected resolved+page, got %s ob=%+v", st[0].Phase, ob)
	}
	st, ob = Evaluate(200, []Rule{rule}, hostSnap(10), st)
	if st[0].Phase != PhaseOK || len(ob) != 0 {
		t.Fatalf("t=200 expected ok, got %s ob=%d", st[0].Phase, len(ob))
	}
}

// Anti-flap: a blip that doesn't sustain never pages.
func TestAntiFlapNoPage(t *testing.T) {
	rule := Rule{ID: 1, Kind: KindHostCPU, Threshold: 80, ForSeconds: 60, Level: LevelWarning, Enabled: true}
	st, _ := Evaluate(0, []Rule{rule}, hostSnap(95), nil)
	st, ob := Evaluate(10, []Rule{rule}, hostSnap(10), st)
	if st[0].Phase != PhaseOK || len(ob) != 0 {
		t.Errorf("flap should return to ok with no page, got %s ob=%d", st[0].Phase, len(ob))
	}
}

func appSnap(project string, running bool, opsRes *ops.Result) *monitor.Snapshot {
	state := "running"
	if !running {
		state = "exited"
	}
	return &monitor.Snapshot{Apps: []monitor.App{{
		Project: project, Ops: opsRes,
		Services: []monitor.ServiceStatus{{Service: "web", State: state}},
	}}}
}

func TestContainerDownLiveness(t *testing.T) {
	rule := Rule{ID: 2, Kind: KindContainerDown, ForSeconds: 0, Level: LevelCritical, DeferWhenSelfManaged: false, Enabled: true}
	st, _ := Evaluate(0, []Rule{rule}, appSnap("shop", false, nil), nil)
	st, ob := Evaluate(1, []Rule{rule}, appSnap("shop", false, nil), st)
	if st[0].Phase != PhaseFiring || len(ob) != 1 {
		t.Fatalf("container down should fire, got %s ob=%d", st[0].Phase, len(ob))
	}
}

func TestDeferWhenSelfManagedReachable(t *testing.T) {
	reachable := &ops.Result{Mode: ops.RICH, AlertingCapable: true}
	resourceRule := Rule{ID: 3, Kind: KindRestartStorm, Threshold: 1, ForSeconds: 0, DeferWhenSelfManaged: true, Enabled: true}
	livenessRule := Rule{ID: 4, Kind: KindContainerDown, ForSeconds: 0, DeferWhenSelfManaged: false, Enabled: true}

	snap := appSnap("shop", false, reachable)
	snap.Apps[0].Services[0].RestartCount = 5

	if st, _ := Evaluate(0, []Rule{resourceRule}, snap, nil); len(st) != 0 {
		t.Errorf("resource rule should be deferred (self-managed+reachable), got %d states", len(st))
	}
	if st, _ := Evaluate(0, []Rule{livenessRule}, snap, nil); len(st) != 1 {
		t.Errorf("liveness rule must always cover, got %d states", len(st))
	}
}

func TestDownOnlySafetyNet(t *testing.T) {
	unreachable := &ops.Result{Mode: ops.BASIC, AlertingCapable: true, Err: "probe failed"}
	resourceRule := Rule{ID: 5, Kind: KindRestartStorm, Threshold: 1, ForSeconds: 0, DeferWhenSelfManaged: true, Enabled: true}
	livenessRule := Rule{ID: 6, Kind: KindContainerDown, ForSeconds: 0, DeferWhenSelfManaged: true, Enabled: true}

	snap := appSnap("shop", false, unreachable)
	snap.Apps[0].Services[0].RestartCount = 5

	if st, _ := Evaluate(0, []Rule{resourceRule}, snap, nil); len(st) != 0 {
		t.Errorf("resource rule should stay deferred for a dark self-managed app, got %d", len(st))
	}
	if st, _ := Evaluate(0, []Rule{livenessRule}, snap, nil); len(st) != 1 {
		t.Errorf("liveness must cover a dark self-managed app (down-only net), got %d", len(st))
	}
}

// A firing threshold alert that later becomes deferred (the app starts
// self-alerting) is CLOSED (resolved to ok), never left stuck firing.
func TestDeferredTargetClosesOpenAlert(t *testing.T) {
	rule := Rule{ID: 9, Kind: KindRestartStorm, Threshold: 1, ForSeconds: 0, DeferWhenSelfManaged: true, Enabled: true}
	notManaged := appSnap("shop", true, nil)
	notManaged.Apps[0].Services[0].RestartCount = 5

	st, _ := Evaluate(0, []Rule{rule}, notManaged, nil)
	st, _ = Evaluate(1, []Rule{rule}, notManaged, st)
	if st[0].Phase != PhaseFiring {
		t.Fatalf("precondition: expected firing, got %s", st[0].Phase)
	}
	managed := appSnap("shop", true, &ops.Result{Mode: ops.RICH, AlertingCapable: true})
	managed.Apps[0].Services[0].RestartCount = 5
	st, _ = Evaluate(2, []Rule{rule}, managed, st)
	for _, s := range st {
		if s.Phase == PhaseFiring {
			t.Errorf("deferred target left stuck firing: %+v", s)
		}
	}
}

func TestNotSelfManagedCovered(t *testing.T) {
	rule := Rule{ID: 7, Kind: KindRestartStorm, Threshold: 1, ForSeconds: 0, DeferWhenSelfManaged: true, Enabled: true}
	snap := appSnap("shop", true, nil)
	snap.Apps[0].Services[0].RestartCount = 5
	if st, _ := Evaluate(0, []Rule{rule}, snap, nil); len(st) != 1 {
		t.Errorf("non-self-managed app must be covered, got %d states", len(st))
	}
}
