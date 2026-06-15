package scale

import "testing"

func testCtlPolicy() Policy {
	return Policy{
		Min: 1, Max: 5,
		UpCPUPct: 80, DownCPUPct: 40, // 40-pt dead band
		UpMemPct: 80, DownMemPct: 40,
		BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300,
	}
}

func TestPolicyValidation(t *testing.T) {
	if ok, _ := testCtlPolicy().Valid(); !ok {
		t.Fatal("the baseline policy should be valid")
	}
	bad := testCtlPolicy()
	bad.DownCPUPct = 70 // dead band only 10
	if ok, _ := bad.Valid(); ok {
		t.Error("a <20-pt dead band must be rejected")
	}
	bad = testCtlPolicy()
	bad.CooldownDownSecs = 10 // less than up cooldown
	if ok, _ := bad.Valid(); ok {
		t.Error("down cooldown < up cooldown (not down-lazy) must be rejected")
	}
}

var hot = Metrics{CPUMeanPct: 90, MemMaxPct: 50, AllHealthy: true}
var cold = Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true}
var warm = Metrics{CPUMeanPct: 60, MemMaxPct: 50, AllHealthy: true} // in the dead band

func TestScaleUpRequiresSustainedBreach(t *testing.T) {
	p := testCtlPolicy()
	st := State{Replicas: 1}
	// First hot tick starts the breach timer but does NOT act. (now is real unix time,
	// never 0 — 0 is the "not breaching" sentinel.)
	d := Decide(st, hot, p, 5, 1000)
	if d.Action != ActNone || d.Next.BreachSince == 0 {
		t.Fatalf("first breach tick should start the timer, not act; got %s breachSince=%d", d.Action, d.Next.BreachSince)
	}
	// Before breach_for elapses → still no action.
	d = Decide(d.Next, hot, p, 5, 1030)
	if d.Action != ActNone {
		t.Fatalf("breach not yet sustained should hold, got %s", d.Action)
	}
	// After breach_for → scale up one step.
	d = Decide(d.Next, hot, p, 5, 1070)
	if d.Action != ActUp || d.Target != 2 {
		t.Fatalf("sustained breach should scale up to 2, got %s target=%d", d.Action, d.Target)
	}
}

func TestDeadBandHoldsSteady(t *testing.T) {
	// In the dead band (between down and up thresholds): neither up nor down.
	d := Decide(State{Replicas: 2}, warm, testCtlPolicy(), 5, 1000)
	if d.Action != ActNone {
		t.Errorf("a signal in the dead band must hold steady, got %s", d.Action)
	}
}

func TestDownLazyAndStepOne(t *testing.T) {
	p := testCtlPolicy()
	st := State{Replicas: 4, LastChange: 0}
	// Within the down cooldown → hold.
	if d := Decide(st, cold, p, 5, 100); d.Action != ActNone {
		t.Fatalf("within down cooldown should hold, got %s", d.Action)
	}
	// Past the (long) down cooldown → shed exactly one.
	d := Decide(st, cold, p, 5, 400)
	if d.Action != ActDown || d.Target != 3 {
		t.Fatalf("down should step by exactly 1 (4→3), got %s target=%d", d.Action, d.Target)
	}
}

func TestDownRequiresAllHealthy(t *testing.T) {
	p := testCtlPolicy()
	m := cold
	m.AllHealthy = false
	if d := Decide(State{Replicas: 3, LastChange: 0}, m, p, 5, 400); d.Action == ActDown {
		t.Error("must not scale down while a replica is unhealthy")
	}
}

func TestScaleUpRefusedAtCapacity(t *testing.T) {
	p := testCtlPolicy()
	// Sustained breach + cooldown ok, but the capacity ceiling == current (2).
	st := State{Replicas: 2, BreachSince: 1, LastChange: 0}
	d := Decide(st, hot, p, 2 /* ceiling */, 1000)
	if d.Action != ActRefused {
		t.Fatalf("a sustained scale-up blocked by capacity must REFUSE (alert), got %s", d.Action)
	}
	if d.Next.BreachSince == 0 {
		t.Error("a refusal must keep the breach timer so it re-fires next tick")
	}
}

func TestCapacityForcesDownWhenOverCeiling(t *testing.T) {
	p := testCtlPolicy()
	// 4 replicas but the ceiling dropped to 2 (another app grew) → shed toward 2.
	d := Decide(State{Replicas: 4}, warm, p, 2, 1000)
	if d.Action != ActDown || d.Target != 2 {
		t.Errorf("over-ceiling must force a drained scale-down to the ceiling, got %s target=%d", d.Action, d.Target)
	}
}

func TestNeverBelowMinOrAboveMax(t *testing.T) {
	p := testCtlPolicy()
	// At min, cold → no down.
	if d := Decide(State{Replicas: 1, LastChange: 0}, cold, p, 5, 9999); d.Action == ActDown {
		t.Error("must not scale below min")
	}
	// At max, hot+sustained → no up (held at max).
	st := State{Replicas: 5, BreachSince: 1, LastChange: 0}
	if d := Decide(st, hot, p, 5, 9999); d.Action == ActUp {
		t.Error("must not scale above max")
	}
}
