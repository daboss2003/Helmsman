package clockskew

import (
	"testing"
	"time"
)

func TestSteadyClockNoBreach(t *testing.T) {
	d := New(time.Second)
	// Wall and monotonic advance together in 1s steps (with sub-tolerance jitter).
	wall, mono := 1_000*time.Second, 0*time.Second
	for i := 0; i < 10; i++ {
		wall += time.Second + time.Duration(i)*time.Millisecond // tiny jitter
		mono += time.Second
		if _, breach := d.Observe(wall, mono); breach {
			t.Fatalf("steady clock breached at i=%d", i)
		}
	}
	if d.Breached() {
		t.Error("steady clock must not set the sticky breach flag")
	}
}

func TestForwardJumpDetected(t *testing.T) {
	d := New(time.Second)
	d.Observe(1000*time.Second, 0)
	// Wall jumps +1h but monotonic only advances 1s → ~1h divergence.
	skew, breach := d.Observe(1000*time.Second+time.Hour, time.Second)
	if !breach {
		t.Fatal("a forward wall-clock jump must breach")
	}
	if skew < 59*time.Minute {
		t.Errorf("skew magnitude too small: %v", skew)
	}
	if !d.Breached() || d.MaxSkew() < 59*time.Minute {
		t.Errorf("sticky breach/maxSkew not recorded: breached=%v max=%v", d.Breached(), d.MaxSkew())
	}
}

func TestBackwardJumpDetected(t *testing.T) {
	d := New(time.Second)
	d.Observe(1000*time.Second, 0)
	// Wall steps BACKWARD 10m while monotonic advances 1s — the dangerous case
	// (could revive an expired credential).
	skew, breach := d.Observe(1000*time.Second-10*time.Minute, time.Second)
	if !breach {
		t.Fatal("a backward wall-clock step must breach")
	}
	if skew > 0 {
		t.Errorf("a backward step should yield negative skew, got %v", skew)
	}
}

func TestMonotonicGoingBackwardIsHardBreach(t *testing.T) {
	d := New(time.Hour) // even with a huge tolerance...
	d.Observe(1000*time.Second, 100*time.Second)
	// ...a monotonic source that moves backward is always a breach (broken source).
	_, breach := d.Observe(1001*time.Second, 90*time.Second)
	if !breach {
		t.Fatal("a backward monotonic reading must always breach (fail-closed)")
	}
}

func TestFirstObservationNeverBreaches(t *testing.T) {
	d := New(time.Second)
	if _, breach := d.Observe(999999*time.Second, 5*time.Second); breach {
		t.Error("the first (anchoring) observation must never breach")
	}
}

func TestResetReanchors(t *testing.T) {
	d := New(time.Second)
	d.Observe(1000*time.Second, 0)
	d.Observe(1000*time.Second+time.Hour, time.Second) // breach
	if !d.Breached() {
		t.Fatal("expected breach before reset")
	}
	d.Reset()
	if d.Breached() || d.MaxSkew() != 0 {
		t.Error("reset must clear the sticky breach + maxSkew")
	}
	// After reset, the next observation re-anchors and does not breach.
	if _, breach := d.Observe(2000*time.Second, 10*time.Second); breach {
		t.Error("post-reset anchoring observation must not breach")
	}
}

func TestNonPositiveToleranceClamped(t *testing.T) {
	d := New(0)
	d.Observe(1000*time.Second, 0)
	// A 500ms divergence is under the clamped 1s tolerance → no breach.
	if _, breach := d.Observe(1001*time.Second+500*time.Millisecond, time.Second); breach {
		t.Error("sub-1s divergence must not breach under the clamped default tolerance")
	}
}

func TestObserveNowSteady(t *testing.T) {
	d := New(time.Second)
	// Two real readings a moment apart must not breach (wall≈mono on a healthy host).
	if _, breach := d.ObserveNow(); breach {
		t.Fatal("first ObserveNow must not breach")
	}
	if _, breach := d.ObserveNow(); breach {
		t.Error("steady real-clock readings must not breach")
	}
}
