package selfheal

import "testing"

func baseGate() GateInput {
	return GateInput{
		Rung:                 RungRestart,
		WritePlaneOK:         true,
		RedeployEnabled:      false,
		AcquireSemaphore:     func() bool { return true },
		HeadroomBytes:        2 << 30, // 2 GiB free
		FloorBytes:           256 << 20,
		IsEdgeOrControlPlane: false,
	}
}

func TestGatesAllPassAcquiresSemaphore(t *testing.T) {
	acquired := false
	in := baseGate()
	in.AcquireSemaphore = func() bool { acquired = true; return true }
	out, _ := Gates(in)
	if out != GateProceed {
		t.Fatalf("all gates should pass, got %s", out)
	}
	if !acquired {
		t.Error("GateProceed must have acquired the docker-child semaphore")
	}
}

func TestGateEdgeIsNeverATarget(t *testing.T) {
	in := baseGate()
	in.IsEdgeOrControlPlane = true
	// Edge precedence: even with everything else broken, the answer is SKIP, and the
	// semaphore must NOT be touched.
	in.AcquireSemaphore = func() bool { t.Fatal("must not acquire semaphore for an edge target"); return false }
	in.WritePlaneOK = false
	if out, _ := Gates(in); out != GateSkip {
		t.Errorf("edge/control-plane must be skipped, got %s", out)
	}
}

func TestGateWritePlaneDisabledDefers(t *testing.T) {
	in := baseGate()
	in.WritePlaneOK = false
	if out, _ := Gates(in); out != GateDefer {
		t.Errorf("a disabled write plane must defer, got %s", out)
	}
}

func TestGateRedeployRequiresEnabled(t *testing.T) {
	in := baseGate()
	in.Rung = RungRedeploy
	in.RedeployEnabled = false
	if out, _ := Gates(in); out != GateDefer {
		t.Errorf("redeploy without the opt-in must defer, got %s", out)
	}
}

// THE headline safety property: below the memory-headroom floor, a restart is NEVER
// executed — it pages instead, and the semaphore is never even acquired.
func TestGateLowHeadroomPagesNeverRestarts(t *testing.T) {
	in := baseGate()
	in.HeadroomBytes = 100 << 20 // below the 256 MiB floor
	in.AcquireSemaphore = func() bool { t.Fatal("must not acquire semaphore when headroom is too low"); return false }
	out, _ := Gates(in)
	if out != GatePage {
		t.Fatalf("below the headroom floor the gate must PAGE, not restart, got %s", out)
	}
}

func TestGateSemaphoreBusyDefers(t *testing.T) {
	in := baseGate()
	in.AcquireSemaphore = func() bool { return false } // busy
	if out, _ := Gates(in); out != GateDefer {
		t.Errorf("a busy docker-child semaphore must defer (never queue), got %s", out)
	}
	in.AcquireSemaphore = nil
	if out, _ := Gates(in); out != GateDefer {
		t.Errorf("a nil acquirer must be treated as busy (defer), got %s", out)
	}
}

// The headroom check must run BEFORE the semaphore acquire, so we never hold the
// one-docker-child semaphore while merely deciding to page.
func TestGateHeadroomCheckedBeforeSemaphore(t *testing.T) {
	in := baseGate()
	in.HeadroomBytes = 1 << 20 // below floor
	in.AcquireSemaphore = func() bool { t.Fatal("semaphore acquired before the headroom decision"); return true }
	if out, _ := Gates(in); out != GatePage {
		t.Errorf("expected GatePage, got %s", out)
	}
}
