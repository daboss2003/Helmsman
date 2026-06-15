package scale

// The auto-scaling controller (plan §8A): one pure decision per tick over the
// poller snapshot. Hysteresis is ALL THREE of: a sustained-breach time window, a
// ≥20-point dead band between the up and down thresholds, and asymmetric cooldowns
// (up-eager, down-lazy). Down steps are always 1 and require all replicas healthy;
// up ramps one step under sustained load. The host-capacity ceiling caps every
// decision and a blocked scale-up becomes a refusal (an alert, never a silent hold).

// Action is what the watcher should do with the decision.
type Action string

const (
	ActNone    Action = "none"
	ActUp      Action = "up"
	ActDown    Action = "down"
	ActRefused Action = "refused" // wanted to scale up but the capacity ceiling blocked it
)

// Metrics is the per-service signal: per-replica CPU MEAN and mem MAX aggregated
// across the running replicas (plan §8A), plus whether every replica is healthy.
type Metrics struct {
	CPUMeanPct float64
	MemMaxPct  float64
	AllHealthy bool
}

// Policy is the operator's scaling policy for one service.
type Policy struct {
	Min, Max         int
	UpCPUPct         float64
	UpMemPct         float64
	DownCPUPct       float64
	DownMemPct       float64
	BreachForSecs    int64
	CooldownUpSecs   int64
	CooldownDownSecs int64
}

// deadBand is the minimum gap required between an up and the matching down
// threshold (plan §8A: "≥ 20-pt dead band").
const deadBand = 20.0

// Valid checks the policy invariants config validation must enforce: a sane replica
// range, the ≥20-pt dead band on BOTH signals, and up-eager/down-lazy cooldowns.
func (p Policy) Valid() (bool, string) {
	switch {
	case p.Min < 1:
		return false, "min replicas must be >= 1"
	case p.Max < p.Min:
		return false, "max replicas must be >= min"
	case p.UpCPUPct-p.DownCPUPct < deadBand:
		return false, "cpu up/down thresholds must differ by >= 20 points (dead band)"
	case p.UpMemPct-p.DownMemPct < deadBand:
		return false, "mem up/down thresholds must differ by >= 20 points (dead band)"
	case p.BreachForSecs <= 0:
		return false, "breach_for must be positive (anti-flap time window)"
	case p.CooldownDownSecs < p.CooldownUpSecs:
		return false, "down cooldown must be >= up cooldown (down-lazy)"
	default:
		return true, ""
	}
}

// State is the persisted controller state for one service. Replicas is the DESIRED
// count the controller is driving toward (the watcher reconciles observed→desired).
type State struct {
	Replicas    int
	BreachSince int64 // unix sec; when the current up-breach started (0 = not breaching)
	LastChange  int64 // unix sec; last scale action (for the cooldowns)
}

// Decision is the pure outcome; the watcher persists Next and, on Up/Down, performs
// the scale (+ edge-pool reconcile). On Refused it raises scale_refused_no_capacity.
type Decision struct {
	Target int
	Action Action
	Reason string
	Next   State
}

// Decide steps the controller for one service. ceiling is the host-capacity guard's
// hard cap for this tick (from MaxReplicas).
func Decide(st State, m Metrics, p Policy, ceiling int, now int64) Decision {
	cur := st.Replicas
	hardMax := p.Max
	if ceiling < hardMax {
		hardMax = ceiling
	}

	// Capacity force-down: if we are above the hard ceiling (e.g. another app grew
	// and shrank our budget), shed toward it — reducing pressure is always safe. The
	// watcher drains each removed replica from the edge pool first.
	if cur > hardMax && hardMax >= p.Min {
		ns := st
		ns.Replicas = hardMax
		ns.LastChange = now
		ns.BreachSince = 0
		return Decision{Target: hardMax, Action: ActDown, Reason: "over the host-capacity ceiling", Next: ns}
	}

	wantUp := m.CPUMeanPct >= p.UpCPUPct || m.MemMaxPct >= p.UpMemPct
	wantDown := m.CPUMeanPct < p.DownCPUPct && m.MemMaxPct < p.DownMemPct && m.AllHealthy

	if wantUp {
		ns := st
		if ns.BreachSince == 0 {
			ns.BreachSince = now // start the sustained-breach timer
		}
		if now-ns.BreachSince < p.BreachForSecs {
			return hold(ns, "up-breach not yet sustained")
		}
		if now-st.LastChange < p.CooldownUpSecs {
			return hold(ns, "up cooldown")
		}
		if cur >= p.Max {
			return hold(ns, "at policy max")
		}
		if cur >= ceiling {
			// Sustained desire to grow, but the capacity guard blocks it: refuse and
			// alert (never a silent hold). Keep the breach timer so it re-fires.
			return Decision{Target: cur, Action: ActRefused, Reason: "scale-up refused: no host capacity", Next: ns}
		}
		ns.Replicas = cur + 1 // up-eager, one step per tick
		ns.LastChange = now
		ns.BreachSince = 0
		return Decision{Target: ns.Replicas, Action: ActUp, Reason: "sustained load", Next: ns}
	}

	// Not breaching up → reset the breach timer.
	ns := st
	ns.BreachSince = 0
	if wantDown {
		if now-st.LastChange < p.CooldownDownSecs {
			return hold(ns, "down cooldown")
		}
		if cur <= p.Min {
			return hold(ns, "at policy min")
		}
		ns.Replicas = cur - 1 // down step always 1
		ns.LastChange = now
		return Decision{Target: ns.Replicas, Action: ActDown, Reason: "load shed", Next: ns}
	}
	return hold(ns, "steady")
}

func hold(ns State, reason string) Decision {
	return Decision{Target: ns.Replicas, Action: ActNone, Reason: reason, Next: ns}
}
