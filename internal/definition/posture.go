package definition

import "fmt"

// posture.go is the closed posture-widening predicate (plan §7.8). Host `defaults`
// are projected as a base layer beneath each app, but a default may only TIGHTEN a
// posture, never silently WIDEN one. Any default that — versus the conservative
// built-in — enables auto_deploy, raises scaling.max/min, or disables self-healing
// requires a per-app, field-named posture-widening ACKNOWLEDGEMENT. The predicate is
// CLOSED: it enumerates every wideking and defaults to "this widens" for anything it
// can't prove is a tightening, so a new widening knob can't slip through unacked.

// Widening is one posture-widening a default would apply to an app (needs an ack).
type Widening struct {
	Field  string
	Detail string
}

// builtin posture (the conservative baseline a default is compared against).
const (
	builtinScalingMax = 1 // effective_max collapses to 1 by default (§8A)
	builtinScalingMin = 1
	builtinAutoDeploy = false // git auto-deploy off by default (§7.6)
	builtinSelfHeal   = true  // the supervisor is on by default (§8.5)
)

// PostureWidenings returns every posture-widening the given host defaults would
// apply (empty = the defaults only tighten / are neutral, applicable without
// acknowledgement). edge.routes and git.ref cannot appear in Defaults at all (not in
// the struct), so they need no check here.
func PostureWidenings(d *Defaults) []Widening {
	if d == nil {
		return nil
	}
	var w []Widening
	if d.AutoDeploy != nil && *d.AutoDeploy != builtinAutoDeploy && *d.AutoDeploy {
		w = append(w, Widening{Field: "defaults.auto_deploy", Detail: "enables git auto-deploy for apps that don't set it"})
	}
	if d.SelfHealing != nil && *d.SelfHealing != builtinSelfHeal && !*d.SelfHealing {
		w = append(w, Widening{Field: "defaults.self_healing", Detail: "disables the self-healing supervisor"})
	}
	if d.Scaling != nil {
		if d.Scaling.Max > builtinScalingMax {
			w = append(w, Widening{Field: "defaults.scaling.max", Detail: fmt.Sprintf("raises the default replica ceiling to %d", d.Scaling.Max)})
		}
		if d.Scaling.Min > builtinScalingMin {
			w = append(w, Widening{Field: "defaults.scaling.min", Detail: fmt.Sprintf("raises the default replica floor to %d", d.Scaling.Min)})
		}
	}
	return w
}

// AckSet is the set of field names the operator has acknowledged as widening.
type AckSet map[string]bool

// UnackedWidenings returns the posture-widenings NOT covered by acks — a non-empty
// result must BLOCK the apply (the host default would silently widen an app's
// posture). This is how "defaults never silently widen" is enforced.
func UnackedWidenings(d *Defaults, acks AckSet) []Widening {
	var out []Widening
	for _, w := range PostureWidenings(d) {
		if !acks[w.Field] {
			out = append(out, w)
		}
	}
	return out
}
