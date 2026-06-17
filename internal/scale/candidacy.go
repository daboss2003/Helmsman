// Package scale is the opt-in, host-aware process auto-scaler (plan §8A). It scales
// container REPLICAS of one edge-fronted HTTP service — never VMs, never the whole
// project — and is conservative-by-construction: it REFUSES rather than queues,
// treats a refusal as an alertable signal, and on a small box collapses to a safe
// no-op (effective_max = 1).
//
// This file is the candidacy gate. The decision core (controller hysteresis) and the
// load-bearing host-capacity guard are in controller.go / capacity.go. All three are
// pure so the safety properties are exhaustively testable; the watcher (watcher.go)
// supplies the inputs, applies the §0 gate + semaphore, and performs the scale.
package scale

// ServiceSpec is the deploy-time view of one service, derived from its compose
// definition + the managed edge routes. Candidacy is re-evaluated on every deploy /
// config change; a service that GAINS a host port or RW volume loses candidacy and
// is scaled back to 1.
type ServiceSpec struct {
	Name                string
	EdgeUpstream        bool // C1: an edge HTTP upstream with a known internal port
	L4Upstream          bool // C1 (alt): a managed L4 (TCP/UDP) upstream — fronted by an edge l4_route, replicas internal-only
	FixedHostPort       bool // C2 (disqualifies): publishes a fixed host port the LB does NOT own
	RWVolume            bool // C3 (disqualifies): has an exclusive read-write volume
	Stateful            bool // C4 (disqualifies): a DB/broker/coordination store
	IdentityPlaceholder bool // C5 (disqualifies): a deploy-time identity (node cookie/name/seed/host-bound port)
	StatelessContract   bool // C6: honors the stateless restart contract (operator attests)
	OptedIn             bool // C7: the operator explicitly enabled scaling for this service
}

// Candidacy reports whether a service may be auto-scaled, with the first failing
// reason. Default is NOT scalable: every condition must hold. A stateful service is
// rejected with a clear reason — it is a config-file/cert-binding app (§7.4), not a
// scaling candidate.
func Candidacy(s ServiceSpec) (ok bool, reason string) {
	switch {
	case !s.OptedIn:
		return false, "scaling not enabled for this service (opt-in required)"
	case !s.EdgeUpstream && !s.L4Upstream:
		return false, "not an edge HTTP upstream or a managed L4 upstream with a known internal port (C1)"
	case s.FixedHostPort:
		return false, "publishes a fixed host port the LB doesn't own — replicas would collide (C2)"
	case s.RWVolume:
		return false, "has an exclusive read-write volume — not safely replicable (C3)"
	case s.Stateful:
		return false, "stateful service (database/broker/coordination store) — not a scaling candidate (C4)"
	case s.IdentityPlaceholder:
		return false, "carries a deploy-time identity (node name/cookie/seed/host-bound port) (C5)"
	case !s.StatelessContract:
		return false, "does not honor the stateless restart contract (C6)"
	default:
		return true, ""
	}
}
