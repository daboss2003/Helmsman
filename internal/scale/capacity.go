package scale

// The host-capacity guard (plan §8A) — the load-bearing safety math, recomputed
// every tick on fresh data. It bounds the replica ceiling so the scaler can NEVER
// over-commit the host into an OOM: the hard ceiling is min(memory budget, cpu
// budget, policy max), and each resource budget is the MIN of the declared-
// reservation math AND the measured-free room, after reserving headroom for the
// control plane, the edge slice, a safety floor, and ALL OTHER apps' desired (not
// merely observed) replicas. On a near-OOM box it collapses to effective_max = 1.

// Budget is one resource's accounting (memory in bytes, or CPU in milli-units).
type Budget struct {
	HostTotal  uint64 // total host resource
	HostFree   uint64 // measured-free right now
	Reserved   uint64 // everything NOT this service: control plane + edge + safety floor + OTHER apps' desired replicas
	FreeFloor  uint64 // keep at least this much free (applied to the measured budget)
	PerReplica uint64 // this service's per-replica reservation (required, non-zero)
	Current    int    // this service's current replica count
}

// ceiling returns the max TOTAL replicas this service may have under this resource.
// It is the min of two conservative budgets:
//   - declared:  (HostTotal − Reserved) / PerReplica          — reservation-based cap
//   - measured:  Current + (HostFree − FreeFloor) / PerReplica — actual-usage cap
//
// The declared budget stops reservation over-commit (incl. other apps' desired
// replicas); the measured budget catches replicas using MORE than they reserved.
func (b Budget) ceiling() int {
	if b.PerReplica == 0 {
		return b.Current // can't reason about per-replica cost → never grow
	}
	declared := int64(0)
	if int64(b.HostTotal) > int64(b.Reserved) {
		declared = (int64(b.HostTotal) - int64(b.Reserved)) / int64(b.PerReplica)
	}
	measuredAddl := int64(0)
	if int64(b.HostFree) > int64(b.FreeFloor) {
		measuredAddl = (int64(b.HostFree) - int64(b.FreeFloor)) / int64(b.PerReplica)
	}
	measured := int64(b.Current) + measuredAddl
	c := declared
	if measured < c {
		c = measured
	}
	if c < 0 {
		c = 0
	}
	return int(c)
}

// CapacityInput is everything MaxReplicas needs for one service this tick.
type CapacityInput struct {
	Mem Budget
	CPU Budget

	PolicyMax          int    // operator's configured max_replicas
	PerReplicaMemFloor uint64 // an implausibly small per-replica mem reservation is rejected
	NearOOMFreeBytes   uint64 // host mem free below this → effective_max collapses to 1
}

// MaxReplicas returns the hard replica ceiling this service may run RIGHT NOW. It is
// never below 1 (a service always keeps its base replica) and is capped by the
// policy max and BOTH resource budgets. nearOOM=true means the box is critically low
// on memory and scaling is a no-op (effective_max = 1) — a wanted scale-up above
// this is a refusal the caller must surface as scale_refused_no_capacity.
func MaxReplicas(in CapacityInput) (ceiling int, nearOOM bool, reason string) {
	// A per-replica reservation must be plausible — an implausibly small one would
	// let the budget "fund" replicas that then OOM (clamp by refusing to grow).
	if in.Mem.PerReplica == 0 || in.Mem.PerReplica < in.PerReplicaMemFloor {
		return clampMin(in.Mem.Current, 1), false, "per-replica memory reservation is implausibly small; refusing to grow"
	}
	// Near-OOM: collapse to effective_max = 1 (a permanent no-op; shed toward 1).
	if in.NearOOMFreeBytes > 0 && in.Mem.HostFree < in.NearOOMFreeBytes {
		return 1, true, "host is near OOM — effective_max collapsed to 1"
	}
	ceiling = in.PolicyMax
	if c := in.Mem.ceiling(); c < ceiling {
		ceiling = c
	}
	if c := in.CPU.ceiling(); c < ceiling {
		ceiling = c
	}
	if ceiling < 1 {
		ceiling = 1
	}
	return ceiling, false, ""
}

func clampMin(v, lo int) int {
	if v < lo {
		return lo
	}
	return v
}
