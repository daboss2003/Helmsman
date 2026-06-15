// Package clockskew detects system wall-clock steps by comparing the wall clock
// against a monotonic source (plan §5.9 / §6.3). Time-based security decisions —
// session/API-token expiry, TOTP windows, cert/ACME renewal — all trust the wall
// clock; a backward step could revive an expired credential or a forward jump could
// prematurely expire a live cert. This detector is pure and deterministic (it takes
// explicit readings, never calls the clock itself), so the consuming caller can feed
// it time.Now() in production and fixed readings in tests.
//
// The detector compares the DELTA of the wall clock to the DELTA of the monotonic
// clock between consecutive observations. In a healthy system the two advance
// together; a divergence beyond tolerance means the wall clock was stepped (NTP
// correction, manual set, VM pause/resume, or a hostile reset). It also flags a
// monotonic clock that appears to move backward (a broken time source), which is
// itself a fail-closed signal.
package clockskew

import "time"

// Detector is a stateful, NON-concurrent skew detector (guard with the caller's lock
// if observed from multiple goroutines). Construct with New.
type Detector struct {
	tol      int64 // tolerance in nanoseconds
	lastWall int64
	lastMono int64
	have     bool
	breached bool
	maxSkew  int64     // largest absolute per-interval divergence ever seen (ns)
	base     time.Time // monotonic anchor for ObserveNow (lazily set on first call)
}

// New builds a Detector. tolerance is the per-interval wall-vs-monotonic divergence
// that is treated as a real step (smaller drifts are normal scheduling jitter / NTP
// slew). A non-positive tolerance is clamped to 1s.
func New(tolerance time.Duration) *Detector {
	if tolerance <= 0 {
		tolerance = time.Second
	}
	return &Detector{tol: int64(tolerance)}
}

// Observe records one (wall, mono) reading and reports the per-interval skew (the
// wall delta minus the monotonic delta) and whether it breaches tolerance. wall is
// the system wall clock; mono is a strictly-monotonic source. Both are durations
// since a fixed but arbitrary epoch (in production, pass time.Now() decomposed — see
// Reading). The FIRST observation only anchors state and never reports a breach.
func (d *Detector) Observe(wall, mono time.Duration) (skew time.Duration, breach bool) {
	w, m := int64(wall), int64(mono)
	if !d.have {
		d.have, d.lastWall, d.lastMono = true, w, m
		return 0, false
	}
	dw := w - d.lastWall
	dm := m - d.lastMono
	d.lastWall, d.lastMono = w, m

	// A monotonic source must never go backward; if it does, treat the whole reading
	// as a hard skew of that magnitude (fail-closed — never silently trust it).
	if dm < 0 {
		d.breached = true
		if a := abs(dm); a > d.maxSkew {
			d.maxSkew = a
		}
		return time.Duration(dm), true
	}

	div := dw - dm
	a := abs(div)
	if a > d.tol {
		d.breached = true
		if a > d.maxSkew {
			d.maxSkew = a
		}
		return time.Duration(div), true
	}
	return time.Duration(div), false
}

// Breached reports whether ANY observation has breached tolerance since
// construction (a sticky flag — once time has been seen to step, the caller should
// treat subsequent time-based decisions conservatively until an operator confirms).
func (d *Detector) Breached() bool { return d.breached }

// MaxSkew returns the largest absolute per-interval divergence observed so far.
func (d *Detector) MaxSkew() time.Duration { return time.Duration(d.maxSkew) }

// Reset clears the sticky breach state and re-anchors on the next Observe (call after
// an operator has acknowledged a known, legitimate time change).
func (d *Detector) Reset() {
	d.have, d.breached, d.maxSkew = false, false, 0
	d.lastWall, d.lastMono = 0, 0
	d.base = time.Time{}
}

// ObserveNow is the production convenience: it reads time.Now() and decomposes it
// into the (wall, mono) pair Observe expects. The wall component is absolute unix
// time; the monotonic component is the elapsed reading from a base captured on the
// first call (Go's time.Now() carries a monotonic reading, so now.Sub(base) advances
// monotonically regardless of wall-clock steps). Observe only looks at deltas, so the
// differing bases cancel. This method calls the clock; the core Observe stays pure.
func (d *Detector) ObserveNow() (skew time.Duration, breach bool) {
	now := time.Now()
	if d.base.IsZero() {
		d.base = now
	}
	wall := time.Duration(now.UnixNano())
	mono := now.Sub(d.base)
	return d.Observe(wall, mono)
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
