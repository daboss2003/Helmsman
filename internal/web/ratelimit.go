package web

import (
	"sync"
	"time"
)

// rateLimiter is a small in-memory fixed-window limiter keyed by client IP. It
// is the general request limiter (pipeline step 4); login brute-force is handled
// separately by the DB-backed lockout (plan §5.2). Deliberately dependency-free
// and self-cleaning so it adds no background goroutine on a tiny box.
// maxWindows hard-caps the live key set so peak memory is bounded regardless of
// intra-interval key cardinality (review #24) — important in trusted-proxy mode
// where the rate-limit key derives from an attacker-rotatable (but allowlisted)
// XFF client value. ~50k entries ≈ a few MB worst case.
const maxWindows = 50_000

type rateLimiter struct {
	mu        sync.Mutex
	windows   map[string]*window
	limit     int
	interval  time.Duration
	lastSweep time.Time
}

type window struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, interval time.Duration) *rateLimiter {
	return &rateLimiter{
		windows:   make(map[string]*window),
		limit:     limit,
		interval:  interval,
		lastSweep: time.Now(),
	}
}

// allow reports whether a request from key may proceed.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.sweep(now)

	w := rl.windows[key]
	if w == nil || now.After(w.reset) {
		if w == nil && len(rl.windows) >= maxWindows {
			// Force an immediate prune of expired entries before giving up.
			rl.sweepNow(now)
			if len(rl.windows) >= maxWindows {
				// Still full of live windows: deny NEW keys under a flood rather
				// than grow unbounded. Previously-seen keys keep their windows.
				return false
			}
		}
		rl.windows[key] = &window{count: 1, reset: now.Add(rl.interval)}
		return true
	}
	if w.count >= rl.limit {
		return false
	}
	w.count++
	return true
}

// sweep drops expired windows lazily, at most once per interval (no background
// goroutine). Caller holds mu.
func (rl *rateLimiter) sweep(now time.Time) {
	if now.Sub(rl.lastSweep) < rl.interval {
		return
	}
	rl.sweepNow(now)
}

// sweepNow unconditionally prunes expired windows. Caller holds mu.
func (rl *rateLimiter) sweepNow(now time.Time) {
	for k, w := range rl.windows {
		if now.After(w.reset) {
			delete(rl.windows, k)
		}
	}
	rl.lastSweep = now
}
