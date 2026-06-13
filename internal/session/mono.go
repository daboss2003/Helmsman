package session

import "time"

// pkgStart is captured once with a monotonic clock reading. time.Since(pkgStart)
// then yields elapsed monotonic time, immune to wall-clock steps (plan §5.9).
var pkgStart = time.Now()

// monoNow returns monotonic time elapsed since process start.
func monoNow() time.Duration { return time.Since(pkgStart) }
