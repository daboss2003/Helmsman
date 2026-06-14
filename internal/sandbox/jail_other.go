//go:build !linux

package sandbox

import (
	"context"
	"runtime"
)

// On any non-Linux host the jail's containment guarantees (cgroup-wide
// freeze+SIGKILL of a detached child, userns isolation) are not available, so the
// sandbox is FAIL-CLOSED: it reports unavailable and refuses to run anything.

// Available reports the sandbox cannot run here.
func Available() (bool, string) {
	return false, "setup sandbox requires Linux (got " + runtime.GOOS + "); fail-closed"
}

// SelfTest always fails closed off-Linux.
func SelfTest(ctx context.Context, c Config) error { return ErrUnavailable }

// Run always fails closed off-Linux.
func Run(ctx context.Context, c Config, ss ScriptSet, scratchDir string) (RunResult, error) {
	return RunResult{}, ErrUnavailable
}
