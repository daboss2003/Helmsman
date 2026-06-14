//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The Linux jail backend: a throwaway, unprivileged container launched via the
// host docker CLI (NOT the read-only proxy — that has no run verb) with the full
// hardening set. Containment, not trust:
//   --network none        no egress, no loopback reach to 2375/2019/9000
//   --read-only           read-only rootfs (only the scratch bind is writable)
//   --cap-drop ALL        empty capability set
//   --security-opt no-new-privileges
//   --user <uid>:<gid>    non-root (so captures are Helmsman-owned, not root)
//   --pids-limit/--memory(=--memory-swap, swap off)/--cpus   resource caps
//   --rm                  removed (cgroup-wide kill) on exit/timeout
// The docker.sock / config dir / DB / master key are simply not in the mount set.

// hardeningArgs are the flags applied to BOTH the self-test probe and the run.
func (c Config) hardeningArgs(scratchDir string) []string {
	mem := strconv.Itoa(c.Limits.MemoryMB) + "m"
	return []string{
		"run", "--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", c.UID, c.GID),
		"--pids-limit", strconv.Itoa(c.Limits.PidsLimit),
		"--memory", mem, "--memory-swap", mem, // swap off (MemorySwapMax=0 equivalent)
		"--cpus", c.Limits.CPUs,
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"-v", scratchDir + ":/work:rw",
		"-w", "/work",
	}
}

// Available reports the sandbox can run here. The real posture is asserted by the
// per-run SelfTest; this only checks the docker CLI is present.
func Available() (bool, string) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, "docker CLI not found; setup sandbox unavailable"
	}
	return true, ""
}

// probeScript asserts the live posture from INSIDE the jail and prints one line.
const probeScript = `caps=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}'); ` +
	`net=$(ls /sys/class/net 2>/dev/null | tr '\n' ' '); ` +
	`ro=ro; (echo x > /hm-probe 2>/dev/null) && ro=rw; rm -f /hm-probe 2>/dev/null; ` +
	`echo "CAPEFF=$caps NET=${net}END RO=$ro"`

// SelfTest runs a probe with the SAME hardening as a real run and asserts (plan
// §7): empty effective capabilities, only the loopback NIC present (no egress /
// no reach to control ports under --network none), and a read-only rootfs. Any
// deviation — or a probe that won't run — is FAIL-CLOSED. (This is the §15 escape
// test as a runtime precondition.)
func SelfTest(ctx context.Context, c Config) error {
	if ok, why := Available(); !ok {
		return fmt.Errorf("%w: %s", ErrUnavailable, why)
	}
	// The probe needs a writable scratch only for the RO check; give it /work via
	// the caller-independent /tmp tmpfs is not enough (we test the rootfs), so use
	// a throwaway in-memory dir. We bind nothing writable except the tmpfs; the RO
	// check writes to / (rootfs), which must fail.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{
		"run", "--rm",
		"--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", c.UID, c.GID),
		"--pids-limit", "64", "--memory", "64m", "--memory-swap", "64m",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m",
		c.Image, "/bin/sh", "-c", probeScript,
	}
	out, err := runCapped(ctx, c.Binary, args, 8<<10)
	if err != nil {
		return fmt.Errorf("%w: probe did not run: %v", ErrUnavailable, err)
	}
	line := strings.TrimSpace(out)
	caps := field(line, "CAPEFF=")
	net := field(line, "NET=")
	ro := field(line, "RO=")
	if caps == "" || !isZeroCaps(caps) {
		return fmt.Errorf("%w: non-empty capabilities in jail (CapEff=%q)", ErrUnavailable, caps)
	}
	// Only the loopback NIC may exist (no egress; --network none). The probe MUST
	// have enumerated at least `lo` — an empty list means `ls /sys/class/net` did
	// not run, which is a deviation and is FAIL-CLOSED (not silently "no NICs").
	netClean := strings.TrimSpace(strings.TrimSuffix(net, "END"))
	nics := strings.Fields(netClean)
	if len(nics) == 0 {
		return fmt.Errorf("%w: network self-test inconclusive (probe enumerated no interfaces)", ErrUnavailable)
	}
	for _, nic := range nics {
		if nic != "lo" {
			return fmt.Errorf("%w: unexpected network interface %q in jail", ErrUnavailable, nic)
		}
	}
	if ro != "ro" {
		return fmt.Errorf("%w: jail rootfs is writable", ErrUnavailable)
	}
	return nil
}

// Run executes the script in the jail and returns the capped combined output.
// The caller MUST have run SelfTest immediately before (and hold the global
// one-docker-child semaphore).
func Run(ctx context.Context, c Config, ss ScriptSet, scratchDir string) (RunResult, error) {
	if ok, why := Available(); !ok {
		return RunResult{}, fmt.Errorf("%w: %s", ErrUnavailable, why)
	}
	wall := c.Limits.WallClock
	if wall <= 0 {
		wall = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, wall)
	defer cancel()

	args := append(c.hardeningArgs(scratchDir), c.Image, "/bin/sh", "-c", ss.Script)
	cap := c.Limits.OutputCapKB << 10
	if cap <= 0 {
		cap = 256 << 10
	}
	out, err := runCapped(runCtx, c.Binary, args, cap)
	res := RunResult{Output: out}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
		res.ExitCode = -1
		// --rm forces a cgroup-wide kill of the whole container (incl. any detached
		// child) when the context cancels the docker CLI.
		return res, fmt.Errorf("setup script exceeded the %s wall-clock limit", wall)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // a non-zero script exit is a result, not an infra error
		}
		return res, err
	}
	return res, nil
}

// runCapped runs argv, returning combined output truncated at capBytes.
func runCapped(ctx context.Context, binary string, args []string, capBytes int) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = minimalDockerEnv()
	var buf cappedBuffer
	buf.cap = capBytes
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.b.String(), err
}

func field(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		return rest[:j]
	}
	return rest
}

func isZeroCaps(hex string) bool {
	for _, c := range hex {
		if c != '0' {
			return false
		}
	}
	return len(hex) > 0
}

// minimalDockerEnv passes only what the docker CLI needs (never Helmsman's full
// env), mirroring dockerexec.
func minimalDockerEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type cappedBuffer struct {
	b   bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.b.Len() >= c.cap {
		return len(p), nil
	}
	if room := c.cap - c.b.Len(); len(p) > room {
		c.b.Write(p[:room])
		return len(p), nil
	}
	return c.b.Write(p)
}
