// Package sandbox is the Mode-3 setup-script jail (plan §7/§9) — the single most
// dangerous feature in Helmsman, so it is built assuming the script IS hostile.
// It is OFF by default and FAIL-CLOSED: a script runs only inside a throwaway,
// unprivileged, no-docker.sock, no-network, read-only-rootfs, resource-capped
// jail whose live self-test must pass before EVERY run; ALL captured output is
// treated as hostile data. The jail backend is Linux-only (cgroup-freeze +
// userns isolation); on any other OS Available()/SelfTest()/Run() fail closed.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Trigger decides whether a setup STEP is included in an operator-initiated,
// confirm-token-gated deploy plan — it is a planner input, NEVER an executor, and
// never runs the jail from a webhook/auto-deploy/boot (plan §7).
const (
	TriggerNever            = "never"
	TriggerOnDemand         = "on_demand"
	TriggerOnFirstDeploy    = "on_first_deploy"
	TriggerBeforeEachDeploy = "before_each_deploy"
)

var validTrigger = map[string]bool{
	TriggerNever: true, TriggerOnDemand: true, TriggerOnFirstDeploy: true, TriggerBeforeEachDeploy: true,
}

// autoTriggers are incompatible with git.auto_deploy (auto-deploy + auto-setup is
// a parse-time hard reject, plan §7).
func IsAutoTrigger(t string) bool {
	return t == TriggerOnFirstDeploy || t == TriggerBeforeEachDeploy
}

// Limits are the jail resource caps (from the validated config.setup block).
type Limits struct {
	WallClock   time.Duration
	CPUs        string
	MemoryMB    int
	PidsLimit   int
	ScratchMB   int
	OutputCapKB int
}

// ScriptSet is one app's setup script plus the policy that pins its identity.
type ScriptSet struct {
	Script    string   // the script bytes (run with /bin/sh in the jail)
	Trigger   string   // never | on_demand | on_first_deploy | before_each_deploy
	Produces  []string // declared outputs: "env:NAME" and/or "file:relpath"
	PinnedSHA string   // the repo/spec sha this is bound to ("" if none)
}

// Validate enforces the structural rules on a script set (plan §7). autoDeploy is
// the app's git.auto_deploy flag — auto-setup + auto-deploy is a hard reject.
func (ss ScriptSet) Validate(autoDeploy bool) error {
	if strings.TrimSpace(ss.Script) == "" {
		return errors.New("setup script is empty")
	}
	if !validTrigger[ss.Trigger] {
		return fmt.Errorf("setup trigger %q is invalid", ss.Trigger)
	}
	if autoDeploy && IsAutoTrigger(ss.Trigger) {
		return errors.New("auto-deploy is incompatible with an auto setup trigger (on_first_deploy/before_each_deploy)")
	}
	for _, p := range ss.Produces {
		if err := validateProduces(p); err != nil {
			return err
		}
	}
	return nil
}

var (
	produceEnvRe  = regexp.MustCompile(`^env:[A-Z_][A-Z0-9_]*$`)
	produceFileRe = regexp.MustCompile(`^file:[A-Za-z0-9._/-]+$`)
)

func validateProduces(p string) error {
	switch {
	case strings.HasPrefix(p, "env:"):
		if !produceEnvRe.MatchString(p) {
			return fmt.Errorf("produces %q: env name must match [A-Z_][A-Z0-9_]*", p)
		}
	case strings.HasPrefix(p, "file:"):
		if !produceFileRe.MatchString(p) {
			return fmt.Errorf("produces %q: file path has illegal characters", p)
		}
		rel := strings.TrimPrefix(p, "file:")
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") || strings.HasSuffix(rel, "/..") {
			return fmt.Errorf("produces %q: file path must be a relative, traversal-free path", p)
		}
	default:
		return fmt.Errorf("produces %q: must start with env: or file:", p)
	}
	return nil
}

// Checksum binds the FULL identity of a setup run (plan §7): script bytes + limits
// + produces + trigger + pinned-sha. The confirm token and the setup_runs
// idempotence key derive from this, so raising a cap, adding a capture, changing
// the trigger, or editing a byte all VOID a prior confirmation. Encoded
// unambiguously (length-prefixed) so no two distinct inputs can collide.
func (ss ScriptSet) Checksum(lim Limits) string {
	h := sha256.New()
	field := func(s string) {
		fmt.Fprintf(h, "%d:", len(s))
		h.Write([]byte(s))
	}
	field(ss.Script)
	field(ss.Trigger)
	field(ss.PinnedSHA)
	prod := append([]string(nil), ss.Produces...)
	sort.Strings(prod)
	field(strings.Join(prod, "\x00"))
	field(fmt.Sprintf("wc=%d;cpu=%s;mem=%d;pids=%d;scratch=%d;out=%d",
		lim.WallClock, lim.CPUs, lim.MemoryMB, lim.PidsLimit, lim.ScratchMB, lim.OutputCapKB))
	return hex.EncodeToString(h.Sum(nil))
}

// Config configures the throwaway-container jail backend.
type Config struct {
	Image  string // digest-pinned base image
	Binary string // docker CLI ("docker")
	Limits Limits
	UID    int // run the script as this (non-root) uid so captures are Helmsman-owned
	GID    int
}

// RunResult is the outcome of a jail execution.
type RunResult struct {
	ExitCode int
	Output   string // combined stdout+stderr, capped at OutputCapKB
	TimedOut bool
}

// ErrUnavailable means the host cannot provide a working sandbox (non-Linux, or a
// failed self-test). It is ALWAYS fail-closed: when in doubt, refuse to run.
var ErrUnavailable = errors.New("sandbox: unavailable on this host (fail-closed)")

// --- capture-as-hostile-data (plan §7) ---

var capturedEnvKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ValidateCapturedEnvKey enforces the key shape on a value the SCRIPT emitted.
func ValidateCapturedEnvKey(k string) error {
	if !capturedEnvKeyRe.MatchString(k) {
		return fmt.Errorf("captured env key %q is invalid", k)
	}
	return nil
}

// ValidateCapturedEnvValue rejects a captured value containing newline/CR/NUL or
// a ${ sequence — captured values are stored OPAQUE and must never be re-expanded
// through compose interpolation (plan §7 red-team).
func ValidateCapturedEnvValue(v string) error {
	if strings.ContainsAny(v, "\n\r\x00") {
		return errors.New("captured env value contains a control character")
	}
	if strings.Contains(v, "${") {
		return errors.New("captured env value contains a ${ interpolation sequence")
	}
	return nil
}

// ConfineCapturePath resolves a script-declared captured file name to an absolute
// destination under runDir, rejecting traversal/absolute/escaping paths. The
// caller still writes it O_NOFOLLOW + regular-file-only + size-capped + 0600.
func ConfineCapturePath(runDir, name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("captured file %q is not a safe relative path", name)
	}
	dest := filepath.Join(runDir, clean)
	rel, err := filepath.Rel(runDir, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("captured file %q escapes the app directory", name)
	}
	return dest, nil
}
