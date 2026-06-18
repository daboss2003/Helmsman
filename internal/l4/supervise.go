package l4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// nginxBin is fixed (never operator-supplied): the binary is invoked with the `-c`
// config flag, and the static-shell-exec lint (SEC-1) only permits `-c` on a literal,
// allowlisted command — a dynamic binary name + `-c` is exactly the shell-injection
// shape it forbids. Helmsman pins the binary by digest (VerifyDigest), not by path.
const nginxBin = "nginx"

// Available reports whether this host can OWN the managed L4 load balancer — a
// supervised child nginx (stream module) with its own systemd slice +
// CAP_NET_BIND_SERVICE + egress firewall (the L4 analog of the edge, plan §6),
// Linux-only. Off Linux, or with no nginx binary, it is FAIL-CLOSED unavailable.
func Available() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "managed L4 LB requires Linux (got " + runtime.GOOS + ")"
	}
	if _, err := exec.LookPath(nginxBin); err != nil {
		return false, "nginx binary not found on PATH"
	}
	return true, ""
}

// VerifyDigest checks the nginx binary's SHA-256 against a pinned digest (supply
// chain — refuse on mismatch, plan §6). An empty want skips the check.
func VerifyDigest(nginxPath, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(nginxPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("l4: nginx binary digest mismatch (refusing to launch)")
	}
	return nil
}

// Supervisor owns the child nginx that serves the L4 stream proxy. Config lives in a
// Helmsman-owned file; the operator never authors it. Reconcile renders from typed
// routes, validates with `nginx -t`, and only then swaps the live config + reloads —
// a rejected render keeps the last-good config serving (fail-closed). The testConf /
// signal seams let the reconcile state machine be unit-tested without a real nginx.
type Supervisor struct {
	ConfigPath string // the live config file the master reads (Helmsman-owned)
	Prefix     string // nginx -p prefix dir (Helmsman-owned, e.g. /var/lib/helmsman/l4)
	Digest     string // pinned SHA-256 of the nginx binary (optional)
	Log        *slog.Logger

	mu   sync.Mutex
	proc *os.Process // running master, for a SIGHUP reload (nil when not running)

	// Seams (nil → real implementation): testConf runs `nginx -t`; sighup signals reload.
	testConf func(ctx context.Context, configPath string) error
	sighup   func(p *os.Process) error
}

// Reconcile renders the routes, validates the rendered config, and atomically swaps
// it in + reloads. It is fail-closed and serialized: a render error or an `nginx -t`
// rejection leaves the live config untouched (last-good keeps serving).
func (s *Supervisor) Reconcile(ctx context.Context, routes []Route) error {
	cfg, err := Render(routes) // bad routes → nothing changes
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.ConfigPath), 0o755); err != nil {
		return err
	}
	tmp := s.ConfigPath + ".new"
	if err := os.WriteFile(tmp, []byte(cfg), 0o644); err != nil {
		return err
	}
	if err := s.runTest(ctx, tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("l4: rendered config rejected by nginx -t (keeping last-good): %w", err)
	}
	if err := os.Rename(tmp, s.ConfigPath); err != nil { // atomic swap
		os.Remove(tmp)
		return err
	}
	if s.proc != nil {
		if err := s.doSighup(s.proc); err != nil {
			s.Log.Warn("l4: reload signal failed", "err", err)
		}
	}
	return nil
}

func (s *Supervisor) runTest(ctx context.Context, configPath string) error {
	if s.testConf != nil {
		return s.testConf(ctx, configPath)
	}
	cmd := exec.CommandContext(ctx, "nginx", "-t", "-c", configPath, "-p", s.Prefix) // literal: SEC-1 requires it
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func (s *Supervisor) doSighup(p *os.Process) error {
	if s.sighup != nil {
		return s.sighup(p)
	}
	return p.Signal(syscall.SIGHUP)
}

// ensureModuleDir points <Prefix>/modules at nginx's real module directory. Because
// nginx runs with `-p <Prefix>`, the relative `load_module modules/ngx_stream_module.so`
// that Debian/Ubuntu's /etc/nginx/modules-enabled emits resolves under <Prefix> — so
// without this it dlopens <Prefix>/modules/… and the stream module is "not found".
// Best-effort: if nginx's module dir can't be determined (stream built into nginx, or
// no nginx) it's a no-op, and `nginx -t` surfaces any genuine problem.
func (s *Supervisor) ensureModuleDir() {
	dir := nginxModulesDir()
	if dir == "" {
		return
	}
	link := filepath.Join(s.Prefix, "modules")
	if cur, err := os.Readlink(link); err == nil && cur == dir {
		return // already correct
	}
	if err := os.MkdirAll(s.Prefix, 0o755); err != nil {
		s.Log.Warn("l4: could not create prefix dir for the module link", "err", err)
		return
	}
	_ = os.Remove(link) // replace a stale/wrong link (no-op if absent)
	if err := os.Symlink(dir, link); err != nil {
		s.Log.Warn("l4: could not link nginx module dir", "link", link, "target", dir, "err", err)
	}
}

// nginxModulesDir returns nginx's compiled --modules-path (from `nginx -V`), or "" if
// nginx is absent or the path can't be parsed.
func nginxModulesDir() string {
	out, err := exec.Command(nginxBin, "-V").CombinedOutput() // nginx -V prints config to stderr; literal binary (SEC-1)
	if err != nil {
		return ""
	}
	return parseModulesPath(string(out))
}

// parseModulesPath extracts --modules-path=<dir> from `nginx -V` output.
func parseModulesPath(nginxV string) string {
	for _, tok := range strings.Fields(nginxV) {
		if v, ok := strings.CutPrefix(tok, "--modules-path="); ok {
			return v
		}
	}
	return ""
}

// Run supervises the child nginx with capped backoff until ctx is cancelled. It is
// fail-closed: if the host can't own the L4 LB (non-Linux, no binary, digest
// mismatch) it logs and returns without starting anything. The systemd slice / user
// / caps / egress firewall are the OS deployment layer (plan §6); this owns the
// lifecycle. Not exercised off-Linux.
func (s *Supervisor) Run(ctx context.Context) {
	if ok, why := Available(); !ok {
		s.Log.Warn("managed L4 LB not started", "reason", why)
		return
	}
	if s.Digest != "" {
		path, err := exec.LookPath(nginxBin)
		if err != nil {
			s.Log.Error("managed L4 LB not started", "err", err)
			return
		}
		if err := VerifyDigest(path, s.Digest); err != nil {
			s.Log.Error("managed L4 LB not started", "err", err)
			return
		}
	}
	// Make the prefix-relative `load_module modules/…` (from /etc/nginx/modules-enabled
	// on Debian/Ubuntu) resolve, since we run nginx with `-p <Prefix>`.
	s.ensureModuleDir()
	// Ensure a valid config exists before the first launch (an empty stream block
	// is a valid floor; routes are pushed via Reconcile).
	if _, err := os.Stat(s.ConfigPath); err != nil {
		if rerr := s.Reconcile(ctx, nil); rerr != nil {
			s.Log.Error("l4: could not write initial config", "err", rerr)
			return
		}
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		if err := s.launch(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("l4 child exited", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		} else if backoff < 30*time.Second {
			backoff *= 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// launch runs nginx in the foreground (daemon off) so this supervisor owns its
// lifecycle and can SIGHUP it for a graceful reload. The resource set / slice / caps
// are pinned by the OS layer.
func (s *Supervisor) launch(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nginx", "-c", s.ConfigPath, "-p", s.Prefix, "-g", "daemon off;") // literal: SEC-1 requires it
	cmd.Env = []string{"HOME=" + s.Prefix}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // surface nginx errors in journald (not /dev/null)
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.proc = cmd.Process
	s.mu.Unlock()
	err := cmd.Wait()
	s.mu.Lock()
	s.proc = nil
	s.mu.Unlock()
	return err
}
