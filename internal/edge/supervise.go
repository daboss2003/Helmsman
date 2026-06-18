package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Available reports whether this host can OWN the managed edge. The edge is a
// supervised child Caddy with a systemd slice + CAP_NET_BIND_SERVICE + an egress
// firewall (plan §6) — Linux-only. On any other OS, or with no caddy binary, the
// edge is FAIL-CLOSED unavailable (managed mode degrades to an "edge not owned"
// banner; Helmsman's control plane still serves).
func Available(caddyBin string) (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "managed edge requires Linux (got " + runtime.GOOS + ")"
	}
	if caddyBin == "" {
		caddyBin = "caddy"
	}
	if _, err := exec.LookPath(caddyBin); err != nil {
		return false, "caddy binary not found on PATH"
	}
	return true, ""
}

// VerifyDigest checks the caddy binary's SHA-256 against a pinned digest (supply
// chain — refuse on mismatch, plan §6). An empty want skips the check.
func VerifyDigest(caddyPath, want string) error {
	if want == "" {
		return nil
	}
	f, err := os.Open(caddyPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("edge: caddy binary digest mismatch (refusing to launch)")
	}
	return nil
}

// Supervisor launches + supervises the child Caddy. It is fail-closed: if the
// host can't own the edge, Run logs and returns without starting anything.
type Supervisor struct {
	CaddyBin    string
	AdminListen string
	InitialCfg  []byte // the typed base render (Layer 0) — the recovery floor
	Log         *slog.Logger
}

// Run supervises the child with capped backoff until ctx is cancelled. NOTE: the
// actual process launch + its systemd slice/user/caps/egress-firewall are the OS
// deployment layer (plan §6); this owns the lifecycle. Not exercised off-Linux.
func (s *Supervisor) Run(ctx context.Context) {
	if ok, why := Available(s.CaddyBin); !ok {
		s.Log.Warn("managed edge not started", "reason", why)
		return
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		if err := s.launch(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("edge child exited", "err", err)
		}
		if ctx.Err() != nil {
			return
		}
		// Reset backoff if the child ran a healthy while; else grow it (capped).
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

// launch runs `caddy run` with the resource set the OS layer pins. The admin API
// is the only control surface; the initial config is the safe base (SBD-8 floor).
func (s *Supervisor) launch(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.CaddyBin, "run", "--config", "-", "--adapter", "")
	cmd.Stdin = bytes.NewReader(s.InitialCfg)
	// Pin all of Caddy's storage under the writable /var/lib/caddy: HOME +
	// XDG_DATA_HOME (certs) + XDG_CONFIG_HOME (autosave config) — otherwise autosave
	// falls back to $HOME/.config and is fragile under the sandbox.
	cmd.Env = []string{"HOME=/var/lib/caddy", "XDG_DATA_HOME=/var/lib/caddy", "XDG_CONFIG_HOME=/var/lib/caddy"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // surface Caddy's startup/cert errors in journald (not /dev/null)
	cmd.WaitDelay = 5 * time.Second
	return cmd.Run()
}
