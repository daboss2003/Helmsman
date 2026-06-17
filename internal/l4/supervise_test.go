package l4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAvailableFailClosed(t *testing.T) {
	// On this (non-Linux) box the L4 LB must be unavailable, fail-closed.
	ok, why := Available()
	if ok {
		t.Skip("running on Linux; off-Linux fail-closed path not exercised")
	}
	if !strings.Contains(why, "Linux") {
		t.Errorf("expected a Linux requirement reason, got %q", why)
	}
}

func TestVerifyDigest(t *testing.T) {
	f := filepath.Join(t.TempDir(), "nginx")
	body := []byte("fake-binary")
	if err := os.WriteFile(f, body, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])

	if err := VerifyDigest(f, ""); err != nil {
		t.Errorf("empty want must skip the check: %v", err)
	}
	if err := VerifyDigest(f, good); err != nil {
		t.Errorf("matching digest must pass: %v", err)
	}
	if err := VerifyDigest(f, "deadbeef"); err == nil {
		t.Error("a wrong digest must be rejected")
	}
}

func newSup(t *testing.T) *Supervisor {
	t.Helper()
	return &Supervisor{
		ConfigPath: filepath.Join(t.TempDir(), "nginx.conf"),
		Prefix:     t.TempDir(),
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// A good render passes nginx -t (stubbed) → the live config is written + reloaded.
func TestReconcileWritesAndReloads(t *testing.T) {
	s := newSup(t)
	tested, reloaded := false, false
	s.testConf = func(ctx context.Context, p string) error { tested = true; return nil }
	s.sighup = func(p *os.Process) error { reloaded = true; return nil }

	if err := s.Reconcile(context.Background(), []Route{
		{Listen: 53, Protocol: "udp", Service: "coredns", Port: 5353},
	}); err != nil {
		t.Fatal(err)
	}
	if !tested {
		t.Error("nginx -t must run before swapping the live config")
	}
	if reloaded {
		t.Error("no reload expected when the master isn't running yet")
	}
	got, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		t.Fatalf("live config not written: %v", err)
	}
	if !strings.Contains(string(got), "listen 53 udp;") {
		t.Errorf("live config missing the rendered route:\n%s", got)
	}
	if _, err := os.Stat(s.ConfigPath + ".new"); !os.IsNotExist(err) {
		t.Error("temp config should be renamed away, not left behind")
	}
}

// nginx -t rejecting the new config must NOT replace the live (last-good) config.
func TestReconcileKeepsLastGoodOnTestFailure(t *testing.T) {
	s := newSup(t)
	// Seed a known-good live config.
	if err := os.WriteFile(s.ConfigPath, []byte("GOOD-CONFIG"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.testConf = func(ctx context.Context, p string) error { return errors.New("bad config") }

	err := s.Reconcile(context.Background(), []Route{
		{Listen: 853, Protocol: "tcp", Service: "coredns", Port: 8853},
	})
	if err == nil || !strings.Contains(err.Error(), "last-good") {
		t.Fatalf("a rejected render must error mentioning last-good, got %v", err)
	}
	got, _ := os.ReadFile(s.ConfigPath)
	if string(got) != "GOOD-CONFIG" {
		t.Errorf("live config was replaced despite nginx -t failure: %q", got)
	}
	if _, err := os.Stat(s.ConfigPath + ".new"); !os.IsNotExist(err) {
		t.Error("the rejected temp config must be cleaned up")
	}
}

// An invalid route makes Render fail → Reconcile changes nothing (fail-closed).
func TestReconcileRejectsBadRoute(t *testing.T) {
	s := newSup(t)
	if err := os.WriteFile(s.ConfigPath, []byte("GOOD"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.testConf = func(ctx context.Context, p string) error { return nil }
	if err := s.Reconcile(context.Background(), []Route{
		{Listen: 443, Protocol: "tcp", Service: "x", Port: 1}, // 443 is the HTTP edge's
	}); err == nil {
		t.Fatal("a route on a reserved port must be rejected before any write")
	}
	if got, _ := os.ReadFile(s.ConfigPath); string(got) != "GOOD" {
		t.Errorf("live config must be untouched on a render error: %q", got)
	}
}
