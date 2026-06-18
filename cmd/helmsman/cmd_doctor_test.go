package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckBinary(t *testing.T) {
	// `sh` exists on any Unix dev/CI box; a nonsense name never does.
	if got := checkBinary("sh", "shell", "fix"); got.state != "ok" {
		t.Errorf("sh should be ok, got %q", got.state)
	}
	missing := checkBinary("helmsman-no-such-binary-xyz", "thing", "do the fix")
	if missing.state != "fail" {
		t.Errorf("missing binary should fail, got %q", missing.state)
	}
	if missing.fix != "do the fix" {
		t.Errorf("fix not carried through: %q", missing.fix)
	}
}

func TestReportPrint(t *testing.T) {
	var r report
	r.add(result{"caddy", "fail", "MISSING", "sudo helmsman setup --yes"})
	r.add(result{"docker", "ok", "found", ""})
	if !r.hasFail() {
		t.Error("hasFail should be true")
	}
	var buf bytes.Buffer
	r.print(&buf)
	out := buf.String()
	if !strings.Contains(out, "✗ caddy") || !strings.Contains(out, "✓ docker") {
		t.Errorf("missing status icons:\n%s", out)
	}
	if !strings.Contains(out, "→ sudo helmsman setup --yes") {
		t.Errorf("fix hint not printed for a failing check:\n%s", out)
	}
	// An ok check must not print a fix arrow.
	if strings.Count(out, "→") != 1 {
		t.Errorf("expected exactly one fix arrow:\n%s", out)
	}
}

// TestCaddyRepoConstants guards the apt repo wiring against silent typos: the sources
// line must reference the key path via signed-by, and the key must be fetched over TLS.
func TestCaddyRepoConstants(t *testing.T) {
	if !strings.Contains(caddySources, "signed-by="+caddyKeyPath) {
		t.Errorf("sources line must pin the key via signed-by: %q", caddySources)
	}
	if !strings.HasPrefix(caddyKeyURL, "https://") {
		t.Errorf("the signing key must be fetched over HTTPS: %q", caddyKeyURL)
	}
	if !strings.HasSuffix(caddyKeyPath, ".asc") {
		t.Errorf("armored key path should end .asc for apt signed-by: %q", caddyKeyPath)
	}
}
