package socketproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded, Helmsman-owned proxy must stay locked down: loopback-only, capability-
// stripped, and deny-by-default (only the read verbs enabled). This guards the one
// component that fronts the docker socket from silently gaining write authority.
// NOTE: read_only on the rootfs is deliberately NOT asserted — the haproxy-based image
// renders its config under /usr/local/etc/haproxy at startup, so a read-only rootfs
// crash-loops it. The read-plane boundary is the :ro socket mount + verb allowlist +
// cap_drop + no-new-privileges asserted below, none of which depend on read_only.
func TestEmbeddedProxyIsLockedDown(t *testing.T) {
	c := string(Compose())
	for _, must := range []string{
		"127.0.0.1:2375:2375",                          // loopback bind only
		"/var/run/docker.sock:/var/run/docker.sock:ro", // read-only socket mount
		"cap_drop:",                                    // capabilities stripped
		"no-new-privileges:true",
		`CONTAINERS: "1"`, `INFO: "1"`, `VERSION: "1"`, // read verbs allowed
		`POST: "0"`, `EXEC: "0"`, `IMAGES: "0"`, `VOLUMES: "0"`, `NETWORKS: "0"`, `BUILD: "0"`, // write verbs denied
	} {
		if !strings.Contains(c, must) {
			t.Errorf("embedded proxy compose missing required hardening: %q", must)
		}
	}
	// No write verb may be enabled.
	for _, banned := range []string{`POST: "1"`, `EXEC: "1"`, `IMAGES: "1"`, `VOLUMES: "1"`, `NETWORKS: "1"`, `BUILD: "1"`} {
		if strings.Contains(c, banned) {
			t.Errorf("embedded proxy enables a write verb: %q", banned)
		}
	}
}

// Helmsman auto-pulls and runs this image at boot with the raw docker socket mounted
// in, so a mutable :tag would be a supply-chain swap into root. It MUST be digest-
// pinned (matches the project's rule for setup.image and the Caddy binary).
func TestEmbeddedProxyImageIsDigestPinned(t *testing.T) {
	imageLines := 0
	for _, line := range strings.Split(string(Compose()), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		imageLines++
		ref := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
		// A bare ...:tag (no digest) is the supply-chain swap vector.
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("proxy image must be digest-pinned (@sha256:), got: %q", ref)
		}
	}
	if imageLines != 1 {
		t.Errorf("expected exactly one image: line, got %d", imageLines)
	}
}

func TestMaterializeWritesCompose(t *testing.T) {
	dataDir := t.TempDir()
	path, err := Materialize(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataDir, "socket-proxy", "docker-compose.yml"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(Compose()) {
		t.Error("materialized compose must equal the embedded bytes")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("compose mode = %o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 0700", di.Mode().Perm())
	}
	// Idempotent: a second call overwrites cleanly.
	if _, err := Materialize(dataDir); err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
}

func TestEnsureRunningNilRunner(t *testing.T) {
	if err := EnsureRunning(nil, nil, t.TempDir(), nil); err == nil {
		t.Error("nil runner must error")
	}
}
