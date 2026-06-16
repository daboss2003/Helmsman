package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/Helmsman/internal/compose"
)

func sampleSpec() Spec {
	return Spec{
		Slug: "shop",
		Services: []Service{{
			Name:    "web",
			Image:   "nginx:1.27",
			Ports:   []Port{{Internal: 8080, Publish: true}},
			Volumes: []Volume{{Name: "data", Target: "/var/lib/data"}, {Source: "conf", Target: "/etc/app", ReadOnly: true}},
			Env:     []EnvVar{{Key: "LOG_LEVEL", Value: "info"}, {Key: "DB_PASSWORD", Secret: "DB_PASSWORD"}},
			Restart: "unless-stopped",
		}},
	}
}

// The generated compose is safe by construction AND passes the §5.6 chokepoint.
func TestGenerateProducesSafeComposeThatPassesValidator(t *testing.T) {
	out, err := Generate(sampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "image: nginx:1.27") {
		t.Errorf("missing image:\n%s", s)
	}
	// Loopback-bound publish by default (not 0.0.0.0).
	if !strings.Contains(s, "127.0.0.1:8080:8080") {
		t.Errorf("port not loopback-bound:\n%s", s)
	}
	// Non-secret literals are inline; secrets are by-reference (${NAME}), never valued.
	if !strings.Contains(s, "LOG_LEVEL=info") {
		t.Errorf("literal env not inline:\n%s", s)
	}
	if !strings.Contains(s, "DB_PASSWORD=${DB_PASSWORD}") {
		t.Errorf("secret env not by-reference:\n%s", s)
	}
	// Must pass §5.6 against a run dir.
	res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{})
	if !res.OK() {
		t.Fatalf("generated compose failed §5.6: %s", res.Error())
	}
}

// Public publish binds all interfaces only when explicitly acked.
func TestGeneratePublicPortBindsAllInterfaces(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{{Internal: 8080, Publish: true, Public: true}}
	out, _ := Generate(spec)
	if strings.Contains(string(out), "127.0.0.1:8080") {
		t.Error("public port should not be loopback-bound")
	}
	if !strings.Contains(string(out), "8080:8080") {
		t.Errorf("public port mapping missing:\n%s", out)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]func(*Spec){
		"bad slug":             func(s *Spec) { s.Slug = "Bad Slug" },
		"empty tag":            func(s *Spec) { s.Services[0].Image = "nginx" },
		"control port":         func(s *Spec) { s.Services[0].Ports = []Port{{Internal: 9000, Publish: true}} },
		"abs bind":             func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "/etc", Target: "/x"}} },
		"traversal bind":       func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "../escape", Target: "/x"}} },
		"both name+source":     func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Source: "s", Target: "/x"}} },
		"rel container target": func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Target: "rel"}} },
		"bad env key":          func(s *Spec) { s.Services[0].Env = []EnvVar{{Key: "1BAD"}} },
		"env literal interp":   func(s *Spec) { s.Services[0].Env = []EnvVar{{Key: "X", Value: "${OTHER}"}} },
		"unknown depends_on":   func(s *Spec) { s.Services[0].DependsOn = []string{"ghost"} },
		"bad restart":          func(s *Spec) { s.Services[0].Restart = "sometimes" },
		"newline in command":   func(s *Spec) { s.Services[0].Command = []string{"sh\n-c"} },
		"colon in bind source": func(s *Spec) { s.Services[0].Volumes = []Volume{{Source: "a:b", Target: "/x"}} },
		"colon in target":      func(s *Spec) { s.Services[0].Volumes = []Volume{{Name: "v", Target: "/x:y"}} },
	}
	for name, mut := range cases {
		s := sampleSpec()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// The generator has no field for dangerous keys; even a maximal spec can't emit
// them. (Belt: scan the output for the forbidden set.)
func TestGenerateNeverEmitsDangerousKeys(t *testing.T) {
	out, err := Generate(sampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"privileged", "cap_add", "devices", "network_mode", "pid:", "security_opt", "/var/run/docker.sock"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("generated compose contains forbidden token %q:\n%s", bad, out)
		}
	}
}

// Commit writes atomically and is replaceable; a half-written staging dir never
// becomes the app, and SweepStaging cleans leftovers.
func TestCommitAtomicAndSweep(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "shop")
	files := []File{{RelPath: "docker-compose.yml", Data: []byte("services: {}\n")}}
	if err := Commit(root, runDir, files); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "docker-compose.yml")); err != nil || !strings.Contains(string(b), "services") {
		t.Fatalf("compose not committed: %v %q", err, b)
	}
	// Re-commit (update) replaces atomically.
	files2 := []File{{RelPath: "docker-compose.yml", Data: []byte("services:\n  v2: {}\n")}}
	if err := Commit(root, runDir, files2); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(runDir, "docker-compose.yml"))
	if !strings.Contains(string(b), "v2") {
		t.Errorf("update did not replace: %q", b)
	}
	// No staging/aside leftovers after a clean commit.
	leftovers := stagingLeftovers(t, root)
	if leftovers != 0 {
		t.Errorf("%d staging/aside dirs left after commit", leftovers)
	}
	// Sweep removes a planted stale staging dir.
	os.Mkdir(filepath.Join(root, ".staging-abc"), 0o700)
	os.Mkdir(filepath.Join(root, ".old-xyz"), 0o700)
	SweepStaging(root)
	if stagingLeftovers(t, root) != 0 {
		t.Error("sweep did not remove stale dirs")
	}
}

func TestCommitRejectsTraversalArtifact(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "shop")
	err := Commit(root, runDir, []File{{RelPath: "../../etc/evil", Data: []byte("x")}})
	if err == nil {
		t.Fatal("traversal artifact path should be rejected")
	}
	if _, statErr := os.Stat(runDir); statErr == nil {
		t.Error("run dir should not exist after a rejected commit")
	}
}

func stagingLeftovers(t *testing.T, root string) int {
	t.Helper()
	entries, _ := os.ReadDir(root)
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") || strings.HasPrefix(e.Name(), ".old-") {
			n++
		}
	}
	return n
}
