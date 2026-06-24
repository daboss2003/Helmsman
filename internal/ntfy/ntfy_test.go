package ntfy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func validParams(t *testing.T) Params {
	t.Helper()
	w, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	r, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	return Params{BaseURL: "https://ntfy.example.com", Topic: "alerts", WriteToken: w, ReadToken: r}
}

func TestGenerateTokenFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		if !validToken(tok) || len(tok) != 32 {
			t.Fatalf("token %q is not tk_+29[a-z0-9] (32 chars)", tok)
		}
		if seen[tok] {
			t.Fatalf("token collision: %q", tok)
		}
		seen[tok] = true
	}
}

func TestValidateRejectsBadParams(t *testing.T) {
	good := validParams(t)
	cases := map[string]func(Params) Params{
		"http base":    func(p Params) Params { p.BaseURL = "http://x"; return p },
		"empty topic":  func(p Params) Params { p.Topic = ""; return p },
		"bad topic":    func(p Params) Params { p.Topic = "has space"; return p },
		"same tokens":  func(p Params) Params { p.ReadToken = p.WriteToken; return p },
		"short token":  func(p Params) Params { p.WriteToken = "tk_short"; return p },
		"no tk prefix": func(p Params) Params { p.ReadToken = strings.Repeat("a", 33); return p },
	}
	for name, mut := range cases {
		if err := mut(good).Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Errorf("valid params rejected: %v", err)
	}
}

// The generated server.yml must lock the server down and seed exactly the two
// token-bearing users with the right (write-only / read-only) access on the topic.
func TestServerYAMLLockdownAndSeeding(t *testing.T) {
	p := validParams(t)
	out, err := ServerYAML(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	must := []string{
		`auth-default-access: "deny-all"`,
		`base-url: "https://ntfy.example.com"`,
		`behind-proxy: true`,
		`upstream-base-url: "https://ntfy.sh"`,
		`"helmsman:alerts:wo"`, // publisher = write-only
		`"phone:alerts:ro"`,    // subscriber = read-only
		"helmsman:" + p.WriteToken + ":Helmsman publisher",
		"phone:" + p.ReadToken + ":Phone subscriber",
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("server.yml missing %q\n---\n%s", m, s)
		}
	}
	// The read token must never be granted write, and the write token never read.
	if strings.Contains(s, `"phone:alerts:rw"`) || strings.Contains(s, `"phone:alerts:wo"`) {
		t.Error("subscriber must be read-only")
	}
	// The bcrypt user hashes must be valid bcrypt (so ntfy accepts the users).
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "$2a$"); i >= 0 {
			h := strings.TrimSuffix(line[i:], `:user"`)
			if _, err := bcrypt.Cost([]byte(h)); err != nil {
				t.Errorf("invalid bcrypt hash in auth-users: %q (%v)", h, err)
			}
		}
	}
}

// Materialize writes a container-readable server.yml (0644) inside a private dir (0700)
// and a compose that bind-mounts it + publishes only on loopback.
func TestMaterializePermsAndCompose(t *testing.T) {
	dir := t.TempDir()
	p := validParams(t)
	composePath, err := Materialize(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(dir, "ntfy", "server.yml")

	st, err := os.Stat(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("server.yml perms = %o, want 0644 (container must read it)", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Join(dir, "ntfy"))
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("ntfy dir perms = %o, want 0700 (host-private)", dst.Mode().Perm())
	}

	compose, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	cs := string(compose)
	for _, m := range []string{
		"127.0.0.1:2586:80", // loopback publish only
		serverPath + ":/etc/ntfy/server.yml:ro",
		"helmsman-ntfy-lib:/var/lib/ntfy",
		"no-new-privileges:true",
	} {
		if !strings.Contains(cs, m) {
			t.Errorf("compose missing %q\n---\n%s", m, cs)
		}
	}
}
