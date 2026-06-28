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
	pw, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	return Params{BaseURL: "https://ntfy.example.com", Topic: "alerts", WriteToken: w, SubPassword: pw}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 24 || seen[pw] {
			t.Fatalf("bad/duplicate password %q (len %d)", pw, len(pw))
		}
		seen[pw] = true
	}
}

// The infra image must stay digest-pinned (supply-chain posture) and on a version that
// supports declarative auth seeding (>= v2.14.0).
func TestImageDigestPinned(t *testing.T) {
	if !strings.Contains(Image, "@sha256:") {
		t.Errorf("ntfy image must be digest-pinned, got %q", Image)
	}
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
		"http base":   func(p Params) Params { p.BaseURL = "http://x"; return p },
		"empty topic": func(p Params) Params { p.Topic = ""; return p },
		"bad topic":   func(p Params) Params { p.Topic = "has space"; return p },
		"short token": func(p Params) Params { p.WriteToken = "tk_short"; return p },
		"short pass":  func(p Params) Params { p.SubPassword = "short"; return p },
		"empty pass":  func(p Params) Params { p.SubPassword = ""; return p },
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

// The generated server.yml must lock the server down, give the publisher a write token
// and the subscriber a read-only account whose PASSWORD is the one the operator was
// shown (so they can sign into the ntfy app).
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
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("server.yml missing %q\n---\n%s", m, s)
		}
	}
	// The subscriber must never be granted write, and there must be NO subscriber token
	// (it logs in with username+password).
	if strings.Contains(s, `"phone:alerts:rw"`) || strings.Contains(s, `"phone:alerts:wo"`) {
		t.Error("subscriber must be read-only")
	}
	if strings.Contains(s, "phone:tk_") || strings.Contains(s, "Phone subscriber") {
		t.Error("subscriber must not get a token — it signs in with a password")
	}
	// The phone user's seeded bcrypt hash must verify against the shown password (so the
	// operator can actually sign in), and all hashes must be valid bcrypt.
	phoneVerified := false
	for _, line := range strings.Split(s, "\n") {
		i := strings.Index(line, "$2")
		if i < 0 {
			continue
		}
		h := strings.TrimSuffix(line[i:], `:user"`)
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			t.Errorf("invalid bcrypt hash in auth-users: %q (%v)", h, err)
		}
		if strings.Contains(line, SubscriberUser+":") && bcrypt.CompareHashAndPassword([]byte(h), []byte(p.SubPassword)) == nil {
			phoneVerified = true
		}
	}
	if !phoneVerified {
		t.Error("the phone user's bcrypt hash does not match the subscriber password")
	}
}

// The (re)provision path MUST force-recreate so ntfy restarts and re-reads a rewritten
// server.yml (it provisions auth-users + ACL into user.db only at process start). The
// boot reconcile path must NOT force-recreate, or every Helmsman restart would churn a
// correctly-running ntfy. This is the exact invariant whose violation caused signing in
// to fail with "user phone not authorized" after a re-provision.
func TestUpActionForceRecreate(t *testing.T) {
	reprovision := upAction(true)
	if !containsArg(reprovision, "--force-recreate") {
		t.Errorf("(re)provision up action must include --force-recreate, got %v", reprovision)
	}
	boot := upAction(false)
	if containsArg(boot, "--force-recreate") {
		t.Errorf("boot reconcile up action must NOT force-recreate, got %v", boot)
	}
	// Both must still be an idempotent detached up that prunes orphans.
	for _, a := range [][]string{reprovision, boot} {
		for _, want := range []string{"up", "-d", "--remove-orphans"} {
			if !containsArg(a, want) {
				t.Errorf("up action %v missing %q", a, want)
			}
		}
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
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
