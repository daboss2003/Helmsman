package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helmsman/helmsman/internal/crypto"
)

// validBase builds a minimal YAML config with a real key + password hash, then
// lets each test mutate one field to assert the fail-closed boot check fires.
func validYAML(t *testing.T, overrides string) string {
	t.Helper()
	hash, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	// 32-byte key, base64
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes
	base := `
bind_addr: "127.0.0.1:9000"
encryption_key: "` + key + `"
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + hash + `"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	return base + overrides
}

func mustReject(t *testing.T, yaml, wantSubstr string) {
	t.Helper()
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatalf("expected rejection containing %q, but config was accepted", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error %q does not mention %q", err.Error(), wantSubstr)
	}
}

func TestValidConfigLoads(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, "")))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Edge.Mode != EdgeManaged {
		t.Errorf("default edge mode not managed")
	}
	if len(cfg.Allowlist()) != 1 {
		t.Errorf("allowlist not parsed")
	}
	if cfg.Cookie.Prefix != "__Host-" {
		t.Errorf("default cookie prefix not __Host-")
	}
}

func TestEmptyAllowlistRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist: []
auth:
  username: "operator"
  password_hash: "$argon2id$v=19$m=8192,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "ip_allowlist: empty")
}

func TestNonLoopbackBindRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
`)+"\nbind_addr: \"0.0.0.0:9000\"\n", "bind_addr")
}

func TestManagedRequiresACMEEmail(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + mustHash(t) + `"
edge:
  mode: "managed"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "edge.acme_email")
}

func TestBadKeyLengthRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "c2hvcnQ="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + mustHash(t) + `"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "encryption_key")
}

func TestTrustedProxyTooBroadRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
trust_proxy: true
trusted_proxies:
  - "10.0.0.0/8"
`), "too broad")
}

func TestTrustProxyWithoutProxiesRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
trust_proxy: true
`), "trusted_proxies is empty")
}

func TestUnknownKeyRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
totally_unknown_key: "smuggled"
`), "parse")
}

func TestInvalidPasswordHashRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "not-a-real-hash"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "auth.password_hash")
}

func TestCookieSecurePrefixRequiresBasePath(t *testing.T) {
	mustReject(t, validYAML(t, `
cookie:
  prefix: "__Secure-"
`), "requires cookie.base_path")
}

func mustHash(t *testing.T) string {
	t.Helper()
	h, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTrustedProxyOverlapsAllowlistRefused(t *testing.T) {
	// validYAML's allowlist is 203.0.113.10/32; trusting the same IP must reject.
	mustReject(t, validYAML(t, `
trust_proxy: true
trusted_proxies:
  - "203.0.113.10/32"
`), "overlaps")
}

func TestParsePrefixCanonicalizes4in6(t *testing.T) {
	p, err := parsePrefix("::ffff:203.0.113.7/128")
	if err != nil {
		t.Fatal(err)
	}
	if p.Addr().Is4In6() {
		t.Errorf("4in6 prefix was not unmapped: %v", p)
	}
	if !p.Contains(netip.MustParseAddr("203.0.113.7")) {
		t.Errorf("canonicalized prefix %v does not contain the plain-v4 peer", p)
	}
	// The whole-IPv4-space 4in6 form must be flagged too broad (review #3).
	bp, err := parsePrefix("::ffff:0.0.0.0/96")
	if err != nil {
		t.Fatal(err)
	}
	if !tooBroad(bp) {
		t.Errorf("::ffff:0.0.0.0/96 (entire IPv4 space) not flagged too broad: %v", bp)
	}
}

func TestCheckPermsRejectsWorldAccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPerms(p); err == nil {
		t.Error("checkPerms accepted a world-readable (0644) config")
	}
}

func TestCheckPermsRejectsNonRootOwnerUnlessDevHatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the owner check passes trivially")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o600)
	t.Setenv(DevInsecurePermsEnv, "") // ensure the hatch is off
	if err := checkPerms(p); err == nil {
		t.Error("checkPerms accepted a non-root-owned config (root-of-trust bypass)")
	}
	t.Setenv(DevInsecurePermsEnv, "1")
	if err := checkPerms(p); err != nil {
		t.Errorf("dev escape hatch did not relax the owner check: %v", err)
	}
}
