package opsclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/secret"
)

func TestValidateRelPath(t *testing.T) {
	good := []string{"/", "/health/live", "/ops/health/snapshot", "/a.b_c-d/e"}
	for _, p := range good {
		if !ValidateRelPath(p) {
			t.Errorf("ValidateRelPath(%q) = false, want true", p)
		}
	}
	bad := []string{
		"",                             // empty
		"health/live",                  // no leading slash
		"//evil.com/x",                 // protocol-relative authority
		"http://169.254.169.254/",      // scheme+host (descriptor trying to move host)
		"/path?q=1",                    // query not allowed
		"/a/../../etc",                 // traversal
		"/has space",                   // space
		"/" + strings.Repeat("a", 200), // too long
		"/has\nnewline",                // control char
	}
	for _, p := range bad {
		if ValidateRelPath(p) {
			t.Errorf("ValidateRelPath(%q) = true, want false", p)
		}
	}
}

// The headline invariant: the descriptor cannot move the outbound host.
func TestDescriptorCannotMoveHost(t *testing.T) {
	base := "http://web:8080"
	// Anything a hostile descriptor might inject as a "path" is rejected before
	// it can reach the URL builder...
	for _, evil := range []string{"http://169.254.169.254/", "//169.254.169.254/", "https://evil/x"} {
		if _, err := pinnedURL(base, evil); !errors.Is(err, ErrBadRelPath) {
			t.Errorf("pinnedURL accepted host-moving path %q: %v", evil, err)
		}
	}
	// ...and a valid relative path keeps the pinned host.
	u, err := pinnedURL(base, "/health/live")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "web:8080" || u.Scheme != "http" || u.Path != "/health/live" {
		t.Errorf("pinned URL wrong: %s", u)
	}
}

func TestPinnedURLRejectsBadBase(t *testing.T) {
	for _, b := range []string{"ftp://x", "http://", "::::", "/no-scheme"} {
		if _, err := pinnedURL(b, "/x"); !errors.Is(err, ErrBadBase) {
			t.Errorf("pinnedURL(%q) accepted bad base: %v", b, err)
		}
	}
}

func TestProdBlockedCIDRs(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "169.254.169.254", "169.254.1.1", "fe80::1", "224.0.0.1", "0.0.0.0", "::"}
	for _, s := range blocked {
		if !prodBlocked(netip.MustParseAddr(s)) {
			t.Errorf("prodBlocked(%s) = false, want true", s)
		}
	}
	// private container ranges MUST be allowed (apps live there)
	allowed := []string{"172.17.0.2", "10.0.0.5", "192.168.1.10", "100.64.0.1", "8.8.8.8"}
	for _, s := range allowed {
		if prodBlocked(netip.MustParseAddr(s)) {
			t.Errorf("prodBlocked(%s) = true, want false", s)
		}
	}
	// review #2: NAT64-encoded metadata/loopback must be blocked.
	if !prodBlocked(netip.MustParseAddr("64:ff9b::a9fe:a9fe")) { // 169.254.169.254
		t.Error("NAT64 metadata 64:ff9b::a9fe:a9fe not blocked")
	}
	if !prodBlocked(netip.MustParseAddr("64:ff9b::7f00:1")) { // 127.0.0.1
		t.Error("NAT64 loopback 64:ff9b::7f00:1 not blocked")
	}
	// a real global IPv6 (NAT64 prefix carrying a public v4) stays allowed
	if prodBlocked(netip.MustParseAddr("64:ff9b::808:808")) { // 8.8.8.8
		t.Error("NAT64 public address wrongly blocked")
	}
}

func TestValidHeaderName(t *testing.T) {
	for _, ok := range []string{"X-Ops-Secret", "Authorization", "a1-B2"} {
		if !ValidHeaderName(ok) {
			t.Errorf("ValidHeaderName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "X Ops", "X:Y", "a_b", "x\n"} {
		if ValidHeaderName(bad) {
			t.Errorf("ValidHeaderName(%q) = true", bad)
		}
	}
}

// The dialer must refuse when the pinned host resolves to a blocked address —
// even (especially) cloud metadata, and even against a rebinding resolver.
func TestDialerRefusesMetadataAndRebind(t *testing.T) {
	ctx := context.Background()
	cases := map[string][]string{
		"metadata":   {"169.254.169.254"},
		"loopback":   {"127.0.0.1"},
		"rebind-mix": {"172.17.0.2", "169.254.169.254"}, // one good + one bad → refuse
	}
	for name, ips := range cases {
		addrs := make([]netip.Addr, len(ips))
		for i, s := range ips {
			addrs[i] = netip.MustParseAddr(s)
		}
		c := newClient(func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }, prodBlocked, 3*time.Second)
		_, err := c.Get(ctx, "http://pinned.test/", "/health/live", "", secret.Redacted{})
		if !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: got err %v, want ErrBlockedTarget", name, err)
		}
	}
}

// Successful call path: secret header sent, host pinned via injected resolver.
func TestSuccessfulCallSendsSecretHeader(t *testing.T) {
	var gotHeader, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Ops-Secret")
		gotPath = r.URL.Path
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	c, base := testClientFor(srv.URL)
	resp, err := c.Get(context.Background(), base, "/health/live", "X-Ops-Secret", secret.New("super-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || string(resp.Body) != `{"status":"ok"}` {
		t.Errorf("resp = %d %q", resp.Status, resp.Body)
	}
	if gotHeader != "super-secret-value" {
		t.Errorf("secret header not sent: %q", gotHeader)
	}
	if gotPath != "/health/live" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestDoesNotFollowRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/", http.StatusFound)
	}))
	defer srv.Close()
	c, base := testClientFor(srv.URL)
	resp, err := c.Get(context.Background(), base, "/x", "", secret.Redacted{})
	if err != nil {
		t.Fatal(err)
	}
	// ErrUseLastResponse returns the 302 verbatim (its body is just the redirect
	// stub). status==302 (not 200) proves the client did NOT follow it.
	if resp.Status != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect not followed)", resp.Status)
	}
}

func TestResponseSizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 4<<20)) // 4 MiB
	}))
	defer srv.Close()
	c, base := testClientFor(srv.URL)
	resp, err := c.Get(context.Background(), base, "/big", "", secret.Redacted{})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(resp.Body)) > c.maxBytes {
		t.Errorf("body %d exceeds cap %d", len(resp.Body), c.maxBytes)
	}
}

// testClientFor builds a client whose resolver maps any host to the httptest
// server's loopback address, with a permissive block func (the production block
// func is exercised separately in TestProdBlockedCIDRs / TestDialerRefuses...).
func testClientFor(serverURL string) (*Client, string) {
	u, _ := url.Parse(serverURL)
	port := u.Port()
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	permissive := func(netip.Addr) bool { return false }
	return newClient(lookup, permissive, 5*time.Second), "http://pinned.test:" + port
}
