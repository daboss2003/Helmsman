package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidHostname(t *testing.T) {
	good := []string{"ntfy.example.com", "a.b.co", "my-ntfy.sub.example.io"}
	bad := []string{"", "localhost", "example", "http://ntfy.example.com", "ntfy.example.com/x", "ntfy .com", "ntfy.example.com:8080", "-bad.example.com"}
	for _, h := range good {
		if !validHostname(h) {
			t.Errorf("validHostname(%q) = false, want true", h)
		}
	}
	for _, h := range bad {
		if validHostname(h) {
			t.Errorf("validHostname(%q) = true, want false", h)
		}
	}
}

// Without the managed edge (no runner/edge in the bare test server), provisioning a
// Mooring-hosted ntfy is refused with a clear error and creates no channel.
func TestProvisionManagedNtfyNeedsEdge(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/alerts/channels", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{
			"csrf_token":    {csrf.Value},
			"name":          {"hosted"},
			"kind":          {"ntfy_managed"},
			"ntfy_hostname": {"ntfy.example.com"},
			"ntfy_topic":    {"alerts"},
		})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/alerts/channels?err=") {
		t.Fatalf("expected an error redirect, got %q", loc)
	}
	if _, ok, _ := e.srv.alertStore.ManagedNtfy(); ok {
		t.Error("no managed ntfy channel should be created when the edge is unavailable")
	}
}
