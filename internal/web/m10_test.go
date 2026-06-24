package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestAlertChannelSaveEncryptedAndListed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := url.Values{"name": {"hook"}, "kind": {"webhook"}, "url": {"https://example.com/h"}, "secret": {"s3cr3t-hmac"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/alerts/channels", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("channel save = %d, want 303", resp.StatusCode)
	}
	page := readBody(e.req(t, "GET", "/alerts/channels", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, "hook") {
		t.Error("channel not listed")
	}
	if strings.Contains(page, "s3cr3t-hmac") {
		t.Error("channels page leaked a channel secret")
	}
}

func TestAlertRuleSaveAndList(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := url.Values{"name": {"cpu high"}, "kind": {"host_cpu"}, "threshold": {"90"}, "for_seconds": {"60"}, "level": {"warning"}, "enabled": {"on"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/alerts/rules", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rule save = %d, want 303", resp.StatusCode)
	}
	page := readBody(e.req(t, "GET", "/alerts/rules", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, "cpu high") || !strings.Contains(page, "host_cpu") {
		t.Error("rule not listed")
	}
	bad := url.Values{"name": {"x"}, "kind": {"nonsense"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/alerts/rules", "127.0.0.1:1", hdr, cookies, bad); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("bad rule kind = %d, want 422", resp.StatusCode)
	}
}

// A "send test" to a loopback webhook is blocked by the SSRF guard (502), the
// error never leaks the URL, and nothing panics.
func TestAlertChannelTestSSRFGuard(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	e.req(t, "POST", "/alerts/channels", "127.0.0.1:1", hdr, cookies,
		url.Values{"name": {"loop"}, "kind": {"webhook"}, "url": {"http://127.0.0.1:9/h"}, "csrf_token": {csrf.Value}})
	chans, _ := e.srv.alertStore.ListChannels()
	if len(chans) != 1 {
		t.Fatal("channel not saved")
	}
	// The "send test" button (lc-btn) puts the id in the QUERY string, not the body —
	// regression guard for "could not build channel" (handler must read FormValue).
	resp := e.req(t, "POST", "/alerts/channels/test?id="+strconv.FormatInt(chans[0].ID, 10), "127.0.0.1:1", hdr, cookies,
		url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("loopback test = %d, want 502 (send failed/blocked, not a build error)", resp.StatusCode)
	}
	body := readBody(resp)
	if strings.Contains(body, "could not build channel") {
		t.Errorf("send-test failed to resolve the channel id from the query: %q", body)
	}
	// The secret-bearing URL PATH (where a Telegram token / Slack-Discord secret
	// lives) must be stripped from the echoed error; the resolved host:port may
	// remain (not a secret). Here the path is "/h".
	if strings.Contains(body, "/h") {
		t.Errorf("test response leaked the channel URL path: %q", body)
	}
}
