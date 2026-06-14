package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestEdgeRouteSaveAndList(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := url.Values{"hostname": {"app.example.com"}, "upstream": {"myapp-web:8080"}, "upstream_scheme": {"http"}, "hsts": {"on"}, "enabled": {"on"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/edge/routes", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("route save = %d, want 303", resp.StatusCode)
	}
	page := readBody(e.req(t, "GET", "/edge", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, "app.example.com") || !strings.Contains(page, "myapp-web:8080") {
		t.Error("route not listed on the edge page")
	}
}

// A control-plane upstream is rejected at the route store (422), never persisted.
func TestEdgeRouteRejectsControlPlaneUpstream(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	for _, up := range []string{"127.0.0.1:9000", "edge:2019", "host:2375"} {
		f := url.Values{"hostname": {"x.example.com"}, "upstream": {up}, "upstream_scheme": {"http"}, "enabled": {"on"}, "csrf_token": {csrf.Value}}
		if resp := e.req(t, "POST", "/edge/routes", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("upstream %q = %d, want 422", up, resp.StatusCode)
		}
	}
	if rts, _ := e.srv.edgeRoutes.List(); len(rts) != 0 {
		t.Error("an unsafe route must never be persisted")
	}
}

// A wildcard/non-FQDN hostname (catch-all) is rejected.
func TestEdgeRouteRejectsWildcard(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	f := url.Values{"hostname": {"*.example.com"}, "upstream": {"web:80"}, "upstream_scheme": {"http"}, "enabled": {"on"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/edge/routes", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("wildcard host = %d, want 422", resp.StatusCode)
	}
}
