package edge

import (
	"fmt"
	"strings"
	"testing"
)

// A clean overlay (an extra vhost on an operator-owned host proxying to an app
// container, plus a security-headers handler) parses and contributes its hostname
// to TLS automation.
func TestOverlayHappyPath(t *testing.T) {
	raw := []byte(`[
	  {"match":[{"host":["extra.example.com"]}],
	   "handle":[
	     {"handler":"headers","response":{"set":{"X-Frame-Options":["DENY"]}}},
	     {"handler":"reverse_proxy","upstreams":[{"dial":"extra-web:8080"}]}
	   ]}
	]`)
	routes, hosts, err := ParseOverlay(raw, map[string]bool{"app.example.com": true})
	if err != nil {
		t.Fatalf("clean overlay rejected: %v", err)
	}
	if len(routes) != 1 || !routes[0].Terminal {
		t.Fatalf("want 1 terminal route, got %+v", routes)
	}
	if len(hosts) != 1 || hosts[0] != "extra.example.com" {
		t.Errorf("overlay host not surfaced for TLS: %v", hosts)
	}
}

// An empty / whitespace overlay is valid and contributes nothing.
func TestOverlayEmpty(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n\t", "[]"} {
		routes, hosts, err := ParseOverlay([]byte(raw), nil)
		if err != nil || routes != nil || hosts != nil {
			t.Errorf("empty overlay %q should be a no-op, got routes=%v hosts=%v err=%v", raw, routes, hosts, err)
		}
	}
}

// DisallowUnknownFields makes exotic Caddy impossible to EXPRESS — admin/tls/pki
// blocks, file_server roots, import, header add/delete are not fields of the typed
// model, so they're rejected at decode.
func TestOverlayRejectsUnmodelledConstructs(t *testing.T) {
	cases := map[string]string{
		"admin block":      `[{"admin":{"listen":":2019"}}]`,
		"tls automation":   `[{"match":[{"host":["x.example.com"]}],"tls":{"automation":{}},"handle":[{"handler":"static_response"}]}]`,
		"file_server root": `[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"file_server","root":"/etc"}]}]`,
		"header add":       `[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"headers","response":{"add":{"X":["y"]}}}]}]`,
		"not an array":     `{"match":[{"host":["x.example.com"]}]}`,
		"trailing data":    `[] junk`,
	}
	for name, raw := range cases {
		if _, _, err := ParseOverlay([]byte(raw), nil); err == nil {
			t.Errorf("%s: should be rejected by the typed decode", name)
		}
	}
}

// The conflict gate: an overlay host equal to a managed (Layer 0/1) vhost is
// rejected — Layer 2 may add, never redefine/shadow. Case-insensitive.
func TestOverlayConflictGate(t *testing.T) {
	managed := map[string]bool{"app.example.com": true, "admin.example.com": true}
	for _, host := range []string{"app.example.com", "APP.example.com", "admin.example.com"} {
		raw := []byte(`[{"match":[{"host":["` + host + `"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"web:80"}]}]}]`)
		if _, _, err := ParseOverlay(raw, managed); err == nil {
			t.Errorf("overlay host %q shadows a managed vhost and must be rejected", host)
		}
	}
}

// The control-plane reject tier: handler names that name a binary / read the FS /
// run a template are rejected even though the typed decode admits the bare name.
func TestOverlayRejectsDangerousHandlers(t *testing.T) {
	for _, h := range []string{"exec", "templates", "php_fastcgi", "file_server", "subroute"} {
		raw := []byte(`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"` + h + `"}]}]`)
		if _, _, err := ParseOverlay(raw, nil); err == nil {
			t.Errorf("handler %q must be rejected (not in the overlay allowlist)", h)
		}
	}
}

// SBD-4 in the overlay: an upstream to a control-plane port, a loopback literal/
// hostname, or a placeholder dial is rejected.
func TestOverlayRejectsUnsafeUpstreams(t *testing.T) {
	for _, up := range []string{"127.0.0.1:9000", "10.0.0.1:2019", "host:2375", "localhost:8080", "127.0.0.1:8080", "169.254.169.254:80", "{env.SECRET}:80", "{$BACKEND}:80"} {
		raw := []byte(`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"` + up + `"}]}]}]`)
		if _, _, err := ParseOverlay(raw, nil); err == nil {
			t.Errorf("unsafe overlay upstream %q must be rejected", up)
		}
	}
}

// An overlay may not set the XFF/forwarding headers Layer 0 owns (it could forge
// the client IP an app trusts) — on either a headers handler or a reverse_proxy.
func TestOverlayRejectsXFFForge(t *testing.T) {
	cases := []string{
		`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"headers","response":{"set":{"X-Forwarded-For":["1.2.3.4"]}}}]}]`,
		`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"web:80"}],"headers":{"request":{"set":{"X-Real-IP":["1.2.3.4"]}}}}]}]`,
		`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"headers","response":{"set":{"forwarded":["for=1.2.3.4"]}}}]}]`,
		// Defense in depth: a header op placed on a handler type that "shouldn't"
		// carry it (proxy-style "headers" block on a "headers" handler, or on a
		// static_response) is still caught — the check is placement-independent.
		`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"headers","headers":{"request":{"set":{"X-Forwarded-For":["1.2.3.4"]}}}}]}]`,
		`[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"static_response","status_code":200,"headers":{"request":{"set":{"X-Real-IP":["9.9.9.9"]}}}}]}]`,
	}
	for i, raw := range cases {
		if _, _, err := ParseOverlay([]byte(raw), nil); err == nil {
			t.Errorf("case %d: an overlay setting an XFF-owned header must be rejected", i)
		}
	}
}

// A catch-all (matcher-less, or a matcher with no host) is rejected — an overlay
// must scope to operator-owned hostnames.
func TestOverlayRejectsCatchAll(t *testing.T) {
	cases := []string{
		`[{"handle":[{"handler":"static_response","status_code":200}]}]`,
		`[{"match":[{"path":["/x"]}],"handle":[{"handler":"static_response","status_code":200}]}]`,
		`[{"match":[{"host":["*.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}]`,
		`[{"match":[{"host":["nodot"]}],"handle":[{"handler":"static_response","status_code":200}]}]`,
	}
	for i, raw := range cases {
		if _, _, err := ParseOverlay([]byte(raw), nil); err == nil {
			t.Errorf("case %d: a catch-all/invalid-host overlay route must be rejected", i)
		}
	}
}

// A custom reverse_proxy transport (a re-pointed dialer / weakened tls) is
// rejected; the default and an empty-tls https upstream are allowed.
func TestOverlayTransportGate(t *testing.T) {
	bad := `[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"web:443"}],"transport":{"protocol":"http","tls":{"insecure_skip_verify":true}}}]}]`
	if _, _, err := ParseOverlay([]byte(bad), nil); err == nil {
		t.Error("a transport with a non-empty tls block must be rejected")
	}
	ok := `[{"match":[{"host":["x.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"web:443"}],"transport":{"protocol":"http","tls":{}}}]}]`
	if _, _, err := ParseOverlay([]byte(ok), nil); err != nil {
		t.Errorf("an https upstream (empty tls block) should be allowed: %v", err)
	}
}

// Structural caps bound the synchronous linter + the pushed config size: too many
// routes, or too many hosts in a single matcher, is rejected.
func TestOverlayStructuralCaps(t *testing.T) {
	// > maxOverlayRoutes routes.
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < maxOverlayRoutes+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"match":[{"host":["h%d.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}`, i)
	}
	b.WriteString("]")
	if _, _, err := ParseOverlay([]byte(b.String()), nil); err == nil {
		t.Error("an overlay exceeding maxOverlayRoutes must be rejected")
	}

	// > maxHostsPerMatcher hosts in one matcher.
	var hb strings.Builder
	hb.WriteString(`[{"match":[{"host":[`)
	for i := 0; i < maxHostsPerMatcher+1; i++ {
		if i > 0 {
			hb.WriteString(",")
		}
		fmt.Fprintf(&hb, `"h%d.example.com"`, i)
	}
	hb.WriteString(`]}],"handle":[{"handler":"static_response","status_code":200}]}]`)
	if _, _, err := ParseOverlay([]byte(hb.String()), nil); err == nil {
		t.Error("an overlay matcher exceeding maxHostsPerMatcher must be rejected")
	}
}

// RenderComposite splices a valid overlay after the managed routes and before the
// 404, and adds the overlay host to TLS automation.
func TestRenderCompositeIntegratesOverlay(t *testing.T) {
	overlay := []byte(`[{"match":[{"host":["extra.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"extra-web:8080"}]}]}]`)
	out, err := RenderComposite(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true},
	}, overlay)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"app.example.com", "extra.example.com", "extra-web:8080"} {
		if !strings.Contains(s, want) {
			t.Errorf("composite missing %q:\n%s", want, s)
		}
	}
	// The managed route precedes the overlay route, which precedes the 404 floor.
	iApp := strings.Index(s, "app.example.com")
	iExtra := strings.Index(s, "extra.example.com")
	i404 := strings.LastIndex(s, "static_response")
	if !(iApp < iExtra && iExtra < i404) {
		t.Errorf("route order wrong: app=%d extra=%d 404=%d", iApp, iExtra, i404)
	}
}

// A composite render fails closed if the overlay shadows a managed app vhost — the
// conflict gate runs against the LIVE managed set, not a snapshot.
func TestRenderCompositeOverlayCannotShadowApp(t *testing.T) {
	overlay := []byte(`[{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"evil:80"}]}]}]`)
	_, err := RenderComposite(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true},
	}, overlay)
	if err == nil {
		t.Error("an overlay shadowing a managed app vhost must fail the composite render")
	}
}
