package edge

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseCfg() BaseConfig {
	return BaseConfig{
		AdminListen: "unix//run/helmsman/caddy-admin.sock",
		ACMEEmail:   "ops@example.com", ACMECA: "https://acme.example/directory",
	}
}

func mustRender(t *testing.T, base BaseConfig, routes []Route) map[string]any {
	t.Helper()
	out, err := Render(base, routes, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("render produced invalid JSON: %v", err)
	}
	return doc
}

// A valid route renders an HTTPS vhost with a pinned ACME issuer + the catch-all
// 404, and admin stays on the unix socket with enforce_origin.
func TestRenderHappyPath(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "shop-web:8080", UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"app.example.com", "shop-web:8080", "acme", "https://acme.example/directory", "enforce_origin", "static_response"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered config missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "on_demand") {
		t.Error("on-demand TLS must be off by default (SBD-3)")
	}
}

// SBD-4: an upstream targeting a control-plane port (or loopback) is rejected.
func TestRenderRejectsControlPlaneUpstream(t *testing.T) {
	for _, up := range []string{"127.0.0.1:9000", "10.0.0.5:2019", "host:2375", "127.0.0.1:8080", "169.254.169.254:80"} {
		_, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil)
		if err == nil {
			t.Errorf("upstream %q should be rejected", up)
		}
	}
}

// SBD-4: an upstream HOSTNAME that resolves to loopback (localhost family) is
// rejected at validation, not just literal loopback IPs.
func TestRenderRejectsLoopbackHostnames(t *testing.T) {
	for _, up := range []string{"localhost:8080", "foo.localhost:8080", "ip6-localhost:8080", "LOCALHOST:8080"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			t.Errorf("loopback hostname upstream %q should be rejected", up)
		}
	}
	// A normal container-name upstream is still allowed.
	if _, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: "myapp-web:8080", UpstreamScheme: "http", Enabled: true}}, nil); err != nil {
		t.Errorf("a container-name upstream should be allowed: %v", err)
	}
}

// SBD-4: a wildcard / non-FQDN hostname (catch-all) is rejected.
func TestRenderRejectsWildcardHost(t *testing.T) {
	for _, h := range []string{"*.example.com", "*", "localhost", "no-dot", "UPPER.example.com"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: h, Upstream: "web:80", UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			// UPPER is lowercased then validated; ensure non-FQDN/wildcards fail.
			if h != "UPPER.example.com" {
				t.Errorf("hostname %q should be rejected", h)
			}
		}
	}
}

// M14: a scaled route renders a least-conn pool with passive health checks, and
// every pool member is validated (a control-plane member is refused).
func TestRenderScaledPool(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Pool: []string{"app-web-1:8080", "app-web-2:8080", "app-web-3:8080"}, UpstreamScheme: "http", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"app-web-1:8080", "app-web-2:8080", "app-web-3:8080", "least_conn", "passive", "max_fails"} {
		if !strings.Contains(s, want) {
			t.Errorf("scaled pool render missing %q:\n%s", want, s)
		}
	}
	// A pool member targeting a control-plane port is refused (SBD-4 over the pool).
	if _, err := Render(baseCfg(), []Route{
		{Hostname: "x.example.com", Pool: []string{"app-web-1:8080", "127.0.0.1:9000"}, UpstreamScheme: "http", Enabled: true},
	}, nil); err == nil {
		t.Error("a pool member targeting a control-plane port must be refused")
	}
}

// A single-upstream route does NOT get LB/health-check blocks (no pool).
func TestRenderSingleNoPoolMachinery(t *testing.T) {
	out, _ := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}}, nil)
	if strings.Contains(string(out), "least_conn") || strings.Contains(string(out), "load_balancing") {
		t.Error("a single upstream must not render pool load-balancing machinery")
	}
}

// SBD-1: no admin vhost unless admin.hostname is set; when set it requires the IP
// allowlist as a matcher and pins the loopback admin upstream.
func TestRenderAdminVhostGating(t *testing.T) {
	// Default: no admin vhost (the host count = app subjects only).
	doc := mustRender(t, baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}})
	if strings.Contains(toJSON(doc), "9000") {
		t.Error("no admin upstream should appear without admin.hostname")
	}
	// admin.hostname without an allowlist → render error (SBD-1).
	b := baseCfg()
	b.AdminHostname = "admin.example.com"
	b.AdminUpstream = "127.0.0.1:9000"
	if _, err := Render(b, nil, nil); err == nil {
		t.Error("admin vhost without an IP allowlist must be rejected")
	}
	// With an allowlist → the admin vhost renders with the remote_ip matcher.
	b.AdminAllowlist = []string{"203.0.113.0/24"}
	out, err := Render(b, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "remote_ip") || !strings.Contains(s, "203.0.113.0/24") || !strings.Contains(s, "127.0.0.1:9000") {
		t.Errorf("admin vhost not rendered with allowlist+pinned upstream:\n%s", s)
	}
}

// An empty route set renders the safe recovery floor: no TLS automation, no
// proxy, just the 404 catch-all (SBD-8 base).
func TestRenderEmptyIsSafeFloor(t *testing.T) {
	out, err := Render(baseCfg(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "reverse_proxy") {
		t.Error("an empty config must proxy to nothing")
	}
	if strings.Contains(string(out), "acme") {
		t.Error("no ACME automation without configured hostnames")
	}
}

// XFF is overwritten to the real peer on every proxied route.
func TestRenderXFFOverwrite(t *testing.T) {
	out, _ := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}}, nil)
	if !strings.Contains(string(out), "X-Forwarded-For") || !strings.Contains(string(out), "{http.request.remote.host}") {
		t.Errorf("reverse_proxy must overwrite XFF to the real peer:\n%s", out)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// A cert-only subject is issued (ACME) but gets NO proxy route — a consumer app
// (e.g. an MQTT broker) terminates TLS itself with the synced cert.
func TestRenderCertOnlySubject(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true},
	}, []string{"mqtt.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "mqtt.example.com") {
		t.Errorf("cert-only host must be an ACME subject:\n%s", s)
	}
	// app.example.com appears in BOTH a route match and the subjects (>=2); the
	// cert-only host appears ONLY in subjects (exactly once) — proving no proxy route.
	if n := strings.Count(s, "mqtt.example.com"); n != 1 {
		t.Errorf("cert-only host must appear once (subjects only), got %d:\n%s", n, s)
	}
}
