package edge

import (
	"encoding/json"
	"strings"
	"testing"
)

// Layer A of the §15 gate: the Secure-by-Default Baseline (SBD-1..8) must hold on a
// FRESH install with zero operator config. The per-invariant behaviours are tested
// in detail across render_test.go / admin_test.go / routestore_test.go; this file is
// the single consolidated "shippability bar" that asserts the fresh-install posture
// in one place, so the gate is legible and a regression in the default is loud.
//
// "Fresh install" = the typed base config with NO routes and NO admin vhost — what
// every install runs before the operator adds anything.

func freshInstall(t *testing.T) (string, map[string]any) {
	t.Helper()
	out, err := Render(baseCfg(), nil, nil)
	if err != nil {
		t.Fatalf("fresh-install render failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("fresh-install render is not valid JSON: %v", err)
	}
	return string(out), doc
}

// SBD-1: no admin vhost on a fresh install; admin UI is reached via SSH tunnel. The
// admin upstream :9000 must not appear anywhere in the rendered edge.
func TestLayerA_SBD1_NoAdminVhostByDefault(t *testing.T) {
	s, _ := freshInstall(t)
	if strings.Contains(s, "9000") {
		t.Error("SBD-1: a fresh install must render NO admin vhost / :9000 upstream")
	}
	// And an admin vhost without an allowlist is refused (the allowlist can't be omitted).
	b := baseCfg()
	b.AdminHostname = "admin.example.com"
	b.AdminUpstream = "127.0.0.1:9000"
	if _, err := Render(b, nil, nil); err == nil {
		t.Error("SBD-1: an admin vhost without an IP allowlist must be refused")
	}
}

// SBD-2: the Caddy admin API binds the unix socket / loopback with enforce_origin,
// never a routable address.
func TestLayerA_SBD2_AdminAPINotPublic(t *testing.T) {
	s, doc := freshInstall(t)
	admin, ok := doc["admin"].(map[string]any)
	if !ok {
		t.Fatal("SBD-2: no admin block rendered")
	}
	listen, _ := admin["listen"].(string)
	if !strings.HasPrefix(listen, "unix/") && !strings.HasPrefix(listen, "127.0.0.1:") {
		t.Errorf("SBD-2: admin.listen %q is not unix-socket/loopback", listen)
	}
	if eo, _ := admin["enforce_origin"].(bool); !eo {
		t.Error("SBD-2: admin.enforce_origin must be true")
	}
	if !strings.Contains(s, "enforce_origin") {
		t.Error("SBD-2: enforce_origin missing from render")
	}
}

// SBD-3: on-demand TLS is off on a fresh install.
func TestLayerA_SBD3_OnDemandOff(t *testing.T) {
	s, _ := freshInstall(t)
	if strings.Contains(s, "on_demand") {
		t.Error("SBD-3: on-demand TLS must be absent from the base config")
	}
}

// SBD-4: no proxy and no catch-all on a fresh install — unmatched Host → 404; and a
// control-plane / loopback upstream is refused even when an operator adds a route.
func TestLayerA_SBD4_NoCatchAllNoControlPlaneUpstream(t *testing.T) {
	s, _ := freshInstall(t)
	if strings.Contains(s, "reverse_proxy") {
		t.Error("SBD-4: a fresh install must proxy to nothing")
	}
	if !strings.Contains(s, "static_response") {
		t.Error("SBD-4: the unmatched-Host 404 floor must be present")
	}
	for _, up := range []string{"127.0.0.1:9000", "10.0.0.5:2019", "host:2375", "169.254.169.254:80", "localhost:8080"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			t.Errorf("SBD-4: upstream %q must be refused", up)
		}
	}
}

// SBD-6: ACME automation is pinned to the configured CA + email and ONLY emitted
// when there is a hostname to serve (no automation on the fresh, route-less floor).
func TestLayerA_SBD6_ACMEBoundedAndPinned(t *testing.T) {
	s, _ := freshInstall(t)
	if strings.Contains(s, "acme") {
		t.Error("SBD-6: no ACME automation without a configured hostname")
	}
	// With a route, ACME is pinned to exactly the configured CA + email.
	out, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := string(out)
	if !strings.Contains(r, "https://acme.example/directory") || !strings.Contains(r, "ops@example.com") {
		t.Error("SBD-6: ACME issuer must be pinned to the configured CA + email")
	}
}

// SBD-7: the config is rendered ENTIRELY from typed structs — there is no
// operator-supplied Caddy input path (the raw editor was removed; the operator only
// authors mooring.yaml / the typed route model). The renderer is total and
// deterministic: the same inputs render byte-identically.
func TestLayerA_SBD7_TypedRenderDeterministic(t *testing.T) {
	a, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("SBD-7: the typed renderer must be deterministic (byte-identical for identical input)")
	}
}

// SBD-8: the empty/base config is always a loadable recovery floor (it renders
// without error and is valid JSON) — the edge can always fall back to it.
func TestLayerA_SBD8_BaseIsRecoveryFloor(t *testing.T) {
	out, err := Render(baseCfg(), nil, nil)
	if err != nil {
		t.Fatalf("SBD-8: the base config must always render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("SBD-8: the base config must be valid loadable JSON: %v", err)
	}
}
