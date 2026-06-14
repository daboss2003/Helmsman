// Package edge owns the managed edge (plan §6): Helmsman supervises a child Caddy
// and is the SINGLE SOURCE OF TRUTH for its config via the admin API. The config
// is NEVER stored as text — this package RENDERS the whole Caddy JSON document
// from typed structs (SBD-7), baking in the secure-by-default baseline (§6.1):
// admin on loopback/unix only, no admin vhost unless explicitly configured (and
// then IP-allowlist-first), ACME pinned to one CA for only the configured app
// hostnames, no wildcard/catch-all proxy, and NO upstream may target a
// control-plane port (struct-validated AND re-checked at render).
package edge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// controlPorts are Helmsman's own ports; an edge upstream may NEVER target them
// (SBD-4). The admin-vhost→:9000 route is injected by Helmsman, not via this set.
var controlPorts = map[string]bool{"9000": true, "2019": true, "2375": true}

var (
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)
	upHostRe   = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
)

// Route is one operator-desired edge vhost (Layer 1, from app_routes).
type Route struct {
	id              int64 // row id (RouteStore-managed)
	AppID           string
	Hostname        string
	Upstream        string // host:port of the app endpoint
	UpstreamScheme  string // http | https
	PathPrefix      string
	RedirectHTTP    bool
	HSTS            bool
	SecurityHeaders bool
	Enabled         bool
}

// BaseConfig is Layer 0 — the protected base, injected from typed config (never
// operator text).
type BaseConfig struct {
	AdminListen    string   // "unix//run/helmsman/caddy-admin.sock" or "127.0.0.1:2019"
	ACMEEmail      string   // pinned ACME contact
	ACMECA         string   // pinned single issuer directory URL
	AdminHostname  string   // "" = NO admin vhost (reach the UI via SSH tunnel)
	AdminAllowlist []string // IP-allowlist CIDRs for the admin vhost (typed, mandatory if AdminHostname set)
	AdminUpstream  string   // the ONLY loopback upstream, identity-pinned (e.g. 127.0.0.1:9000)
}

// ValidateRoute enforces every route-level safety rule (SBD-4). Returns the first
// violation. A wildcard/catch-all hostname is rejected; an upstream targeting a
// control-plane port or a loopback/link-local literal IP is rejected.
func ValidateRoute(r Route) error {
	h := strings.ToLower(strings.TrimSpace(r.Hostname))
	if len(h) > 253 || !hostnameRe.MatchString(h) {
		return fmt.Errorf("hostname %q is invalid (must be a fully-qualified DNS name, no wildcards)", r.Hostname)
	}
	if r.UpstreamScheme != "http" && r.UpstreamScheme != "https" {
		return fmt.Errorf("upstream_scheme must be http or https")
	}
	if err := validateUpstream(r.Upstream); err != nil {
		return err
	}
	if r.PathPrefix != "" && (!pathRe.MatchString(r.PathPrefix) || strings.Contains(r.PathPrefix, "..")) {
		return fmt.Errorf("path_prefix %q is invalid", r.PathPrefix)
	}
	return nil
}

// validateUpstream rejects a control-plane port and any loopback/link-local
// literal-IP target (the admin upstream is injected separately, never here).
func validateUpstream(up string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(up))
	if err != nil {
		return fmt.Errorf("upstream %q must be host:port", up)
	}
	if controlPorts[port] {
		return fmt.Errorf("upstream %q targets a reserved control-plane port", up)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("upstream %q has an invalid port", up)
	}
	if host == "" || !upHostRe.MatchString(host) {
		return fmt.Errorf("upstream host %q is invalid", up)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("upstream %q targets a loopback/link-local address (control-plane reachable)", up)
		}
	}
	return nil
}

// Render builds the whole Caddy JSON document from the base + the enabled routes.
// It re-validates every route (defense in depth) and FAILS if any is unsafe — a
// bad route can never become a partially-applied config.
func Render(base BaseConfig, routes []Route) ([]byte, error) {
	admin := &caddyAdmin{Listen: base.AdminListen, EnforceOrigin: true, Origins: []string{"127.0.0.1", "::1", "localhost"}}

	var httpRoutes []caddyRoute
	var subjects []string
	seen := map[string]bool{}

	// SBD-1: the admin vhost is rendered ONLY if explicitly configured, with the
	// IP allowlist as the FIRST matcher, upstream pinned to the loopback admin.
	if base.AdminHostname != "" {
		ah := strings.ToLower(strings.TrimSpace(base.AdminHostname))
		if !hostnameRe.MatchString(ah) {
			return nil, fmt.Errorf("admin.hostname %q is invalid", base.AdminHostname)
		}
		if len(base.AdminAllowlist) == 0 {
			return nil, fmt.Errorf("admin vhost requires a non-empty IP allowlist (SBD-1)")
		}
		if base.AdminUpstream == "" {
			return nil, fmt.Errorf("admin vhost requires the pinned admin upstream")
		}
		httpRoutes = append(httpRoutes, caddyRoute{
			Match: []caddyMatch{{Host: []string{ah}, RemoteIP: &caddyRemoteIP{Ranges: base.AdminAllowlist}}},
			Handle: []caddyHandler{{
				Handler:   "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: base.AdminUpstream}},
				Headers:   xffOverwrite(),
			}},
			Terminal: true,
		})
		subjects = append(subjects, ah)
		seen[ah] = true
	}

	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		if err := ValidateRoute(r); err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Hostname, err)
		}
		h := strings.ToLower(strings.TrimSpace(r.Hostname))
		if h == strings.ToLower(strings.TrimSpace(base.AdminHostname)) {
			return nil, fmt.Errorf("route %q collides with the admin vhost", r.Hostname)
		}
		match := caddyMatch{Host: []string{h}}
		if r.PathPrefix != "" {
			match.Path = []string{strings.TrimRight(r.PathPrefix, "/") + "/*"}
		}
		var handlers []caddyHandler
		if r.SecurityHeaders || r.HSTS {
			handlers = append(handlers, caddyHandler{Handler: "headers", Response: &caddyHeaderOps{Set: securityHeaderBundle(r)}})
		}
		rp := caddyHandler{
			Handler:   "reverse_proxy",
			Upstreams: []caddyUpstream{{Dial: r.Upstream}},
			Headers:   xffOverwrite(),
		}
		if r.UpstreamScheme == "https" {
			rp.Transport = map[string]any{"protocol": "http", "tls": map[string]any{}}
		}
		handlers = append(handlers, rp)
		httpRoutes = append(httpRoutes, caddyRoute{Match: []caddyMatch{match}, Handle: handlers, Terminal: true})
		if !seen[h] {
			subjects = append(subjects, h)
			seen[h] = true
		}
	}

	// SBD-4: default unmatched Host → 404 (never proxy, no catch-all).
	httpRoutes = append(httpRoutes, caddyRoute{Handle: []caddyHandler{{Handler: "static_response", StatusCode: 404}}})

	cfg := caddyConfig{
		Admin: admin,
		Apps: caddyApps{
			HTTP: caddyHTTP{Servers: map[string]caddyServer{
				"edge": {Listen: []string{":443", ":80"}, Routes: httpRoutes},
			}},
		},
	}
	// SBD-3: ACME pinned to one CA, issuing ONLY for the configured subjects;
	// on_demand omitted (off). No subjects → no automation policy (base serves
	// nothing, proxies to nothing — the safe recovery floor).
	if len(subjects) > 0 {
		cfg.Apps.TLS = &caddyTLS{Automation: caddyAutomation{Policies: []caddyTLSPolicy{{
			Subjects: subjects,
			Issuers:  []caddyIssuer{{Module: "acme", CA: base.ACMECA, Email: base.ACMEEmail}},
		}}}}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// xffOverwrite sets X-Forwarded-For to the real TCP peer (overwrite, not append),
// matching Helmsman's own XFF invariant so an app behind the edge sees the true
// client and a forged upstream XFF can't slip through.
func xffOverwrite() *caddyProxyHeaders {
	return &caddyProxyHeaders{Request: &caddyHeaderOps{Set: map[string][]string{
		"X-Forwarded-For": {"{http.request.remote.host}"},
	}}}
}

func securityHeaderBundle(r Route) map[string][]string {
	set := map[string][]string{
		"X-Content-Type-Options": {"nosniff"},
		"Referrer-Policy":        {"no-referrer"},
	}
	if r.HSTS {
		// HSTS is only ever sent on the HTTPS vhost Caddy serves for a managed host.
		set["Strict-Transport-Security"] = []string{"max-age=31536000; includeSubDomains"}
	}
	return set
}
