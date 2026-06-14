package edge

// Layer 2 — the operator overlay (plan §6.2). The operator may add EXTRA vhosts /
// headers / matchers on hostnames they own. Per the read-and-render model the raw
// text is NEVER loaded verbatim: it is parsed into the SAME typed model the rest of
// this package emits, conflict-checked + linted (the control-plane reject tier),
// and re-marshalled. What Caddy runs is always Helmsman's typed render of the
// composite (Layer 0 ⊕ 1 ⊕ 2), highest layer = LOWEST authority (Layer 2 can ADD,
// never redefine/shadow Layer 0/1).
//
// The overlay is a JSON array of caddyRoute. Two structural defenses combine:
//   - DisallowUnknownFields — any construct outside the typed schema (admin, tls,
//     pki, exec/templates/file_server config keys, import, header add/delete, …) is
//     rejected because it simply isn't a field. Exotic Caddy is impossible to
//     EXPRESS, not merely linted away (the M8 generator discipline).
//   - lintOverlayRoute — the modelled-but-dangerous cases a typed decode can't stop
//     on its own: a handler NAME like "exec"/"file_server", an upstream resolving to
//     loopback/control-plane, a header op touching XFF, a host shadowing a managed
//     vhost, a placeholder dial.
//
// Constructs the typed model can't express are out of scope by design (header
// add/delete, custom matchers beyond host/path/remote_ip, non-http transports) —
// fail-closed: if you can't express it safely here, you can't ship it through the
// overlay. The Caddyfile→JSON `caddy adapt` front-end (plan §6.2 step 1, Linux/
// sandbox) feeds THIS same linter; the typed reject tier is format-independent.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// maxOverlayBytes caps the raw overlay (defence against a decode bomb; a real
// overlay is a handful of routes).
const maxOverlayBytes = 256 << 10

// overlayHandlers is the allowlist of handler modules an overlay route may use.
// Anything else (exec, file_server, templates, php_fastcgi, …) is a control-plane
// reject — it can name a binary, read the filesystem, or execute a template.
var overlayHandlers = map[string]bool{"reverse_proxy": true, "headers": true, "static_response": true}

// xffOwned are the request/forwarding headers Layer 0 owns (overwrite-to-real-peer);
// an overlay must never set them (it could forge the client IP an app trusts).
var xffOwned = map[string]bool{"x-forwarded-for": true, "x-real-ip": true, "forwarded": true}

// ParseOverlay decodes + lints the operator overlay against the managed hostnames
// (Layer 0 admin host + Layer 1 app vhosts, lowercased). It returns the typed
// overlay routes to splice into the composite and the overlay hostnames to add to
// TLS automation. An empty overlay is valid (no routes). ANY violation fails the
// whole overlay — a partially-valid overlay is never applied.
func ParseOverlay(raw []byte, managed map[string]bool) ([]caddyRoute, []string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, nil
	}
	if len(raw) > maxOverlayBytes {
		return nil, nil, fmt.Errorf("overlay too large (%d bytes, max %d)", len(raw), maxOverlayBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var routes []caddyRoute
	if err := dec.Decode(&routes); err != nil {
		return nil, nil, fmt.Errorf("overlay must be a JSON array of routes (only modelled fields allowed): %w", err)
	}
	if dec.More() {
		return nil, nil, fmt.Errorf("overlay has trailing data after the routes array")
	}
	if len(routes) == 0 {
		return nil, nil, nil
	}

	var hosts []string
	seen := map[string]bool{}
	for i := range routes {
		rhosts, err := lintOverlayRoute(&routes[i], managed)
		if err != nil {
			return nil, nil, fmt.Errorf("overlay route #%d: %w", i+1, err)
		}
		// Force terminal: each overlay route is a self-contained vhost and must not
		// fall through into the managed routes or the 404 floor.
		routes[i].Terminal = true
		for _, h := range rhosts {
			if !seen[h] {
				hosts = append(hosts, h)
				seen[h] = true
			}
		}
	}
	return routes, hosts, nil
}

// lintOverlayRoute enforces the control-plane reject tier on one decoded route and
// returns its (validated, lowercased) hostnames.
func lintOverlayRoute(r *caddyRoute, managed map[string]bool) ([]string, error) {
	// A route MUST scope itself to operator-owned hostnames — an overlay route with
	// no host matcher is a catch-all and could shadow everything (SBD-4).
	if len(r.Match) == 0 {
		return nil, fmt.Errorf("must have a host matcher (a matcher-less route is a catch-all)")
	}
	var hosts []string
	for _, m := range r.Match {
		if len(m.Host) == 0 {
			return nil, fmt.Errorf("every matcher must scope to a host (no catch-all)")
		}
		for _, h := range m.Host {
			lh := strings.ToLower(strings.TrimSpace(h))
			if len(lh) > 253 || !hostnameRe.MatchString(lh) {
				return nil, fmt.Errorf("host %q is invalid (must be a fully-qualified DNS name, no wildcards)", h)
			}
			if managed[lh] {
				// The conflict gate: Layer 2 can never redefine/shadow a Layer 0/1
				// hostname. (Managed and overlay hosts are both wildcard-free FQDNs,
				// so an exact lowercase match is the full overlap check here; wildcard
				// overlap simulation is only needed once wildcards are permitted.)
				return nil, fmt.Errorf("host %q shadows a Helmsman-managed vhost (Layer 2 may add, never redefine)", h)
			}
			hosts = append(hosts, lh)
		}
		if err := validateMatchExtras(m); err != nil {
			return nil, err
		}
	}
	if len(r.Handle) == 0 {
		return nil, fmt.Errorf("must have at least one handler")
	}
	for _, h := range r.Handle {
		if err := lintOverlayHandler(h); err != nil {
			return nil, err
		}
	}
	return hosts, nil
}

// validateMatchExtras validates the non-host matcher fields an overlay may set.
func validateMatchExtras(m caddyMatch) error {
	for _, p := range m.Path {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			return fmt.Errorf("path matcher %q is invalid", p)
		}
	}
	if m.RemoteIP != nil {
		for _, cidr := range m.RemoteIP.Ranges {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				if _, err2 := netip.ParseAddr(cidr); err2 != nil {
					return fmt.Errorf("remote_ip range %q is not a valid CIDR or IP", cidr)
				}
			}
		}
	}
	return nil
}

// lintOverlayHandler enforces the handler-level reject tier.
func lintOverlayHandler(h caddyHandler) error {
	if !overlayHandlers[h.Handler] {
		return fmt.Errorf("handler %q is not permitted in an overlay (only reverse_proxy/headers/static_response)", h.Handler)
	}
	switch h.Handler {
	case "reverse_proxy":
		if len(h.Upstreams) == 0 {
			return fmt.Errorf("reverse_proxy needs at least one upstream")
		}
		for _, up := range h.Upstreams {
			// validateUpstream rejects control-plane ports, loopback/link-local
			// literals, loopback hostnames, and (via the host charset) any
			// {env.*}/{$…} placeholder dial.
			if err := validateUpstream(up.Dial); err != nil {
				return err
			}
		}
		if !transportOK(h.Transport) {
			return fmt.Errorf("reverse_proxy transport is not permitted (only the default http or http+empty-tls)")
		}
		if h.Headers != nil {
			if headerOpsTouchXFF(h.Headers.Request) || headerOpsTouchXFF(h.Headers.Response) {
				return fmt.Errorf("an overlay may not set X-Forwarded-For/X-Real-IP/Forwarded (Layer 0 owns them)")
			}
		}
	case "headers":
		if headerOpsTouchXFF(h.Response) {
			return fmt.Errorf("an overlay may not set X-Forwarded-For/X-Real-IP/Forwarded (Layer 0 owns them)")
		}
	case "static_response":
		if h.StatusCode != 0 && (h.StatusCode < 100 || h.StatusCode > 599) {
			return fmt.Errorf("static_response status %d is invalid", h.StatusCode)
		}
	}
	return nil
}

// transportOK permits only the default http transport (nil) or the http transport
// with an empty tls block (an https upstream) — never a custom dialer/tls config
// that could re-point or weaken the connection.
func transportOK(t map[string]any) bool {
	if t == nil {
		return true
	}
	if proto, ok := t["protocol"].(string); !ok || proto != "http" {
		return false
	}
	for k := range t {
		if k != "protocol" && k != "tls" {
			return false
		}
	}
	if tls, ok := t["tls"]; ok {
		m, ok := tls.(map[string]any)
		if !ok || len(m) != 0 {
			return false
		}
	}
	return true
}

// headerOpsTouchXFF reports whether a header-set op writes a Layer-0-owned header.
func headerOpsTouchXFF(h *caddyHeaderOps) bool {
	if h == nil {
		return false
	}
	for k := range h.Set {
		if xffOwned[strings.ToLower(k)] {
			return true
		}
	}
	return false
}
