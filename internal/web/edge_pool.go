package web

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/daboss2003/Helmsman/internal/edge"
)

// DiscoverEdgePools resolves each route to the live container endpoints (ip:port) of
// its backing service's replicas, for the managed edge to dial directly. It is the
// wiring the auto-scaler's edge pool was designed for (edge.Reconciler.SetPoolDiscoverer):
// Helmsman lists the running replicas ONCE via the READ-ONLY socket-proxy, takes each
// one's docker-bridge IP (the host edge routes to the bridge directly, so it never needs
// to resolve the compose service name), and dials that pool with least-conn + health.
//
// The result is keyed by edge.PoolKey(route). It is fail-safe: a nil docker client or a
// discovery error returns nil (every route keeps its single service-name dial), and a
// route is simply omitted when it has no routable replica IP. It NEVER returns a
// poisoned endpoint — loopback/link-local IPs are filtered here, https upstreams are
// skipped (a bare-IP dial breaks their TLS verification), and edge.Render re-validates
// every member as the hard SBD-4 backstop.
func (s *Server) DiscoverEdgePools(ctx context.Context, routes []edge.Route) map[string][]string {
	if s.docker == nil || len(routes) == 0 {
		return nil
	}
	cs, err := s.docker.ListContainers(ctx, false) // running only
	if err != nil {
		if s.log != nil {
			s.log.Debug("edge pool discovery failed; keeping single dials", "err", err)
		}
		return nil
	}
	// Index one routable bridge IP per RUNNING replica, grouped by (project, service).
	// IPs() is sorted by network name, so the choice is stable for a multi-homed replica
	// (it's reachable on any of its bridges from the host, so only stability matters).
	ipsByService := map[string][]string{}
	for _, c := range cs {
		if !strings.EqualFold(c.State, "running") {
			continue
		}
		proj, svc := c.Project(), c.Service()
		if proj == "" || svc == "" {
			continue
		}
		for _, ip := range c.IPs() {
			if routableUpstreamIP(ip) {
				ipsByService[proj+"\x00"+svc] = append(ipsByService[proj+"\x00"+svc], ip)
				break
			}
		}
	}

	out := map[string][]string{}
	for _, rt := range routes {
		if !rt.Enabled || rt.AppID == "" {
			continue
		}
		// An https upstream is dialed with TLS verification against the dial host; a bare
		// IP would break SNI/cert verification (the upstream cert is for the service name,
		// not the IP), so keep https routes on their service-name dial. HTTP upstreams —
		// the common case, since the edge terminates public TLS — get the discovered pool.
		if strings.EqualFold(rt.UpstreamScheme, "https") {
			continue
		}
		service, port, ok := parseUpstream(rt.Upstream)
		if !ok {
			continue
		}
		key := edge.PoolKey(rt)
		if _, done := out[key]; done {
			continue // routes sharing an upstream share a pool — compute once
		}
		ips := ipsByService[rt.AppID+"\x00"+service]
		if len(ips) == 0 {
			continue
		}
		eps := make([]string, 0, len(ips))
		seen := map[string]bool{}
		for _, ip := range ips {
			ep := net.JoinHostPort(ip, strconv.Itoa(port))
			if !seen[ep] {
				seen[ep] = true
				eps = append(eps, ep)
			}
		}
		sort.Strings(eps) // deterministic → a stable replica set re-renders byte-identical
		out[key] = eps
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// routableUpstreamIP reports whether ip is a plausible app-container address — a
// non-loopback, non-link-local, non-unspecified literal. This pre-filters discovery
// so one pathological IP can't fail the whole edge render; edge.ValidateRoute is the
// authoritative control-plane/loopback backstop applied to every dial regardless.
func routableUpstreamIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return true
}
