package web

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/daboss2003/mooring/internal/edge"
)

// DiscoverEdgePools resolves each route to the live container endpoints (ip:port) of
// its backing service's replicas, for the managed edge to dial directly. It is the
// wiring the auto-scaler's edge pool was designed for (edge.Reconciler.SetPoolDiscoverer):
// it takes each running replica's docker-bridge IP (the host edge routes to the bridge
// directly, so it never resolves the compose service name) and dials that pool with
// least-conn + health.
//
// The result is keyed by edge.PoolKey(route). It is fail-safe: a nil docker client or a
// discovery error returns nil (every route keeps its single service-name dial), and a
// route is simply omitted when it has no routable replica IP. It NEVER returns a
// poisoned endpoint — loopback/link-local IPs are filtered in discovery, https upstreams
// are skipped (a bare-IP dial breaks their TLS verification), and edge.Render
// re-validates every member as the hard SBD-4 backstop.
func (s *Server) DiscoverEdgePools(ctx context.Context, routes []edge.Route) map[string][]string {
	if len(routes) == 0 {
		return nil
	}
	ipsByService := s.replicaIPsByService(ctx)
	if len(ipsByService) == 0 {
		return nil
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
		ips := ipsByService[svcKey(rt.AppID, service)]
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
