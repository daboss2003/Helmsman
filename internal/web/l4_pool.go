package web

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strconv"

	"github.com/daboss2003/Helmsman/internal/docker"
	"github.com/daboss2003/Helmsman/internal/l4"
)

// DiscoverL4Pools resolves each L4 route to the live container endpoints (ip:port) of
// its backing service's replicas, so the host nginx dials bridge IPs directly and never
// has to resolve a compose service name (which it can't — and one unresolvable upstream
// makes `nginx -t` reject the WHOLE config). Counterpart of DiscoverEdgePools, keyed by
// l4.PoolKey(route). Fail-safe: a nil docker client / discovery error / a service with no
// running replica yields no pool for that route — the renderer then SKIPS it (rather than
// emitting an unresolvable name that takes every listener down). An L4 upstream is a raw
// TCP/UDP service:port, so there is no https case to skip.
//
// It is a free function (not a *Server method like DiscoverEdgePools) because the L4
// reconcile closure is built BEFORE the *Server — web.New needs that closure — so it has
// only the docker client to work with, not a *Server.
func DiscoverL4Pools(ctx context.Context, dc *docker.Client, log *slog.Logger, routes []l4.Route) map[string][]string {
	if len(routes) == 0 {
		return nil
	}
	ipsByService := ReplicaIPsByService(ctx, dc, log)
	if len(ipsByService) == 0 {
		return nil
	}
	out := map[string][]string{}
	for _, rt := range routes {
		if rt.AppID == "" {
			continue
		}
		key := l4.PoolKey(rt)
		if _, done := out[key]; done {
			continue
		}
		ips := ipsByService[svcKey(rt.AppID, rt.Service)]
		if len(ips) == 0 {
			continue
		}
		eps := make([]string, 0, len(ips))
		seen := map[string]bool{}
		for _, ip := range ips {
			ep := net.JoinHostPort(ip, strconv.Itoa(rt.Port))
			if !seen[ep] {
				seen[ep] = true
				eps = append(eps, ep)
			}
		}
		sort.Strings(eps) // deterministic → stable replica set re-renders byte-identical
		out[key] = eps
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
