package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
)

// containersJSON is a /containers/json fixture exercising every discovery filter:
// running shop/web replicas (kept), a stopped one + wrong service + wrong project +
// a loopback IP + an empty IP (all dropped).
const containersJSON = `[
 {"Id":"1","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.6"}}}},
 {"Id":"2","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.5"}}}},
 {"Id":"3","State":"exited","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.9"}}}},
 {"Id":"4","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"172.18.0.10"}}}},
 {"Id":"5","State":"running","Labels":{"com.docker.compose.project":"other","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"other_default":{"IPAddress":"172.20.0.2"}}}},
 {"Id":"6","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":"127.0.0.1"}}}},
 {"Id":"7","State":"running","Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"},
  "NetworkSettings":{"Networks":{"shop_default":{"IPAddress":""}}}}
]`

func dockerServingContainers(t *testing.T, body string) *docker.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return docker.New(strings.TrimPrefix(srv.URL, "http://"))
}

func quietWebLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// DiscoverEdgePools keeps only RUNNING replicas of each route's exact (project, service),
// takes one routable bridge IP per replica, attaches the route's port, drops loopback/
// empty IPs, and returns the set sorted (deterministic → stable render), keyed by PoolKey.
func TestDiscoverEdgePools(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	rt := edge.Route{AppID: "shop", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
	got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt})
	want := map[string][]string{edge.PoolKey(rt): {"172.18.0.5:8080", "172.18.0.6:8080"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DiscoverEdgePools = %v, want %v", got, want)
	}
}

// An https upstream is omitted (kept on its service-name dial) — a bare-IP dial breaks
// the upstream TLS cert verification. Regression guard for the scheme check.
func TestDiscoverEdgePoolsSkipsHTTPS(t *testing.T) {
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog()}
	for _, scheme := range []string{"https", "HTTPS"} {
		rt := edge.Route{AppID: "shop", Upstream: "web:8080", UpstreamScheme: scheme, Enabled: true}
		if got := s.DiscoverEdgePools(context.Background(), []edge.Route{rt}); got != nil {
			t.Errorf("scheme %q: expected nil (https keeps the service-name dial), got %v", scheme, got)
		}
	}
}

// Fail-safe: a nil docker client, a route with a bad/absent upstream or app id, or no
// matching replicas all yield no pool, so the caller keeps the service-name dial.
func TestDiscoverEdgePoolsFailSafe(t *testing.T) {
	dc := dockerServingContainers(t, containersJSON)
	cases := []struct {
		name string
		s    *Server
		rt   edge.Route
	}{
		{"nil docker", &Server{docker: nil, log: quietWebLog()}, edge.Route{AppID: "shop", Upstream: "web:8080", Enabled: true}},
		{"bad upstream", &Server{docker: dc, log: quietWebLog()}, edge.Route{AppID: "shop", Upstream: "web", Enabled: true}},
		{"no app id", &Server{docker: dc, log: quietWebLog()}, edge.Route{AppID: "", Upstream: "web:8080", Enabled: true}},
		{"no matching replicas", &Server{docker: dc, log: quietWebLog()}, edge.Route{AppID: "shop", Upstream: "ghost:8080", Enabled: true}},
		{"disabled route", &Server{docker: dc, log: quietWebLog()}, edge.Route{AppID: "shop", Upstream: "web:8080", Enabled: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.DiscoverEdgePools(context.Background(), []edge.Route{tc.rt}); got != nil {
				t.Errorf("expected nil (single-dial fallback), got %v", got)
			}
		})
	}
}
