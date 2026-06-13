package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeEngine serves a minimal subset of the Engine API for client tests.
func fakeEngine(t *testing.T) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"26.1.0","ApiVersion":"1.45"}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "1" {
			t.Errorf("expected all=1, got %q", r.URL.RawQuery)
		}
		w.Write([]byte(`[
			{"Id":"abc","Names":["/web-1"],"Image":"nginx","State":"running","Status":"Up 2 hours (healthy)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"}},
			{"Id":"def","Names":["/db-1"],"Image":"postgres","State":"exited","Status":"Exited (0)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"}},
			{"Id":"ghi","Names":["/loose"],"Image":"redis","State":"running","Status":"Up","Labels":{}}
		]`))
	})
	mux.HandleFunc("/containers/abc/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"abc","Name":"/web-1","RestartCount":3,
			"State":{"Status":"running","Running":true,"Health":{"Status":"healthy"}},
			"Config":{"Image":"nginx"}}`))
	})
	mux.HandleFunc("/containers/abc/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("one-shot") != "true" {
			t.Errorf("expected one-shot=true, got %q", r.URL.RawQuery)
		}
		w.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":2000},"system_cpu_usage":100000,"online_cpus":4},
			"precpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":0},
			"memory_stats":{"usage":104857600,"limit":536870912,"stats":{"inactive_file":4194304}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	return New(addr)
}

func TestVersionAndList(t *testing.T) {
	c := fakeEngine(t)
	ctx := context.Background()
	v, err := c.Version(ctx)
	if err != nil || v.Version != "26.1.0" {
		t.Fatalf("version: %v / %+v", err, v)
	}
	cs, err := c.ListContainers(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 {
		t.Fatalf("want 3 containers, got %d", len(cs))
	}
	if cs[0].Project() != "shop" || cs[0].Service() != "web" || cs[0].Name() != "web-1" {
		t.Errorf("label/name parse wrong: %+v", cs[0])
	}
	if cs[2].Project() != "" {
		t.Errorf("unlabeled container should have empty project")
	}
}

func TestInspectAndStats(t *testing.T) {
	c := fakeEngine(t)
	ctx := context.Background()
	ci, err := c.InspectContainer(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if ci.RestartCount != 3 || ci.HealthStatus() != "healthy" {
		t.Errorf("inspect parse wrong: restarts=%d health=%s", ci.RestartCount, ci.HealthStatus())
	}
	st, err := c.StatsOneShot(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	// mem used = 100MiB usage - 4MiB inactive_file = 96MiB
	if got := st.MemUsed(); got != 104857600-4194304 {
		t.Errorf("MemUsed = %d, want %d", got, 104857600-4194304)
	}
	if st.MemLimit() != 536870912 {
		t.Errorf("MemLimit = %d", st.MemLimit())
	}
	// CPU%: cpuDelta=2000, sysDelta=100000, cpus=4 → (2000/100000)*4*100 = 8.0
	if got := st.CPUPercentBetween(0, 0); got != 8.0 {
		t.Errorf("CPU%% = %v, want 8.0", got)
	}
	// no delta on identical prev → 0
	if got := st.CPUPercentBetween(2000, 100000); got != 0 {
		t.Errorf("CPU%% with zero delta = %v, want 0", got)
	}
}

func TestNoHealthcheckReportsNone(t *testing.T) {
	var ci ContainerInspect
	if ci.HealthStatus() != "none" {
		t.Errorf("missing health should report 'none', got %q", ci.HealthStatus())
	}
}

// review #7: when online_cpus is absent, fall back to len(percpu_usage).
func TestCPUPercentPercpuFallback(t *testing.T) {
	var s Stats
	s.CPUStats.CPUUsage.TotalUsage = 4000
	s.CPUStats.SystemUsage = 100000
	s.CPUStats.OnlineCPUs = 0 // older daemon
	s.CPUStats.CPUUsage.PercpuUsage = []uint64{1, 2, 3, 4}
	// (4000/100000)*4*100 = 16.0
	if got := s.CPUPercentBetween(0, 0); got != 16.0 {
		t.Errorf("percpu fallback CPU%% = %v, want 16.0", got)
	}
}

// review #4: the client must not follow a redirect off the loopback proxy.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	c := New(strings.TrimPrefix(srv.URL, "http://"))
	if _, err := c.Version(context.Background()); err == nil {
		t.Error("Version followed a redirect; expected an error (no off-proxy egress)")
	}
}
