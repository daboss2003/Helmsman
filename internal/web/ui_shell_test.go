package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The CapRover-style shell must render on authenticated pages: a sidebar with
// inline-SVG nav icons and the topbar. Login (unauthenticated) must NOT get the
// shell (it uses the centered card). These pin the layout against regressions.
func TestShellRendersOnAuthedPages(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess == nil {
		t.Fatal("login failed")
	}
	for _, path := range []string{"/", "/edge", "/alerts", "/events"} {
		resp := e.req(t, "GET", path, "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		body := readBody(resp)
		for _, want := range []string{`class="sidebar"`, "data-nav", "<svg", `class="topbar"`} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s: shell marker %q missing from rendered page", path, want)
			}
		}
		// No emoji icons — icons must be real inline SVG.
		if strings.ContainsAny(body, "🔔🌐") {
			t.Errorf("GET %s: page still contains emoji icons (want inline SVG)", path)
		}
	}
}

func TestLoginHasNoShell(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	resp := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	body := readBody(resp)
	if strings.Contains(body, `class="sidebar"`) {
		t.Error("login page must not render the app shell (sidebar)")
	}
	if !strings.Contains(body, `class="auth"`) {
		t.Error("login page must use the centered auth layout")
	}
}

// The home page carries the live-chart mount points the dashboard JS draws into.
func TestHomeHasChartMounts(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	resp := e.req(t, "GET", "/", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	body := readBody(resp)
	for _, want := range []string{`data-chart="cpu"`, `data-chart="mem"`, `data-chart="disk"`} {
		if !strings.Contains(body, want) {
			t.Errorf("home page missing chart mount %q", want)
		}
	}
}

// The metrics-history endpoint is cookie-authed and returns a JSON points array.
func TestMetricsHistoryEndpoint(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	// Unauthenticated → redirect to login (not 200 JSON).
	anon := e.req(t, "GET", "/partials/metrics.json", "127.0.0.1:1", nil, nil, nil)
	if anon.StatusCode == http.StatusOK {
		t.Error("metrics.json must require auth")
	}
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	resp := e.req(t, "GET", "/partials/metrics.json", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed metrics.json = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var out struct {
		Points []metricPoint `json:"points"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Empty DB → an empty (non-null) array.
	if out.Points == nil {
		t.Error("points must be a non-null array")
	}
}
