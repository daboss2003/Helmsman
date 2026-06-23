package web

import "testing"

func TestParseUpstream(t *testing.T) {
	cases := map[string]struct {
		svc  string
		port int
		ok   bool
	}{
		"web:8080":    {"web", 8080, true},
		"api:3000":    {"api", 3000, true},
		"svc.name:53": {"svc.name", 53, true},
		"noport":      {"", 0, false},
		"web:":        {"", 0, false},
		"web:0":       {"", 0, false},
		"web:99999":   {"", 0, false},
		":8080":       {"", 0, false},
	}
	for in, want := range cases {
		svc, port, ok := parseUpstream(in)
		if ok != want.ok || (ok && (svc != want.svc || port != want.port)) {
			t.Errorf("parseUpstream(%q) = (%q,%d,%v), want (%q,%d,%v)", in, svc, port, ok, want.svc, want.port, want.ok)
		}
	}
}
