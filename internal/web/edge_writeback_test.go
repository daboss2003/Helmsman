package web

import (
	"testing"

	"github.com/daboss2003/Helmsman/internal/definition"
)

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

func TestUpsertAndRemoveRoute(t *testing.T) {
	list := []definition.Route{{Hostname: "a.example.com", Service: "a", Port: 80}}
	// Upsert same hostname+prefix replaces in place.
	list = upsertRoute(list, definition.Route{Hostname: "a.example.com", Service: "a", Port: 9090})
	if len(list) != 1 || list[0].Port != 9090 {
		t.Fatalf("upsert should replace in place: %+v", list)
	}
	// Different hostname appends.
	list = upsertRoute(list, definition.Route{Hostname: "b.example.com", Service: "b", Port: 80})
	if len(list) != 2 {
		t.Fatalf("new hostname should append: %+v", list)
	}
	// A different path_prefix on the same host is a distinct route.
	list = upsertRoute(list, definition.Route{Hostname: "a.example.com", PathPrefix: "/api", Service: "a", Port: 80})
	if len(list) != 3 {
		t.Fatalf("distinct path_prefix should be its own route: %d", len(list))
	}
	// Remove one.
	list = removeRoute(list, "b.example.com", "")
	if len(list) != 2 {
		t.Fatalf("remove should drop exactly one: %+v", list)
	}
	for _, r := range list {
		if r.Hostname == "b.example.com" {
			t.Error("b.example.com should be gone")
		}
	}
}
