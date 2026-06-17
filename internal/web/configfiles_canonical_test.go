package web

import (
	"testing"

	"github.com/daboss2003/Helmsman/internal/definition"
)

// TestBindingSourceRoundTrip checks the editor source grammar round-trips through
// parse → string for every binding kind (so a dashboard save then re-display is stable).
func TestBindingSourceRoundTrip(t *testing.T) {
	cases := map[string]definition.Binding{
		"secret:DB_PASS":            {Secret: "DB_PASS"},
		"env:UPSTREAM":              {Env: "UPSTREAM"},
		"app:slug":                  {App: "slug"},
		"cert:shop.example.com.crt": {Cert: "shop.example.com.crt"},
		"literal:hello-world":       {Value: "hello-world"},
	}
	for src, want := range cases {
		got, err := parseBindingSourceStr(src)
		if err != nil {
			t.Errorf("%s: parse: %v", src, err)
			continue
		}
		if got != want {
			t.Errorf("%s: parsed %+v, want %+v", src, got, want)
		}
		if rt := bindingSourceString(got); rt != src {
			t.Errorf("%s: round-trip string = %q", src, rt)
		}
	}
	for _, bad := range []string{"nope", "unknown:x", "secret:", ""} {
		if _, err := parseBindingSourceStr(bad); err == nil {
			t.Errorf("%q: expected parse error", bad)
		}
	}
}

func TestParseCanonicalBindings(t *testing.T) {
	in := "# a comment\ncookie=secret:NODE_COOKIE\nhost=app:slug\n\nup=env:UPSTREAM\n"
	got, err := parseCanonicalBindings(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 3 || got["cookie"].Secret != "NODE_COOKIE" || got["host"].App != "slug" || got["up"].Env != "UPSTREAM" {
		t.Fatalf("unexpected: %+v", got)
	}
	if _, err := parseCanonicalBindings("nokeysep\n"); err == nil {
		t.Error("expected error on a line without '='")
	}
}

func TestUpsertRemoveConfigFileByMount(t *testing.T) {
	list := []definition.ConfigFile{{Mount: "/a", Template: "1"}}
	list = upsertConfigFileByMount(list, definition.ConfigFile{Mount: "/a", Template: "2"}) // replace
	list = upsertConfigFileByMount(list, definition.ConfigFile{Mount: "/b", Template: "3"}) // append
	if len(list) != 2 || list[0].Template != "2" {
		t.Fatalf("upsert: %+v", list)
	}
	list = removeConfigFileByMount(list, "/a")
	if len(list) != 1 || list[0].Mount != "/b" {
		t.Fatalf("remove: %+v", list)
	}
}

func TestUpsertRemoveCertBindingByHost(t *testing.T) {
	list := []definition.CertBinding{{Hostname: "a.com", Mount: "/x"}}
	list = upsertCertBindingByHost(list, definition.CertBinding{Hostname: "a.com", Mount: "/y"}) // replace
	list = upsertCertBindingByHost(list, definition.CertBinding{Hostname: "b.com", Mount: "/z"}) // append
	if len(list) != 2 || list[0].Mount != "/y" {
		t.Fatalf("upsert: %+v", list)
	}
	list = removeCertBindingByHost(list, "a.com")
	if len(list) != 1 || list[0].Hostname != "b.com" {
		t.Fatalf("remove: %+v", list)
	}
}
