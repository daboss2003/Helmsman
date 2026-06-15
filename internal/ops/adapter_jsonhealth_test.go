package ops

import (
	"context"
	"testing"

	"github.com/daboss2003/Helmsman/internal/opsclient"
)

// The registry seam is real: the second built-in adapter is registered and
// resolvable by name, and an unknown name falls back to ops.v1.
func TestRegistryLookupResolvesBothAdapters(t *testing.T) {
	if got := Lookup("ops.v1").Name(); got != "ops.v1" {
		t.Errorf("ops.v1 lookup = %q", got)
	}
	if got := Lookup("health.json").Name(); got != "health.json" {
		t.Errorf("health.json lookup = %q", got)
	}
	if got := Lookup("does-not-exist").Name(); got != "ops.v1" {
		t.Errorf("unknown adapter should fall back to ops.v1, got %q", got)
	}
}

func TestJSONHealthDiscoverAndProbe(t *testing.T) {
	ctx := context.Background()
	a := jsonHealth{}
	target := Target{BaseURL: "http://web:8080"}

	// A plain {"status":"ok"} at /healthz → RICH single indicator "up".
	doer := &fakeDoer{responses: map[string]*opsclient.Response{
		"/healthz": {Status: 200, Body: []byte(`{"status":"ok","message":"all good"}`)},
	}}
	d := a.Discover(ctx, doer, target)
	if d.Mode != RICH {
		t.Fatalf("discover mode = %v, want RICH", d.Mode)
	}
	res := a.Probe(ctx, doer, target, d)
	if res.Mode != RICH || len(res.Indicators) != 1 || res.Indicators[0].Status != "up" {
		t.Fatalf("probe = %+v", res)
	}
	if res.Indicators[0].Source != "health.json" {
		t.Errorf("indicator source = %q, want health.json", res.Indicators[0].Source)
	}

	// 503 with no recognizable status → derived "down".
	doer503 := &fakeDoer{responses: map[string]*opsclient.Response{
		"/healthz": {Status: 503, Body: []byte(`{}`)},
	}}
	d2 := a.Discover(ctx, doer503, target)
	if d2.Mode != RICH { // 503 is still a valid health signal
		t.Fatalf("discover(503) mode = %v, want RICH", d2.Mode)
	}
	res2 := a.Probe(ctx, doer503, target, d2)
	if len(res2.Indicators) != 1 || res2.Indicators[0].Status != "down" {
		t.Fatalf("probe(503) = %+v", res2)
	}

	// Non-JSON body → degrade to BASIC, never crash.
	doerBad := &fakeDoer{responses: map[string]*opsclient.Response{
		"/healthz": {Status: 200, Body: []byte(`not json`)},
	}}
	if d3 := a.Discover(ctx, doerBad, target); d3.Mode != BASIC {
		t.Errorf("non-JSON discover should be BASIC, got %v", d3.Mode)
	}

	// Missing endpoint (404) → BASIC.
	if d4 := a.Discover(ctx, &fakeDoer{}, target); d4.Mode != BASIC {
		t.Errorf("missing /healthz should be BASIC, got %v", d4.Mode)
	}
}
