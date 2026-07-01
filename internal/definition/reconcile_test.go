package definition

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

// base parses the canonical goodDef fixture into a Definition — the shared starting
// point for the definition tests in this package.
func base() *Definition {
	d, err := Parse([]byte(goodDef))
	if err != nil {
		panic(err)
	}
	return d
}

func TestValidateGeneratedHappyPath(t *testing.T) {
	d := base() // generated web service + edge route → web
	if err := Validate(d, "/run/app", compose.Env{}, nil); err != nil {
		t.Errorf("a clean generated definition should validate: %v", err)
	}
}

// A malformed mem_limit is rejected at validation (early), not deferred to docker; a
// valid size and the unset (empty) case both pass.
func TestValidateMemLimit(t *testing.T) {
	set := func(field, v string) *Definition {
		d := base()
		web := d.Spec.Compose.Services["web"]
		if field == "mem_limit" {
			web.MemLimit = v
		} else {
			web.MemReservation = v
		}
		d.Spec.Compose.Services["web"] = web
		return d
	}
	if err := Validate(set("mem_limit", "768x"), "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "mem_limit") {
		t.Errorf("a malformed mem_limit must be rejected, got %v", err)
	}
	if err := Validate(set("mem_reservation", "lots"), "/run/app", compose.Env{}, nil); err == nil {
		t.Error("a malformed mem_reservation must be rejected")
	}
	for _, ok := range []string{"768m", "1g", "768mb", "1073741824", ""} {
		if err := Validate(set("mem_limit", ok), "/run/app", compose.Env{}, nil); err != nil {
			t.Errorf("valid mem_limit %q rejected: %v", ok, err)
		}
	}
}

// A definition with ulimits.nofile must survive the FULL deploy round-trip:
// reconcile → Generate → §5.6 compose.ValidateBytes (i.e. `ulimits` is emitted and
// the generated compose is not rejected). This is what proves the feature works at
// deploy, not just at `mooring validate`.
func TestValidateUlimitsRoundTrip(t *testing.T) {
	d := base()
	web := d.Spec.Compose.Services["web"]
	web.Ulimits = &Ulimits{Nofile: &NofileLimit{Soft: 1048576, Hard: 1048576}}
	d.Spec.Compose.Services["web"] = web
	if err := Validate(d, "/run/app", compose.Env{}, nil); err != nil {
		t.Errorf("a definition with ulimits must pass reconcile + §5.6 re-validation: %v", err)
	}
	// And the generated compose actually carries the ulimits block.
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ulimits:", "nofile:", "soft: 1048576"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("generated compose missing %q:\n%s", want, raw)
		}
	}
}

// stop_grace_period must be a valid positive duration; bad/zero/negative are rejected
// early, a valid duration and the unset case pass.
func TestValidateStopGracePeriod(t *testing.T) {
	set := func(v string) *Definition {
		d := base()
		web := d.Spec.Compose.Services["web"]
		web.StopGracePeriod = v
		d.Spec.Compose.Services["web"] = web
		return d
	}
	for _, bad := range []string{"60", "soon", "0s", "-5s"} {
		if err := Validate(set(bad), "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "stop_grace_period") {
			t.Errorf("stop_grace_period %q must be rejected, got %v", bad, err)
		}
	}
	for _, ok := range []string{"60s", "1m30s", "500ms", "1h", ""} {
		if err := Validate(set(ok), "/run/app", compose.Env{}, nil); err != nil {
			t.Errorf("valid stop_grace_period %q rejected: %v", ok, err)
		}
	}
}

func TestValidateGeneratedProducesSafeCompose(t *testing.T) {
	d := base()
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "privileged") || strings.Contains(string(raw), "9000:") {
		t.Error("generated compose must never contain dangerous keys")
	}
}

// A build service generates a compose `build:` directive pointing at the Mooring-
// generated Dockerfile path; it must NOT emit an image for that service.
func TestComposeBytesGeneratesBuild(t *testing.T) {
	d := base()
	web := d.Spec.Compose.Services["web"]
	web.Image = ""
	web.Build = &Build{Language: "node"}
	web.Env = nil
	d.Spec.Compose.Services["web"] = web
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatalf("a build service must generate: %v", err)
	}
	out := string(raw)
	if !strings.Contains(out, "build:") || !strings.Contains(out, ".mooring/Dockerfile.web") {
		t.Errorf("generated compose must carry the build directive:\n%s", out)
	}
	if strings.Contains(out, "image:") {
		t.Errorf("a build service must not emit image:\n%s", out)
	}
}

const stackDef = `apiVersion: mooring/v1
kind: App
metadata: {slug: credlock}
spec:
  compose:
    source: generated
    services:
      api:
        image: ghcr.io/acme/api:1
        ports:
          - internal: 3000
        env:
          NODE_ENV: production
          DB_PASSWORD: { secret: DB_PASSWORD }
        depends_on: [emqx]
      emqx:
        image: emqx/emqx:5.8.3
        ports:
          - internal: 8883
            publish: true
            public: true
          - internal: 18083
        volumes:
          - name: emqx_data
            target: /opt/emqx/data
  secrets:
    - name: DB_PASSWORD
  edge:
    routes:
      - hostname: api.example.com
        service: api
        port: 3000
`

// A multi-service stack (the CredLock shape) parses, and Mooring GENERATES a compose
// carrying the public port publish, the named volume, the inline literal env, and the
// per-service secret reference (KEY=${NAME}).
func TestGeneratedMultiServiceStack(t *testing.T) {
	d, err := Parse([]byte(stackDef))
	if err != nil {
		t.Fatalf("multi-service stack rejected: %v", err)
	}
	if len(d.Spec.Compose.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(d.Spec.Compose.Services))
	}
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{"8883:8883", "emqx_data", "NODE_ENV=production", "DB_PASSWORD=${DB_PASSWORD}"} {
		if !strings.Contains(out, want) {
			t.Errorf("generated compose missing %q:\n%s", want, out)
		}
	}
}

func TestValidateEdgeUnknownService(t *testing.T) {
	d := base()
	d.Spec.Edge.Routes[0].Service = "ghost"
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil {
		t.Error("an edge route to an unknown service must be rejected")
	}
}

func TestDiffPlan(t *testing.T) {
	if p, _ := DiffPlan(nil, base()); !p.NewApp {
		t.Error("nil current must be a NewApp plan")
	}
	if p, _ := DiffPlan(base(), base()); !p.Empty() {
		t.Errorf("identical defs must be an empty (idempotent) plan, got %v", p.Changes)
	}
	d2 := base()
	d2.Spec.Scaling = []Scaling{{Service: "web", Max: 3}}
	p, _ := DiffPlan(base(), d2)
	if p.Empty() || len(p.Changes) == 0 {
		t.Error("a changed def must produce a non-empty plan")
	}
}
