package definition

import (
	"strings"
	"testing"

	"github.com/helmsman/helmsman/internal/compose"
)

func TestValidateGeneratedHappyPath(t *testing.T) {
	d := base() // generated web service + edge route → web
	if err := Validate(d, "/run/app", compose.Env{}, nil); err != nil {
		t.Errorf("a clean generated definition should validate: %v", err)
	}
}

func TestValidateGeneratedProducesSafeCompose(t *testing.T) {
	// The generated compose must pass §5.6 (no dangerous keys exist by construction).
	d := base()
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "privileged") || strings.Contains(string(raw), "9000:") {
		t.Error("generated compose must never contain dangerous keys")
	}
}

func TestValidateInlineDangerousRejectedBy56(t *testing.T) {
	src := `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: inline
    inline: |
      services:
        web:
          image: nginx
          privileged: true
`
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The envelope/oneOf accept it, but the §5.6 chokepoint must reject privileged.
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil {
		t.Error("an inline compose with privileged:true must be rejected by §5.6")
	}
}

func TestValidateInlinePortPublishRejected(t *testing.T) {
	src := `apiVersion: helmsman/v1
kind: App
metadata: {slug: shop}
spec:
  compose:
    source: inline
    inline: |
      services:
        web:
          image: nginx
          ports: ["80:80"]
`
	d, _ := Parse([]byte(src))
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil {
		t.Error("an inline compose grabbing host :80 must be rejected by §5.6 (edge owns it)")
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
	d2.Spec.Scaling = &Scaling{Service: "web", Max: 3}
	p, _ := DiffPlan(base(), d2)
	if p.Empty() || len(p.Changes) == 0 {
		t.Error("a changed def must produce a non-empty plan")
	}
}
