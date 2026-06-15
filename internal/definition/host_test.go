package definition

import (
	"reflect"
	"strings"
	"testing"
)

// Closedness guard: every field of Defaults must be accounted for by the posture
// predicate. If someone ADDS a Defaults field without handling it in
// PostureWidenings (posture.go), this fails — so a new knob can't silently widen.
func TestDefaultsFieldsAllPostureChecked(t *testing.T) {
	// The fields PostureWidenings inspects. Keep in sync when adding a posture knob.
	checked := map[string]bool{"Scaling": true, "SelfHealing": true, "AutoDeploy": true}
	tp := reflect.TypeOf(Defaults{})
	for i := 0; i < tp.NumField(); i++ {
		f := tp.Field(i).Name
		if !checked[f] {
			t.Errorf("Defaults.%s is not checked by PostureWidenings — add a widening check (posture.go) and list it here", f)
		}
	}
}

func TestDefaultsScalingValidated(t *testing.T) {
	bad := []string{
		`apiVersion: helmsman/v1
kind: Host
spec:
  defaults: {scaling: {min: -1}}`,
		`apiVersion: helmsman/v1
kind: Host
spec:
  defaults: {scaling: {min: 5, max: 2}}`,
	}
	for _, src := range bad {
		if _, err := ParseHost([]byte(src)); err == nil {
			t.Errorf("invalid defaults.scaling must be rejected: %s", src)
		}
	}
}

const goodHost = `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - slug: broker
      source: {managed: true}
      enabled: true
    - slug: api
      source: {repo: "https://example/r", ref: main}
      enabled: true
    - slug: web
      source: {path: ./web}
      enabled: false
  defaults:
    self_healing: true
  orchestration:
    deploy_order:
      - {deploy: api, after: broker}
      - {deploy: web, after: api}
`

func TestParseHostHappyPath(t *testing.T) {
	h, err := ParseHost([]byte(goodHost))
	if err != nil {
		t.Fatalf("clean host rejected: %v", err)
	}
	if len(h.Spec.Apps) != 3 {
		t.Errorf("want 3 registered apps, got %d", len(h.Spec.Apps))
	}
	seq, err := h.Spec.Orchestration.DeploySequence()
	if err != nil {
		t.Fatal(err)
	}
	// broker before api before web.
	if idx(seq, "broker") > idx(seq, "api") || idx(seq, "api") > idx(seq, "web") {
		t.Errorf("deploy order not respected: %v", seq)
	}
}

func idx(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// The 3-tier boundary: a Tier-1 security field in a host (or app) def is a hard
// reject with a pointer to SSH — for BOTH kinds, at any nesting depth.
func TestTier1FieldsRejected(t *testing.T) {
	for _, field := range []string{"encryption_key", "ip_allowlist", "bind_addr", "trusted_proxies", "password_hash", "totp_secret"} {
		hostSrc := "apiVersion: helmsman/v1\nkind: Host\nspec:\n  " + field + ": x\n"
		if _, err := ParseHost([]byte(hostSrc)); err == nil || !strings.Contains(err.Error(), "Tier-1") {
			t.Errorf("host with %q must be a Tier-1 reject, got %v", field, err)
		}
		appSrc := "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: shop}\nspec:\n  " + field + ": x\n  compose: {source: inline, inline: x}\n"
		if _, err := Parse([]byte(appSrc)); err == nil || !strings.Contains(err.Error(), "Tier-1") {
			t.Errorf("app with %q must be a Tier-1 reject, got %v", field, err)
		}
	}
}

func TestParseHostBadEnvelopeAndOneOf(t *testing.T) {
	cases := map[string]string{
		"wrong kind": strings.Replace(goodHost, "kind: Host", "kind: App", 1),
		"dup slug": `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - {slug: app1, source: {managed: true}}
    - {slug: app1, source: {managed: true}}`,
		"source not oneOf": `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - {slug: app1, source: {repo: "x", path: "y"}}`,
		"ref without repo": `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - {slug: app1, source: {ref: main}}`,
		"order unknown app": `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - {slug: app1, source: {managed: true}}
  orchestration:
    deploy_order: [{deploy: app1, after: ghost}]`,
	}
	for name, src := range cases {
		if _, err := ParseHost([]byte(src)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestDeployOrderCycleRejected(t *testing.T) {
	src := `apiVersion: helmsman/v1
kind: Host
spec:
  apps:
    - {slug: app1, source: {managed: true}}
    - {slug: app2, source: {managed: true}}
  orchestration:
    deploy_order:
      - {deploy: app1, after: app2}
      - {deploy: app2, after: app1}
`
	if _, err := ParseHost([]byte(src)); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("a deploy_order cycle must be rejected, got %v", err)
	}
}

// --- posture-widening predicate ---

func bptr(b bool) *bool { return &b }

func TestPostureWideningsTightenVsWiden(t *testing.T) {
	// Tightening / neutral defaults need no ack.
	if w := PostureWidenings(&Defaults{SelfHealing: bptr(true)}); len(w) != 0 {
		t.Errorf("enabling self-healing (the safe default) is not a widening: %v", w)
	}
	// Each widening must be flagged.
	wide := &Defaults{
		AutoDeploy:  bptr(true),  // enabling auto-deploy widens
		SelfHealing: bptr(false), // disabling the supervisor widens
		Scaling:     &DefaultScaling{Max: 5, Min: 2},
	}
	w := PostureWidenings(wide)
	if len(w) != 4 {
		t.Errorf("expected 4 widenings (auto_deploy, self_healing, scaling.max, scaling.min), got %d: %v", len(w), w)
	}
}

func TestUnackedWideningsBlock(t *testing.T) {
	d := &Defaults{AutoDeploy: bptr(true), Scaling: &DefaultScaling{Max: 9}}
	// No acks → both widenings block.
	if len(UnackedWidenings(d, nil)) != 2 {
		t.Error("unacked widenings must block")
	}
	// Acknowledge both → clean.
	acks := AckSet{"defaults.auto_deploy": true, "defaults.scaling.max": true}
	if len(UnackedWidenings(d, acks)) != 0 {
		t.Error("fully-acknowledged widenings must not block")
	}
	// Partial ack → still blocks the unacked one.
	if len(UnackedWidenings(d, AckSet{"defaults.auto_deploy": true})) != 1 {
		t.Error("a partially-acked set must still block the rest")
	}
}
