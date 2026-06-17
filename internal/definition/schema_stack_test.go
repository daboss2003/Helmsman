package definition

import "testing"

// docWith wraps a spec body (indented under `spec:`) into a full App document.
func docWith(specBody string) string {
	return "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: shop}\nspec:\n" + specBody
}

func TestServiceImageXorBuild(t *testing.T) {
	cases := map[string]struct {
		spec    string
		wantErr bool
	}{
		"image only": {`  compose: {source: generated, services: {web: {image: nginx:1}}}`, false},
		"build only": {`  compose:
    source: generated
    services:
      web:
        build: {language: node}`, false},
		"both image and build": {`  compose:
    source: generated
    services:
      web:
        image: nginx:1
        build: {language: node}`, true},
		"neither": {`  compose: {source: generated, services: {web: {}}}`, true},
	}
	for name, c := range cases {
		_, err := Parse([]byte(docWith(c.spec)))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", name, c.wantErr, err)
		}
	}
}

func TestBuildValidation(t *testing.T) {
	cases := map[string]struct {
		build   string
		wantErr bool
	}{
		"auto default":         {`{language: auto}`, false},
		"go":                   {`{language: go}`, false},
		"unknown language":     {`{language: cobol}`, true},
		"generic needs base":   {`{language: generic}`, true},
		"generic with base":    {`{language: generic, base: "ubuntu:24.04", start: ["./s"]}`, false},
		"base without generic": {`{language: node, base: "ubuntu:24.04"}`, true},
		"bad build env key":    {`{language: node, env: {"bad-key": "v"}}`, true},
	}
	for name, c := range cases {
		spec := `  compose:
    source: generated
    services:
      web:
        build: ` + c.build
		_, err := Parse([]byte(docWith(spec)))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", name, c.wantErr, err)
		}
	}
}

func TestServiceEnvValidation(t *testing.T) {
	cases := map[string]struct {
		spec    string
		wantErr bool
	}{
		"literal ok": {`  compose: {source: generated, services: {web: {image: nginx:1, env: {LOG_LEVEL: info}}}}`, false},
		"secret declared": {`  compose:
    source: generated
    services:
      web:
        image: nginx:1
        env: {DB: {secret: DB_PASSWORD}}
  secrets: [{name: DB_PASSWORD}]`, false},
		"secret undeclared":  {`  compose: {source: generated, services: {web: {image: nginx:1, env: {DB: {secret: NOPE}}}}}`, true},
		"literal interp":     {`  compose: {source: generated, services: {web: {image: nginx:1, env: {X: "${OTHER}"}}}}`, true},
		"bad env key":        {`  compose: {source: generated, services: {web: {image: nginx:1, env: {"bad-key": v}}}}`, true},
		"bad env value form": {`  compose: {source: generated, services: {web: {image: nginx:1, env: {X: {wrong: y}}}}}`, true},
	}
	for name, c := range cases {
		_, err := Parse([]byte(docWith(c.spec)))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", name, c.wantErr, err)
		}
	}
}

func TestSecretFilesMustBeDeclared(t *testing.T) {
	declared := `  compose:
    source: generated
    services:
      web:
        image: nginx:1
        secret_files: [api_key]
  secrets: [{name: api_key}]`
	if _, err := Parse([]byte(docWith(declared))); err != nil {
		t.Errorf("a declared secret_files ref must pass: %v", err)
	}
	undeclared := `  compose:
    source: generated
    services:
      web:
        image: nginx:1
        secret_files: [ghost]`
	if _, err := Parse([]byte(docWith(undeclared))); err == nil {
		t.Error("an undeclared secret_files ref must be rejected")
	}
}

func TestConfigFileValidation(t *testing.T) {
	cases := map[string]struct {
		cf      string
		wantErr bool
	}{
		"repo + mount":     {`{repo: docker/emqx.conf, mount: /etc/emqx.conf}`, false},
		"template + mount": {`{template: "x", mount: /etc/x}`, false},
		"missing mount":    {`{repo: a.conf}`, true},
		"relative mount":   {`{repo: a.conf, mount: etc/x}`, true},
		"both sources":     {`{repo: a.conf, template: "x", mount: /etc/x}`, true},
		"neither source":   {`{mount: /etc/x}`, true},
		"repo traversal":   {`{repo: "../../etc/passwd", mount: /etc/x}`, true},
	}
	for name, c := range cases {
		spec := `  compose:
    source: generated
    services:
      web:
        image: nginx:1
        config_files: [` + c.cf + `]`
		_, err := Parse([]byte(docWith(spec)))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", name, c.wantErr, err)
		}
	}
}

func TestCertBindingValidation(t *testing.T) {
	cases := map[string]struct {
		cb      string
		wantErr bool
	}{
		"ok":            {`{hostname: mqtt.example.com, mount: /etc/certs}`, false},
		"bad hostname":  {`{hostname: "not a host", mount: /etc/certs}`, true},
		"missing mount": {`{hostname: mqtt.example.com}`, true},
	}
	for name, c := range cases {
		spec := `  compose:
    source: generated
    services:
      web:
        image: nginx:1
        cert_bindings: [` + c.cb + `]`
		_, err := Parse([]byte(docWith(spec)))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got err=%v", name, c.wantErr, err)
		}
	}
}

func TestPortPublicRequiresPublish(t *testing.T) {
	spec := `  compose:
    source: generated
    services:
      web:
        image: nginx:1
        ports: [{internal: 8883, public: true}]`
	if _, err := Parse([]byte(docWith(spec))); err == nil {
		t.Error("a public port without publish must be rejected")
	}
}

func TestSetupValidation(t *testing.T) {
	ok := `  compose: {source: generated, services: {web: {image: nginx:1}}}
  setup: {script: "#!/bin/sh\necho hi", trigger: on_demand, produces: ["env:TOKEN"]}`
	if _, err := Parse([]byte(docWith(ok))); err != nil {
		t.Errorf("a valid setup must pass: %v", err)
	}
	badTrigger := `  compose: {source: generated, services: {web: {image: nginx:1}}}
  setup: {script: "x", trigger: whenever}`
	if _, err := Parse([]byte(docWith(badTrigger))); err == nil {
		t.Error("an invalid setup trigger must be rejected")
	}
	autoConflict := `  compose: {source: generated, services: {web: {image: nginx:1}}}
  git: {repo: "https://x/y", auto_deploy: true}
  setup: {script: "x", trigger: before_each_deploy}`
	if _, err := Parse([]byte(docWith(autoConflict))); err == nil {
		t.Error("auto setup trigger + git.auto_deploy must be rejected")
	}
}

func TestScalingValidation(t *testing.T) {
	base := "  compose:\n    source: generated\n    services:\n      web: {image: nginx:1}\n      api: {image: nginx:1}\n"
	good := base + "  scaling:\n    - {service: web, enabled: true, min: 1, max: 3}\n    - {service: api, min: 1, max: 2}\n"
	if _, err := Parse([]byte(docWith(good))); err != nil {
		t.Fatalf("two-service scaling should be valid: %v", err)
	}
	bad := map[string]string{
		"unknown service":  base + "  scaling:\n    - {service: ghost, min: 1, max: 2}\n",
		"duplicate":        base + "  scaling:\n    - {service: web, min: 1, max: 2}\n    - {service: web, min: 1, max: 3}\n",
		"min over max":     base + "  scaling:\n    - {service: web, min: 5, max: 2}\n",
		"pct out of range": base + "  scaling:\n    - {service: web, up_cpu_pct: 150}\n",
	}
	for name, spec := range bad {
		if _, err := Parse([]byte(docWith(spec))); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestSelfHealingValidation(t *testing.T) {
	base := "  compose:\n    services:\n      web: {image: nginx:1}\n"
	good := base + "  self_healing:\n    sustain_ticks: 3\n    attempt_cap: 5\n    window_seconds: 3600\n    backoff_base_secs: 60\n    backoff_max_secs: 900\n    redeploy_enabled: true\n"
	if _, err := Parse([]byte(docWith(good))); err != nil {
		t.Fatalf("self_healing should be valid: %v", err)
	}
	bad := map[string]string{
		"negative field": base + "  self_healing:\n    sustain_ticks: -1\n",
		"max below base": base + "  self_healing:\n    backoff_base_secs: 600\n    backoff_max_secs: 60\n",
		"unknown field":  base + "  self_healing:\n    bogus: 1\n",
	}
	for name, spec := range bad {
		if _, err := Parse([]byte(docWith(spec))); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestOpsInterfaceValidation(t *testing.T) {
	base := "  compose:\n    services:\n      web: {image: nginx:1}\n  secrets:\n    - {name: OPS_SECRET, generate: 'password:32'}\n"
	good := base + "  ops_interface:\n    enabled: true\n    base_url: http://web:8080\n    secret_header: X-Ops-Secret\n    secret: OPS_SECRET\n    mode: rich\n    base_path: /ops\n"
	if _, err := Parse([]byte(docWith(good))); err != nil {
		t.Fatalf("ops_interface should be valid: %v", err)
	}
	bad := map[string]string{
		"bad mode":          base + "  ops_interface:\n    mode: turbo\n",
		"enabled loopback":  base + "  ops_interface:\n    enabled: true\n    base_url: http://localhost:8080\n",
		"enabled no host":   base + "  ops_interface:\n    enabled: true\n    base_url: notaurl\n",
		"undeclared secret": base + "  ops_interface:\n    secret: GHOST\n",
		"bad base_path":     base + "  ops_interface:\n    base_path: 'http://x'\n",
	}
	for name, spec := range bad {
		if _, err := Parse([]byte(docWith(spec))); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// TestSelfHealOpsCanonicalRoundTrip proves the new spec keys survive a Canonical →
// Parse round-trip (the write-back path: dashboard/deploy renders the canonical, then
// re-validates it). A field that didn't round-trip would silently drop on every save.
func TestSelfHealOpsCanonicalRoundTrip(t *testing.T) {
	src := docWith("  compose:\n    services:\n      web: {image: nginx:1}\n" +
		"  secrets:\n    - {name: OPS_SECRET, generate: 'password:32'}\n" +
		"  self_healing:\n    attempt_cap: 5\n    redeploy_enabled: true\n" +
		"  ops_interface:\n    enabled: true\n    base_url: http://web:8080\n    secret: OPS_SECRET\n    mode: rich\n")
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canon, err := Canonical(d)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	d2, err := Parse(canon)
	if err != nil {
		t.Fatalf("re-parse canonical: %v\n%s", err, canon)
	}
	if d2.Spec.SelfHealing == nil || d2.Spec.SelfHealing.AttemptCap != 5 || !d2.Spec.SelfHealing.RedeployEnabled {
		t.Errorf("self_healing did not round-trip: %+v", d2.Spec.SelfHealing)
	}
	if d2.Spec.OpsInterface == nil || !d2.Spec.OpsInterface.Enabled || d2.Spec.OpsInterface.Secret != "OPS_SECRET" || d2.Spec.OpsInterface.Mode != "rich" {
		t.Errorf("ops_interface did not round-trip: %+v", d2.Spec.OpsInterface)
	}
}
