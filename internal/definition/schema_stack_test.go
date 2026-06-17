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
