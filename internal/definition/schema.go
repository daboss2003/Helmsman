// Package definition is the helmsman.yaml definition file (plan §7.7): the
// declarative source of truth for an app's Helmsman-managed surface. It is a SECOND
// front-end onto the same reconciler/§5.6 validator the dashboard drives — a new
// front door, never a new trust path. Nothing in it reaches `docker compose`
// unvalidated.
//
// This file is the typed schema (DefinitionV1). normalize.go is the parser-
// differential-resistant parse (exact apiVersion, unknown-key reject, YAML
// anchor/alias/merge-key/duplicate-key reject, single-document, canonical
// re-marshal). Each spec section is a PROJECTION onto an existing artifact — no new
// artifact types — so the deep validation reuses the existing chokepoints (§5.6
// compose validator, §6.2 edge gate, the secret store).
package definition

import (
	"fmt"
	"regexp"
)

// APIVersion is the ONLY accepted envelope version — exact-match, fail-closed. An
// unknown/future version is rejected, never best-effort parsed.
const APIVersion = "helmsman/v1"

var (
	slugRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	svcRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	secretRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	envKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)
)

// Definition is the whole helmsman.yaml document (kind: App).
type Definition struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata carries the immutable app slug.
type Metadata struct {
	Slug string `yaml:"slug"`
}

// Spec is the managed surface. Each field projects onto an existing artifact.
type Spec struct {
	Compose Compose  `yaml:"compose"`
	Env     []EnvVar `yaml:"env,omitempty"`
	Secrets []Secret `yaml:"secrets,omitempty"`
	Edge    Edge     `yaml:"edge"`
	Scaling *Scaling `yaml:"scaling,omitempty"`
	Git     *Git     `yaml:"git,omitempty"`
}

// Compose is a strict oneOf over the three sources (no inference).
type Compose struct {
	Source   string    `yaml:"source"` // generated | repo_path | inline
	Services []Service `yaml:"services,omitempty"`
	Path     string    `yaml:"path,omitempty"`   // repo_path: a repo-relative compose path
	Inline   string    `yaml:"inline,omitempty"` // inline: literal compose YAML
}

// Service is one generated service. There is NO host-publish field — ingress is only
// an edge.route — and no dangerous keys exist in the schema by construction.
type Service struct {
	Name        string   `yaml:"name"`
	Image       string   `yaml:"image"`
	Port        int      `yaml:"port"` // internal container port (no host publish)
	Volumes     []Volume `yaml:"volumes,omitempty"`
	Env         []string `yaml:"env,omitempty"` // env-var names (values live in env/secrets)
	Command     []string `yaml:"command,omitempty"`
	Healthcheck []string `yaml:"healthcheck,omitempty"`
	Restart     string   `yaml:"restart"`
	DependsOn   []string `yaml:"depends_on,omitempty"`
}

// Volume is a named volume XOR a run_dir-confined bind.
type Volume struct {
	Name     string `yaml:"name"`
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only"`
}

// EnvVar is a non-secret literal (Value) XOR a secret reference (Secret = name).
type EnvVar struct {
	Name   string `yaml:"name"`
	Value  string `yaml:"value"`
	Secret string `yaml:"secret"`
}

// Secret declares a name (+ optional generate hint) — NEVER a value. The file is
// never secret-bearing.
type Secret struct {
	Name     string `yaml:"name"`
	Generate string `yaml:"generate"` // optional hint: e.g. "hex32", "base64-32"
}

// Edge is the Layer-1 route input (§6).
type Edge struct {
	Routes []Route `yaml:"routes,omitempty"`
}

// Route is one managed edge vhost. Upstream is a SELECTOR — "service:port" — resolved
// against this app's discovered containers, never a literal dial target.
type Route struct {
	Hostname        string `yaml:"hostname"`
	Service         string `yaml:"service"` // which of this app's services
	Port            int    `yaml:"port"`    // the service's internal port
	PathPrefix      string `yaml:"path_prefix"`
	HSTS            bool   `yaml:"hsts"`
	SecurityHeaders bool   `yaml:"security_headers"`
	RedirectHTTP    bool   `yaml:"redirect_http"`
}

// Scaling is the opt-in auto-scaling policy (§8A) for one service.
type Scaling struct {
	Service            string  `yaml:"service"`
	Enabled            bool    `yaml:"enabled"`
	Min                int     `yaml:"min"`
	Max                int     `yaml:"max"`
	UpCPUPct           float64 `yaml:"up_cpu_pct"`
	DownCPUPct         float64 `yaml:"down_cpu_pct"`
	UpMemPct           float64 `yaml:"up_mem_pct"`
	DownMemPct         float64 `yaml:"down_mem_pct"`
	PerReplicaMemMiB   int     `yaml:"per_replica_mem_mib"`
	PerReplicaCPUMilli int     `yaml:"per_replica_cpu_milli"`
}

// Git is the repo-path / auto-pull config (§7.6). AutoDeploy defaults false.
type Git struct {
	Repo       string `yaml:"repo"`
	Ref        string `yaml:"ref"`
	AutoDeploy bool   `yaml:"auto_deploy"`
}

const (
	SourceGenerated = "generated"
	SourceRepoPath  = "repo_path"
	SourceInline    = "inline"
)

// validateEnvelope enforces the fail-closed envelope rules (exact apiVersion, kind,
// immutable-slug shape, the compose oneOf). Deep per-projection validation is done
// by the reconciler through the existing chokepoints.
func (d *Definition) validateEnvelope() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be exactly %q (got %q) — unknown versions are rejected", APIVersion, d.APIVersion)
	}
	if d.Kind != "App" {
		return fmt.Errorf("kind must be \"App\" (got %q)", d.Kind)
	}
	if !slugRe.MatchString(d.Metadata.Slug) {
		return fmt.Errorf("metadata.slug must match [a-z][a-z0-9-]{1,30} (got %q)", d.Metadata.Slug)
	}
	return d.Spec.validate()
}

// validate enforces the structural spec rules (the oneOf, names, references). It is
// the cheap field-level pass; the §5.6/§6.2 chokepoints do the deep validation.
func (s *Spec) validate() error {
	switch s.Compose.Source {
	case SourceGenerated:
		if len(s.Compose.Services) == 0 {
			return fmt.Errorf("compose.source=generated requires spec.compose.services")
		}
		if s.Compose.Path != "" || s.Compose.Inline != "" {
			return fmt.Errorf("compose.source=generated must not set path/inline")
		}
		if err := s.validateServices(); err != nil {
			return err
		}
	case SourceRepoPath:
		if s.Compose.Path == "" {
			return fmt.Errorf("compose.source=repo_path requires compose.path")
		}
		if len(s.Compose.Services) > 0 || s.Compose.Inline != "" {
			return fmt.Errorf("compose.source=repo_path must not set services/inline")
		}
	case SourceInline:
		if s.Compose.Inline == "" {
			return fmt.Errorf("compose.source=inline requires compose.inline")
		}
		if len(s.Compose.Services) > 0 || s.Compose.Path != "" {
			return fmt.Errorf("compose.source=inline must not set services/path")
		}
	default:
		return fmt.Errorf("compose.source must be one of generated|repo_path|inline (got %q)", s.Compose.Source)
	}
	if err := s.validateSecretsAndEnv(); err != nil {
		return err
	}
	return s.validateEdge()
}

func (s *Spec) validateServices() error {
	names := map[string]bool{}
	for _, svc := range s.Compose.Services {
		if !svcRe.MatchString(svc.Name) {
			return fmt.Errorf("service name %q is invalid", svc.Name)
		}
		if names[svc.Name] {
			return fmt.Errorf("duplicate service %q", svc.Name)
		}
		names[svc.Name] = true
		if svc.Image == "" {
			return fmt.Errorf("service %q must set image", svc.Name)
		}
		if svc.Port != 0 && controlPort(svc.Port) {
			return fmt.Errorf("service %q port %d is a reserved control-plane port", svc.Name, svc.Port)
		}
		for _, k := range svc.Env {
			if !envKeyRe.MatchString(k) {
				return fmt.Errorf("service %q env key %q is invalid", svc.Name, k)
			}
		}
	}
	return nil
}

func (s *Spec) validateSecretsAndEnv() error {
	declared := map[string]bool{}
	for _, sec := range s.Secrets {
		if !secretRe.MatchString(sec.Name) {
			return fmt.Errorf("secret name %q is invalid", sec.Name)
		}
		declared[sec.Name] = true
	}
	for _, e := range s.Env {
		if !envKeyRe.MatchString(e.Name) {
			return fmt.Errorf("env name %q is invalid", e.Name)
		}
		if e.Value != "" && e.Secret != "" {
			return fmt.Errorf("env %q sets both value and secret (pick one)", e.Name)
		}
		if e.Secret != "" && !declared[e.Secret] {
			return fmt.Errorf("env %q references undeclared secret %q", e.Name, e.Secret)
		}
	}
	return nil
}

func (s *Spec) validateEdge() error {
	for _, r := range s.Edge.Routes {
		h := r.Hostname
		if len(h) > 253 || !hostnameRe.MatchString(h) {
			return fmt.Errorf("edge route hostname %q is invalid (FQDN, no wildcards)", h)
		}
		if r.Service == "" {
			return fmt.Errorf("edge route %q must name a service (upstream is a selector, never a literal)", h)
		}
		if r.Port != 0 && controlPort(r.Port) {
			return fmt.Errorf("edge route %q port %d is a reserved control-plane port", h, r.Port)
		}
	}
	return nil
}

func controlPort(p int) bool { return p == 9000 || p == 2019 || p == 2375 }
