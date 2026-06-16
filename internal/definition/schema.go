// Package definition is the helmsman.yaml definition file (plan §7.7): the
// declarative source of truth for an app's Helmsman-managed surface. It is a SECOND
// front-end onto the same reconciler/§5.6 validator the dashboard drives — a new
// front door, never a new trust path. Nothing in it reaches `docker compose`
// unvalidated.
//
// Helmsman OWNS the runtime: the operator declares a multi-service STACK here and
// Helmsman GENERATES the compose (and, for build services, the Dockerfile). There is
// no way to supply a raw compose/Dockerfile — `compose.source` is generated-only.
// `services` is a map keyed by name; per-service `env` is a map of literals/secret
// references (compose-familiar).
package definition

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/daboss2003/Helmsman/internal/sandbox"
	"gopkg.in/yaml.v3"
)

// APIVersion is the ONLY accepted envelope version — exact-match, fail-closed.
const APIVersion = "helmsman/v1"

var (
	slugRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	svcRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	secretRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	envKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)
)

// buildLanguages are the recognized build languages. "auto" (the default) detects
// the stack from the repo; "generic" wraps the operator's own base + commands.
var buildLanguages = map[string]bool{
	"auto": true, "node": true, "python": true, "go": true,
	"ruby": true, "php": true, "static": true, "generic": true,
}

var validRestart = map[string]bool{
	"": true, "no": true, "always": true, "on-failure": true, "unless-stopped": true,
}

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
	Secrets []Secret `yaml:"secrets,omitempty"`
	Edge    Edge     `yaml:"edge"`
	Scaling *Scaling `yaml:"scaling,omitempty"`
	Git     *Git     `yaml:"git,omitempty"`
	Setup   *Setup   `yaml:"setup,omitempty"`
}

// Compose is GENERATED-ONLY: Helmsman owns the compose. `source` defaults to and may
// only be "generated". The legacy `repo_path`/`inline` sources are rejected; Path and
// Inline are retained ONLY so a stale definition gets a clear, guiding rejection.
type Compose struct {
	Source   string             `yaml:"source,omitempty"`
	Services map[string]Service `yaml:"services,omitempty"`
	Path     string             `yaml:"path,omitempty"`
	Inline   string             `yaml:"inline,omitempty"`
}

// Service is one service in the generated stack (the map key is its name). A service
// is `image` (pull) XOR `build` (Helmsman generates the Dockerfile).
type Service struct {
	Image        string              `yaml:"image,omitempty"` // image XOR build
	Build        *Build              `yaml:"build,omitempty"`
	Ports        []Port              `yaml:"ports,omitempty"`
	Volumes      []Volume            `yaml:"volumes,omitempty"`
	Env          map[string]EnvValue `yaml:"env,omitempty"` // KEY: literal | {secret: NAME}
	SecretFiles  []string            `yaml:"secret_files,omitempty"`
	ConfigFiles  []ConfigFile        `yaml:"config_files,omitempty"`
	CertBindings []CertBinding       `yaml:"cert_bindings,omitempty"`
	Command      []string            `yaml:"command,omitempty"`
	Healthcheck  []string            `yaml:"healthcheck,omitempty"`
	Restart      string              `yaml:"restart,omitempty"`
	DependsOn    []string            `yaml:"depends_on,omitempty"`
}

// EnvValue is a per-service env var: a literal value XOR a `{secret: NAME}` reference.
// A scalar is a literal; a mapping must be exactly `{ secret: NAME }`.
type EnvValue struct {
	Value  string
	Secret string
}

// MarshalYAML renders the canonical form: a `{secret: NAME}` mapping for a reference,
// else the scalar literal — so Canonical round-trips back through UnmarshalYAML.
func (e EnvValue) MarshalYAML() (any, error) {
	if e.Secret != "" {
		return map[string]string{"secret": e.Secret}, nil
	}
	return e.Value, nil
}

// UnmarshalYAML accepts a scalar literal or a `{ secret: NAME }` mapping (only).
func (e *EnvValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		e.Value = n.Value
		return nil
	case yaml.MappingNode:
		if len(n.Content) != 2 || n.Content[0].Value != "secret" {
			return fmt.Errorf("env value mapping must be exactly { secret: NAME }")
		}
		e.Secret = n.Content[1].Value
		if e.Secret == "" {
			return fmt.Errorf("env value { secret: } requires a name")
		}
		return nil
	default:
		return fmt.Errorf("env value must be a literal or { secret: NAME }")
	}
}

// Port is one container port. Internal is the in-container port; Publish maps it to
// the host (loopback by default, all interfaces only when Public).
type Port struct {
	Internal int  `yaml:"internal"`
	Publish  bool `yaml:"publish"`
	Public   bool `yaml:"public"`
}

// Build is the declarative build spec — Helmsman GENERATES the Dockerfile from it.
type Build struct {
	Language string            `yaml:"language,omitempty"`
	Version  string            `yaml:"version,omitempty"`
	Base     string            `yaml:"base,omitempty"` // generic only
	Install  string            `yaml:"install,omitempty"`
	BuildCmd string            `yaml:"build,omitempty"`
	Start    []string          `yaml:"start,omitempty"`
	Env      map[string]string `yaml:"env,omitempty"`
	Packages []string          `yaml:"packages,omitempty"`
	Nonroot  *bool             `yaml:"run_as_nonroot,omitempty"`
}

// Volume is a named volume XOR a run_dir-confined bind.
type Volume struct {
	Name     string `yaml:"name"`
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only"`
}

// ConfigFile is an app config file Helmsman renders + bind-mounts read-only into a
// service. Content is a repo path (git cat-file @ pinned commit) XOR inline template.
type ConfigFile struct {
	Repo     string `yaml:"repo,omitempty"`
	Template string `yaml:"template,omitempty"`
	Mount    string `yaml:"mount"`
}

// CertBinding syncs a managed cert to a service (renew + reload handled by Helmsman).
type CertBinding struct {
	Hostname string `yaml:"hostname"`
	Mount    string `yaml:"mount"`
}

// Secret declares a name (+ optional generate hint) — NEVER a value.
type Secret struct {
	Name     string `yaml:"name"`
	Generate string `yaml:"generate"`
}

// Edge is the Layer-1 route input (§6).
type Edge struct {
	Routes []Route `yaml:"routes,omitempty"`
}

// Route is one managed edge vhost. Upstream is a SELECTOR — "service:port".
type Route struct {
	Hostname        string `yaml:"hostname"`
	Service         string `yaml:"service"`
	Port            int    `yaml:"port"`
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

// Setup is the per-app setup script (Mode 3), declared here and synced into the setup
// store; the portal is a read-only view + the gated Run (no literal paste).
type Setup struct {
	Script   string   `yaml:"script"`
	Trigger  string   `yaml:"trigger"`
	Produces []string `yaml:"produces,omitempty"`
}

// SourceGenerated is the only accepted compose source.
const SourceGenerated = "generated"

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

func (s *Spec) validate() error {
	switch s.Compose.Source {
	case "", SourceGenerated:
		// ok — Helmsman generates the compose.
	case "repo_path", "inline":
		return fmt.Errorf("compose.source %q is no longer supported — Helmsman generates the compose; "+
			"declare your services (with image: or build:) under compose.services (source: generated)", s.Compose.Source)
	default:
		return fmt.Errorf("compose.source must be \"generated\" (got %q) — Helmsman generates the compose", s.Compose.Source)
	}
	if s.Compose.Path != "" || s.Compose.Inline != "" {
		return fmt.Errorf("compose.path/compose.inline are no longer supported — Helmsman generates the compose from compose.services")
	}
	if len(s.Compose.Services) == 0 {
		return fmt.Errorf("compose.services is required (Helmsman generates the compose from your services)")
	}
	if err := s.validateServices(); err != nil {
		return err
	}
	if err := s.validateSecrets(); err != nil {
		return err
	}
	if err := s.validateEdge(); err != nil {
		return err
	}
	return s.validateSetup()
}

// serviceNames returns the stack's service names, sorted (deterministic validation).
func (s *Spec) serviceNames() []string {
	names := make([]string, 0, len(s.Compose.Services))
	for n := range s.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (s *Spec) validateServices() error {
	declaredSecrets := map[string]bool{}
	for _, sec := range s.Secrets {
		declaredSecrets[sec.Name] = true
	}
	names := map[string]bool{}
	for n := range s.Compose.Services {
		names[n] = true
	}
	for _, name := range s.serviceNames() {
		if !svcRe.MatchString(name) {
			return fmt.Errorf("service name %q is invalid", name)
		}
		svc := s.Compose.Services[name]

		hasImage := svc.Image != ""
		hasBuild := svc.Build != nil
		if hasImage == hasBuild {
			return fmt.Errorf("service %q must set exactly one of image or build", name)
		}
		if hasBuild {
			if err := validateBuild(name, svc.Build); err != nil {
				return err
			}
		}
		for _, p := range svc.Ports {
			if p.Internal < 1 || p.Internal > 65535 {
				return fmt.Errorf("service %q port %d is out of range", name, p.Internal)
			}
			if controlPort(p.Internal) {
				return fmt.Errorf("service %q port %d is a reserved control-plane port", name, p.Internal)
			}
			if p.Public && !p.Publish {
				return fmt.Errorf("service %q port %d sets public without publish", name, p.Internal)
			}
		}
		if err := validateServiceEnv(name, svc.Env, declaredSecrets); err != nil {
			return err
		}
		for _, sf := range svc.SecretFiles {
			if !declaredSecrets[sf] {
				return fmt.Errorf("service %q secret_files references undeclared secret %q", name, sf)
			}
		}
		for _, cf := range svc.ConfigFiles {
			if err := validateConfigFile(name, cf); err != nil {
				return err
			}
		}
		for _, cb := range svc.CertBindings {
			if err := validateCertBinding(name, cb); err != nil {
				return err
			}
		}
		for _, v := range svc.Volumes {
			if err := validateVolume(name, v); err != nil {
				return err
			}
		}
		if !validRestart[svc.Restart] {
			return fmt.Errorf("service %q restart %q is not allowed", name, svc.Restart)
		}
		if err := validateExec("command", name, svc.Command); err != nil {
			return err
		}
		if err := validateExec("healthcheck", name, svc.Healthcheck); err != nil {
			return err
		}
		for _, d := range svc.DependsOn {
			if d == name {
				return fmt.Errorf("service %q cannot depend on itself", name)
			}
			if !names[d] {
				return fmt.Errorf("service %q depends_on unknown service %q", name, d)
			}
		}
	}
	return nil
}

// validateServiceEnv checks each per-service env entry: a valid KEY, a literal with no
// `${` interpolation sequence (so a literal can't smuggle a compose variable) / no
// control chars, or a `{secret: NAME}` ref to a DECLARED secret.
func validateServiceEnv(svc string, env map[string]EnvValue, declaredSecrets map[string]bool) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("service %q env key %q is invalid", svc, k)
		}
		v := env[k]
		if v.Secret != "" {
			if !secretRe.MatchString(v.Secret) {
				return fmt.Errorf("service %q env %q references an invalid secret name %q", svc, k, v.Secret)
			}
			if !declaredSecrets[v.Secret] {
				return fmt.Errorf("service %q env %q references undeclared secret %q", svc, k, v.Secret)
			}
			continue
		}
		if strings.ContainsAny(v.Value, "\x00\n\r") {
			return fmt.Errorf("service %q env %q value contains a control character", svc, k)
		}
		if strings.Contains(v.Value, "${") {
			return fmt.Errorf("service %q env %q literal must not contain ${...} (use a secret reference)", svc, k)
		}
	}
	return nil
}

func validateBuild(svc string, b *Build) error {
	lang := b.Language
	if lang == "" {
		lang = "auto"
	}
	if !buildLanguages[lang] {
		return fmt.Errorf("service %q build.language %q is not supported (auto|node|python|go|ruby|php|static|generic)", svc, b.Language)
	}
	if lang == "generic" && b.Base == "" {
		return fmt.Errorf("service %q build.language generic requires build.base (the base image)", svc)
	}
	if lang != "generic" && b.Base != "" {
		return fmt.Errorf("service %q build.base is only valid with language generic", svc)
	}
	if err := validateExec("build.start", svc, b.Start); err != nil {
		return err
	}
	for k := range b.Env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("service %q build.env key %q is invalid", svc, k)
		}
	}
	for _, p := range b.Packages {
		if p == "" || strings.ContainsAny(p, "\x00\n ") {
			return fmt.Errorf("service %q build.packages entry %q is invalid", svc, p)
		}
	}
	return nil
}

func validateConfigFile(svc string, cf ConfigFile) error {
	if err := mountPath(cf.Mount); err != nil {
		return fmt.Errorf("service %q config_files mount: %w", svc, err)
	}
	hasRepo := cf.Repo != ""
	hasTmpl := cf.Template != ""
	if hasRepo == hasTmpl {
		return fmt.Errorf("service %q config_files entry must set exactly one of repo or template", svc)
	}
	if hasRepo {
		if err := relConfined(cf.Repo); err != nil {
			return fmt.Errorf("service %q config_files repo %q: %w", svc, cf.Repo, err)
		}
	}
	return nil
}

func validateCertBinding(svc string, cb CertBinding) error {
	if len(cb.Hostname) > 253 || !hostnameRe.MatchString(cb.Hostname) {
		return fmt.Errorf("service %q cert_bindings hostname %q is invalid (FQDN, no wildcards)", svc, cb.Hostname)
	}
	if err := mountPath(cb.Mount); err != nil {
		return fmt.Errorf("service %q cert_bindings mount: %w", svc, err)
	}
	return nil
}

func validateVolume(svc string, v Volume) error {
	hasName := v.Name != ""
	hasBind := v.Source != ""
	if hasName == hasBind {
		return fmt.Errorf("service %q volume must set exactly one of name or source", svc)
	}
	if v.Target == "" || !strings.HasPrefix(v.Target, "/") || strings.ContainsAny(v.Target, "\x00\n:") {
		return fmt.Errorf("service %q volume target must be an absolute container path (no ':')", svc)
	}
	if hasName {
		if !svcRe.MatchString(v.Name) {
			return fmt.Errorf("service %q volume name %q is invalid", svc, v.Name)
		}
		return nil
	}
	if strings.Contains(v.Source, ":") {
		return fmt.Errorf("service %q bind source %q must not contain ':'", svc, v.Source)
	}
	if err := relConfined(v.Source); err != nil {
		return fmt.Errorf("service %q bind source %q: %w", svc, v.Source, err)
	}
	return nil
}

func (s *Spec) validateSecrets() error {
	for _, sec := range s.Secrets {
		if !secretRe.MatchString(sec.Name) {
			return fmt.Errorf("secret name %q is invalid", sec.Name)
		}
	}
	return nil
}

func (s *Spec) validateEdge() error {
	declared := map[string]bool{}
	for n := range s.Compose.Services {
		declared[n] = true
	}
	for _, r := range s.Edge.Routes {
		h := r.Hostname
		if len(h) > 253 || !hostnameRe.MatchString(h) {
			return fmt.Errorf("edge route hostname %q is invalid (FQDN, no wildcards)", h)
		}
		if !svcRe.MatchString(r.Service) {
			return fmt.Errorf("edge route %q must name a valid service (upstream is a selector, never a literal dial target)", h)
		}
		if !declared[r.Service] {
			return fmt.Errorf("edge route %q targets unknown service %q", h, r.Service)
		}
		if r.Port != 0 && controlPort(r.Port) {
			return fmt.Errorf("edge route %q port %d is a reserved control-plane port", h, r.Port)
		}
	}
	return nil
}

func (s *Spec) validateSetup() error {
	if s.Setup == nil {
		return nil
	}
	autoDeploy := s.Git != nil && s.Git.AutoDeploy
	ss := sandbox.ScriptSet{Script: s.Setup.Script, Trigger: s.Setup.Trigger, Produces: s.Setup.Produces}
	if err := ss.Validate(autoDeploy); err != nil {
		return fmt.Errorf("spec.setup: %w", err)
	}
	return nil
}

func mountPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be an absolute container path")
	}
	return nil
}

func relConfined(p string) error {
	if p == "" || filepath.IsAbs(p) || p == ".." ||
		strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") ||
		strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be a repo-relative, traversal-free path")
	}
	return nil
}

func validateExec(field, svc string, argv []string) error {
	for _, a := range argv {
		if a == "" {
			return fmt.Errorf("service %q %s has an empty argument", svc, field)
		}
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("service %q %s argument contains a control character", svc, field)
		}
	}
	return nil
}

func controlPort(p int) bool { return p == 9000 || p == 2019 || p == 2375 }
