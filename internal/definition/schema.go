// Package definition is the helmsman.yaml definition file (plan §7.7): the
// declarative source of truth for an app's Helmsman-managed surface. It is a SECOND
// front-end onto the same reconciler/§5.6 validator the dashboard drives — a new
// front door, never a new trust path. Nothing in it reaches `docker compose`
// unvalidated.
//
// Helmsman OWNS the runtime: the operator declares a multi-service STACK here and
// Helmsman GENERATES the compose (and, for build services, the Dockerfile). There is
// no way to supply a raw compose/Dockerfile — `compose.source` is generated-only.
//
// This file is the typed schema. normalize.go is the parser-differential-resistant
// parse (exact apiVersion, unknown-key reject, YAML anchor/alias/merge-key/
// duplicate-key reject, single-document, canonical re-marshal). Each spec section is
// a PROJECTION onto an existing artifact, so the deep validation reuses the existing
// chokepoints (§5.6 compose validator, §6.2 edge gate, the secret store).
package definition

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/daboss2003/Helmsman/internal/sandbox"
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
	Env     []EnvVar `yaml:"env,omitempty"`
	Secrets []Secret `yaml:"secrets,omitempty"`
	Edge    Edge     `yaml:"edge"`
	Scaling *Scaling `yaml:"scaling,omitempty"`
	Git     *Git     `yaml:"git,omitempty"`
	Setup   *Setup   `yaml:"setup,omitempty"`
}

// Compose is GENERATED-ONLY: Helmsman owns the compose. `source` defaults to and may
// only be "generated". The legacy `repo_path`/`inline` sources are rejected; Path and
// Inline are retained ONLY so a stale definition gets a clear, guiding rejection
// instead of a cryptic unknown-field decode error.
type Compose struct {
	Source   string    `yaml:"source,omitempty"`
	Services []Service `yaml:"services,omitempty"`
	Path     string    `yaml:"path,omitempty"`
	Inline   string    `yaml:"inline,omitempty"`
}

// Service is one service in the generated stack. A service is `image` (pull) XOR
// `build` (Helmsman generates the Dockerfile). No host-publish-by-default, no
// dangerous keys — they cannot be expressed, so no input can produce them.
type Service struct {
	Name         string        `yaml:"name"`
	Image        string        `yaml:"image,omitempty"` // image XOR build
	Build        *Build        `yaml:"build,omitempty"`
	Ports        []Port        `yaml:"ports,omitempty"`
	Volumes      []Volume      `yaml:"volumes,omitempty"`
	Env          []string      `yaml:"env,omitempty"`          // env-var names (values live in env/secrets)
	SecretFiles  []string      `yaml:"secret_files,omitempty"` // secret names mounted at /run/secrets/<name>
	ConfigFiles  []ConfigFile  `yaml:"config_files,omitempty"`
	CertBindings []CertBinding `yaml:"cert_bindings,omitempty"`
	Command      []string      `yaml:"command,omitempty"`
	Healthcheck  []string      `yaml:"healthcheck,omitempty"`
	Restart      string        `yaml:"restart,omitempty"`
	DependsOn    []string      `yaml:"depends_on,omitempty"`
}

// Port is one container port. Internal is the in-container port; Publish maps it to
// the host (loopback by default, all interfaces only when Public).
type Port struct {
	Internal int  `yaml:"internal"`
	Publish  bool `yaml:"publish"`
	Public   bool `yaml:"public"`
}

// Build is the declarative build spec — Helmsman GENERATES the Dockerfile from it
// (there is no raw Dockerfile). language "auto" (default) detects the stack from the
// repo; "generic" uses `base` + the operator's own commands (best effort).
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
// service. Content is a repo path (read via git cat-file @ pinned commit) XOR inline.
type ConfigFile struct {
	Repo     string `yaml:"repo,omitempty"`
	Template string `yaml:"template,omitempty"`
	Mount    string `yaml:"mount"`
}

// CertBinding syncs a managed cert to a service (renew + reload handled by Helmsman,
// so the app never runs a docker.sock cert-reloader).
type CertBinding struct {
	Hostname string `yaml:"hostname"`
	Mount    string `yaml:"mount"`
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

// Setup is the per-app setup script (Mode 3). It is declared HERE and synced into the
// setup store; the portal is a read-only view + the gated Run (no literal paste).
type Setup struct {
	Script   string   `yaml:"script"`
	Trigger  string   `yaml:"trigger"`
	Produces []string `yaml:"produces,omitempty"`
}

// SourceGenerated is the only accepted compose source — Helmsman generates the
// compose. (The legacy repo_path/inline sources were removed; Helmsman owns it.)
const SourceGenerated = "generated"

// validateEnvelope enforces the fail-closed envelope rules (exact apiVersion, kind,
// immutable-slug shape). Deep per-projection validation is done by the reconciler
// through the existing chokepoints.
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

// validate enforces the structural spec rules. Helmsman owns the compose, so the only
// accepted source is "generated" (default); the deep §5.6/§6.2 chokepoints do the
// rest.
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
	if err := s.validateSecretsAndEnv(); err != nil {
		return err
	}
	if err := s.validateEdge(); err != nil {
		return err
	}
	return s.validateSetup()
}

func (s *Spec) validateServices() error {
	declaredSecrets := map[string]bool{}
	for _, sec := range s.Secrets {
		declaredSecrets[sec.Name] = true
	}
	names := map[string]bool{}
	for _, svc := range s.Compose.Services {
		if !svcRe.MatchString(svc.Name) {
			return fmt.Errorf("service name %q is invalid", svc.Name)
		}
		if names[svc.Name] {
			return fmt.Errorf("duplicate service %q", svc.Name)
		}
		names[svc.Name] = true

		// image XOR build — exactly one source of the container image.
		hasImage := svc.Image != ""
		hasBuild := svc.Build != nil
		if hasImage == hasBuild {
			return fmt.Errorf("service %q must set exactly one of image or build", svc.Name)
		}
		if hasBuild {
			if err := validateBuild(svc.Name, svc.Build); err != nil {
				return err
			}
		}
		for _, p := range svc.Ports {
			if p.Internal < 1 || p.Internal > 65535 {
				return fmt.Errorf("service %q port %d is out of range", svc.Name, p.Internal)
			}
			if controlPort(p.Internal) {
				return fmt.Errorf("service %q port %d is a reserved control-plane port", svc.Name, p.Internal)
			}
			if p.Public && !p.Publish {
				return fmt.Errorf("service %q port %d sets public without publish", svc.Name, p.Internal)
			}
		}
		for _, k := range svc.Env {
			if !envKeyRe.MatchString(k) {
				return fmt.Errorf("service %q env key %q is invalid", svc.Name, k)
			}
		}
		for _, sf := range svc.SecretFiles {
			if !declaredSecrets[sf] {
				return fmt.Errorf("service %q secret_files references undeclared secret %q", svc.Name, sf)
			}
		}
		for _, cf := range svc.ConfigFiles {
			if err := validateConfigFile(svc.Name, cf); err != nil {
				return err
			}
		}
		for _, cb := range svc.CertBindings {
			if err := validateCertBinding(svc.Name, cb); err != nil {
				return err
			}
		}
		for _, v := range svc.Volumes {
			if err := validateVolume(svc.Name, v); err != nil {
				return err
			}
		}
		if !validRestart[svc.Restart] {
			return fmt.Errorf("service %q restart %q is not allowed", svc.Name, svc.Restart)
		}
		if err := validateExec("command", svc.Name, svc.Command); err != nil {
			return err
		}
		if err := validateExec("healthcheck", svc.Name, svc.Healthcheck); err != nil {
			return err
		}
		for _, d := range svc.DependsOn {
			if d == svc.Name {
				return fmt.Errorf("service %q cannot depend on itself", svc.Name)
			}
		}
	}
	// depends_on references must name a real sibling.
	for _, svc := range s.Compose.Services {
		for _, d := range svc.DependsOn {
			if !names[d] {
				return fmt.Errorf("service %q depends_on unknown service %q", svc.Name, d)
			}
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
	declared := map[string]bool{}
	for _, svc := range s.Compose.Services {
		declared[svc.Name] = true
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

// mountPath requires an absolute, clean container path (no NUL/newline).
func mountPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be an absolute container path")
	}
	return nil
}

// relConfined requires a repo-relative, traversal-free path (the deep symlink-aware
// confinement is re-asserted under the checkout/run_dir at §5.6/materialize time).
func relConfined(p string) error {
	if p == "" || filepath.IsAbs(p) || p == ".." ||
		strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") ||
		strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be a repo-relative, traversal-free path")
	}
	return nil
}

// validateExec checks an exec-form argv: each element non-empty, no NUL/newline.
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
