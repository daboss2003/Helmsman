// Package provision is the app provisioning core (plan §7): a typed form spec
// (helmsman.yaml under the hood) deterministically GENERATED into a safe compose.
// Helmsman OWNS the compose — there is no raw-compose/Dockerfile paste path — so
// the dangerous compose keys (privileged, cap_add, host namespaces, host binds,
// :80/:443 publishes) SIMPLY DO NOT EXIST in its typed model (no input can produce
// them), and the generated YAML is still re-run through §5.6 as defense in depth.
package provision

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	slugRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	svcRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	envKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	volNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	imageRe   = regexp.MustCompile(`^[A-Za-z0-9._/:@-]+$`)
)

// controlPorts are Helmsman's own ports; a generated service may never publish or
// target them (plan §7 red-team).
var controlPorts = map[int]bool{9000: true, 2019: true, 2375: true}

var validRestart = map[string]bool{"": true, "no": true, "always": true, "on-failure": true, "unless-stopped": true}

// Port is one published container port. Internal is the container port; Publish
// maps it to the host. Public binds 0.0.0.0 (requires an explicit ack) — the
// default binds loopback only (plan §7: 127.0.0.1 unless "expose publicly").
type Port struct {
	Internal int  `json:"internal"`
	Publish  bool `json:"publish"`
	Public   bool `json:"public"`
}

// Volume is a named volume XOR a run_dir-confined bind. Exactly one of Name/Source.
type Volume struct {
	Name     string `json:"name"`   // named volume
	Source   string `json:"source"` // relative bind path, confined under run_dir
	Target   string `json:"target"` // absolute path inside the container
	ReadOnly bool   `json:"read_only"`
}

// Service is one generated service. Only safe fields exist here by construction.
type Service struct {
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Ports       []Port   `json:"ports"`
	Volumes     []Volume `json:"volumes"`
	EnvKeys     []string `json:"env_keys"`    // names only; values live in the encrypted store
	Command     []string `json:"command"`     // exec form (no shell)
	Healthcheck []string `json:"healthcheck"` // exec form, e.g. ["curl","-f","http://localhost/health"]
	Restart     string   `json:"restart"`
	DependsOn   []string `json:"depends_on"` // sibling service names
}

// Spec is the Mode-1 form, the source of truth for a generated app.
type Spec struct {
	Slug     string    `json:"slug"`
	Services []Service `json:"services"`
}

// Validate enforces every field-level safety rule BEFORE generation (the first
// defense, plan §7). It returns the first violation as an operator-facing error.
func (s Spec) Validate() error {
	if !slugRe.MatchString(s.Slug) {
		return fmt.Errorf("app id must match [a-z][a-z0-9-]{1,30} (got %q)", s.Slug)
	}
	if len(s.Services) == 0 {
		return fmt.Errorf("at least one service is required")
	}
	if len(s.Services) > 20 {
		return fmt.Errorf("too many services (max 20)")
	}
	names := map[string]bool{}
	for _, svc := range s.Services {
		if !svcRe.MatchString(svc.Name) {
			return fmt.Errorf("service name %q is invalid (use [a-z0-9][a-z0-9_-]*)", svc.Name)
		}
		if names[svc.Name] {
			return fmt.Errorf("duplicate service name %q", svc.Name)
		}
		names[svc.Name] = true
	}
	for _, svc := range s.Services {
		if err := svc.validate(names); err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
	}
	return nil
}

func (svc Service) validate(siblings map[string]bool) error {
	if err := validateImageRef(svc.Image); err != nil {
		return err
	}
	if !validRestart[svc.Restart] {
		return fmt.Errorf("restart %q is not allowed", svc.Restart)
	}
	for _, p := range svc.Ports {
		if p.Internal < 1 || p.Internal > 65535 {
			return fmt.Errorf("port %d out of range", p.Internal)
		}
		if controlPorts[p.Internal] {
			return fmt.Errorf("port %d is a reserved control-plane port", p.Internal)
		}
	}
	for _, v := range svc.Volumes {
		if err := v.validate(); err != nil {
			return err
		}
	}
	for _, k := range svc.EnvKeys {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("env key %q is invalid", k)
		}
	}
	if err := validateExec(svc.Command); err != nil {
		return fmt.Errorf("command: %w", err)
	}
	if err := validateExec(svc.Healthcheck); err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	for _, d := range svc.DependsOn {
		if !siblings[d] {
			return fmt.Errorf("depends_on references unknown service %q", d)
		}
		if d == svc.Name {
			return fmt.Errorf("service cannot depend on itself")
		}
	}
	return nil
}

func (v Volume) validate() error {
	hasName := v.Name != ""
	hasBind := v.Source != ""
	if hasName == hasBind {
		return fmt.Errorf("volume must set exactly one of name or source")
	}
	// ':' is the field separator in compose's short volume syntax — a path
	// component containing it would shift source/target/mode fields, so reject it
	// (a real path never needs ':').
	if v.Target == "" || !strings.HasPrefix(v.Target, "/") || strings.ContainsAny(v.Target, "\x00\n:") {
		return fmt.Errorf("volume target must be an absolute container path (no ':')")
	}
	if hasName {
		if !volNameRe.MatchString(v.Name) {
			return fmt.Errorf("volume name %q is invalid", v.Name)
		}
		return nil
	}
	// Bind source: relative, no traversal, no abs, no home, no NUL/newline. The
	// §5.6 validator re-confines it under run_dir at validate/deploy time.
	src := v.Source
	if strings.ContainsAny(src, "\x00\n:") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") {
		return fmt.Errorf("bind source %q must be a relative path under the app directory (no ':')", src)
	}
	if src == ".." || strings.HasPrefix(src, "../") || strings.Contains(src, "/../") || strings.HasSuffix(src, "/..") {
		return fmt.Errorf("bind source %q must not traverse outside the app directory", src)
	}
	return nil
}

// validateExec checks an exec-form argv: each element non-empty, no NUL/newline.
// An empty list is allowed (the field is omitted).
func validateExec(argv []string) error {
	for _, a := range argv {
		if a == "" {
			return fmt.Errorf("empty argument")
		}
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("argument contains a control character")
		}
	}
	return nil
}

// validateImageRef requires a non-empty, charset-safe reference WITH an explicit
// tag or digest — never a silent :latest (plan §7).
func validateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("image is required")
	}
	if len(ref) > 512 || !imageRe.MatchString(ref) {
		return fmt.Errorf("image reference %q is invalid", ref)
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		// digest form name@sha256:<64 hex>
		dig := ref[i+1:]
		if !strings.HasPrefix(dig, "sha256:") || len(dig) != len("sha256:")+64 {
			return fmt.Errorf("image digest %q must be sha256:<64 hex>", dig)
		}
		return nil
	}
	// Require an explicit tag in the last path component (registry host ports have
	// a ':' too, so only the component after the last '/' counts).
	last := ref
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		last = ref[i+1:]
	}
	if !strings.Contains(last, ":") {
		return fmt.Errorf("image %q must pin an explicit tag (no silent :latest)", ref)
	}
	if strings.HasSuffix(last, ":") {
		return fmt.Errorf("image %q has an empty tag", ref)
	}
	return nil
}
