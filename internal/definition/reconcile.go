package definition

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/daboss2003/Helmsman/internal/builder"
	"github.com/daboss2003/Helmsman/internal/compose"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/provision"
)

// reconcile.go is the shared validation core (plan §7.7): a definition is fanned out
// into the EXISTING typed sub-structs and run through the SAME chokepoints the
// dashboard uses — §5.6 (compose) and §6.2 (edge) — so the CLI/dashboard/repo are
// three front doors onto one trust path. Nothing here reaches `docker compose`
// unvalidated.

// toProvisionSpec maps a generated-compose definition onto the M8 typed app spec.
// There is no host-publish field — ingress is only an edge.route — so a generated
// service can never publish a port (Publish stays false).
func toProvisionSpec(d *Definition) provision.Spec {
	ps := provision.Spec{Slug: d.Metadata.Slug}
	for _, name := range d.Spec.serviceNames() { // sorted → deterministic compose
		svc := d.Spec.Compose.Services[name]
		s := provision.Service{
			Name:    name,
			Command: svc.Command, Healthcheck: svc.Healthcheck, Restart: svc.Restart, DependsOn: svc.DependsOn,
		}
		if svc.Build != nil {
			// Helmsman generates the Dockerfile into the run dir at deploy; the compose
			// build context is the app's checkout (".").
			s.Build = &provision.Build{Context: ".", Dockerfile: builder.DockerfilePath(name)}
		} else {
			s.Image = svc.Image
		}
		for _, p := range svc.Ports {
			s.Ports = append(s.Ports, provision.Port{Internal: p.Internal, Publish: p.Publish, Public: p.Public})
		}
		for _, v := range svc.Volumes {
			s.Volumes = append(s.Volumes, provision.Volume{Name: v.Name, Source: v.Source, Target: v.Target, ReadOnly: v.ReadOnly})
		}
		// Managed config-file / secret-file mounts (Helmsman renders the content into
		// the run dir at deploy; here we emit the read-only bind into the compose).
		for i, cf := range svc.ConfigFiles {
			s.Volumes = append(s.Volumes, provision.Volume{Source: ManagedConfigPath(name, i), Target: cf.Mount, ReadOnly: true})
		}
		for _, sec := range svc.SecretFiles {
			s.Volumes = append(s.Volumes, provision.Volume{Source: ManagedSecretPath(name, sec), Target: "/run/secrets/" + sec, ReadOnly: true})
		}
		for _, cb := range svc.CertBindings {
			s.Volumes = append(s.Volumes, provision.Volume{Source: ManagedCertDir(name, cb.Hostname), Target: cb.Mount, ReadOnly: true})
		}
		ekeys := make([]string, 0, len(svc.Env))
		for k := range svc.Env {
			ekeys = append(ekeys, k)
		}
		sort.Strings(ekeys)
		for _, k := range ekeys {
			ev := svc.Env[k]
			s.Env = append(s.Env, provision.EnvVar{Key: k, Value: ev.Value, Secret: ev.Secret})
		}
		ps.Services = append(ps.Services, s)
	}
	return ps
}

// ComposeBytes returns the compose document this definition would deploy: ALWAYS
// generated from the typed services — Helmsman owns the compose. There is no raw
// (repo_path/inline) source.
func ComposeBytes(d *Definition) ([]byte, error) {
	if src := d.Spec.Compose.Source; src != "" && src != SourceGenerated {
		return nil, fmt.Errorf("compose.source %q is not supported — Helmsman generates the compose", src)
	}
	ps := toProvisionSpec(d)
	if err := ps.Validate(); err != nil { // field-level gate before generation
		return nil, err
	}
	return provision.Generate(ps)
}

// Validate runs the full reconcile validation: §5.6 over the (generated or inline)
// compose, then §6.2 over the edge routes (upstreams are service selectors, never
// literal dial targets). Returns the first violation. env is for inline ${VAR}
// resolution; runDir is the app run dir bind mounts must stay under.
func Validate(d *Definition, runDir string, env compose.Env, protectedPaths []string) error {
	raw, err := ComposeBytes(d)
	if err != nil {
		return fmt.Errorf("compose: %w", err)
	}
	if res := compose.ValidateBytes(raw, env, runDir, compose.Options{ProtectedPaths: protectedPaths}); !res.OK() {
		return fmt.Errorf("§5.6 compose validation failed: %s", res.Violations[0].String())
	}
	// §6.2 edge gate: each route's upstream is a selector (service:port) resolved
	// against THIS app's containers — validated like any Layer-1 route (no
	// control-plane port, no loopback, FQDN host).
	declared := map[string]bool{}
	for name := range d.Spec.Compose.Services {
		declared[name] = true
	}
	for _, r := range d.Spec.Edge.Routes {
		if !declared[r.Service] {
			return fmt.Errorf("edge route %q targets unknown service %q", r.Hostname, r.Service)
		}
		port := r.Port
		if port == 0 {
			port = 80
		}
		er := edge.Route{
			Hostname:        r.Hostname,
			Upstream:        r.Service + ":" + strconv.Itoa(port), // selector, resolved to the container at apply
			UpstreamScheme:  "http",
			PathPrefix:      r.PathPrefix,
			HSTS:            r.HSTS,
			SecurityHeaders: r.SecurityHeaders,
			RedirectHTTP:    r.RedirectHTTP,
			Enabled:         true,
		}
		if err := edge.ValidateRoute(er); err != nil {
			return fmt.Errorf("§6.2 edge route %q: %w", r.Hostname, err)
		}
	}
	return nil
}

// Plan is the diff between the live canonical (current) and a desired definition.
type Plan struct {
	NewApp  bool
	Changes []string // changed field paths (the file is never secret-bearing, so nothing to mask)
}

// Empty reports whether applying the plan would be a no-op (idempotent apply).
func (p Plan) Empty() bool { return !p.NewApp && len(p.Changes) == 0 }

// DiffPlan computes the field-level changes from current to desired. current may be
// nil (a brand-new app).
func DiffPlan(current, desired *Definition) (Plan, error) {
	if current == nil {
		return Plan{NewApp: true}, nil
	}
	cm, err := flattenDef(current)
	if err != nil {
		return Plan{}, err
	}
	dm, err := flattenDef(desired)
	if err != nil {
		return Plan{}, err
	}
	seen := map[string]bool{}
	var changes []string
	for p, cv := range cm {
		if dm[p] != cv {
			changes = append(changes, p)
		}
		seen[p] = true
	}
	for p := range dm {
		if !seen[p] {
			changes = append(changes, p)
		}
	}
	sort.Strings(changes)
	return Plan{Changes: changes}, nil
}
