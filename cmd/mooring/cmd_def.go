package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/definition"
)

// cmdValidate is the read-plane `mooring validate` — parse + reconcile a
// mooring.yaml through the SAME §5.6/§6.2 chokepoints an apply uses, with NO DB and
// NO write plane (safe to run in CI, below the §0 floor). Exit non-zero on any
// violation. This is the CLI/dashboard parity guarantee: a def that validates here
// is one the dashboard would accept, because both go through the one reconciler.
func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	from := fs.String("from", "mooring.yaml", "path to the definition file")
	runDir := fs.String("run-dir", "", "app run directory bind mounts must stay under (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*from)
	if err != nil {
		return fmt.Errorf("read %s: %w", *from, err)
	}
	kind, err := definition.Kind(raw)
	if err != nil {
		return err
	}
	if kind == "Host" {
		h, err := definition.ParseHost(raw)
		if err != nil {
			return err // envelope + Tier-1 + registry + deploy-order cycle checks
		}
		fmt.Printf("OK: host definition is valid (%d apps registered)\n", len(h.Spec.Apps))
		return nil
	}
	d, err := definition.Parse(raw)
	if err != nil {
		return err // parse + envelope + parser-differential rejections
	}
	// Resolve ${VAR} for an inline compose from a sibling .env, never Mooring's env.
	env := compose.Env{}
	if data, derr := os.ReadFile(filepath.Join(filepath.Dir(*from), ".env")); derr == nil {
		env = compose.ParseEnvFile(data)
	}
	if err := definition.Validate(d, *runDir, env, nil); err != nil {
		return err
	}
	fmt.Printf("OK: %s (kind=%s, compose.source=%s) is valid\n", d.Metadata.Slug, d.Kind, d.Spec.Compose.Source)
	return nil
}

// relPath rejects an absolute or parent-traversing path (a CLI fail-fast guard so a
// scaffold never reads/writes outside the operator's working directory).
func relPath(flag, p string) error {
	clean := filepath.Clean(p)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s must be a repo-relative path, not absolute or traversing (got %q)", flag, p)
	}
	return nil
}

// cmdInit scaffolds a generated mooring.yaml skeleton (Mooring owns the compose —
// there is no compose/Dockerfile to point at). The operator edits the seed service
// (image: or build:) and fills in env/secrets/edge.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	slug := fs.String("slug", "", "app slug (immutable after first apply)")
	image := fs.String("image", "nginx:1.27", "image for the seed service (replace, or switch to build:)")
	port := fs.Int("port", 0, "internal container port for the seed service (optional)")
	out := fs.String("out", "mooring.yaml", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("usage: mooring init --slug <slug> [--image <image>] [--port <n>] [--out mooring.yaml]")
	}
	// --out must be repo-relative + non-traversing — never write outside the
	// operator's working directory.
	if err := relPath("--out", *out); err != nil {
		return err
	}
	svc := definition.Service{Image: *image}
	if *port > 0 {
		svc.Ports = []definition.Port{{Internal: *port}}
	}
	d := &definition.Definition{
		APIVersion: definition.APIVersion,
		Kind:       "App",
		Metadata:   definition.Metadata{Slug: *slug},
		Spec: definition.Spec{
			Compose: definition.Compose{Source: definition.SourceGenerated, Services: map[string]definition.Service{"web": svc}},
		},
	}
	// Round-trip through Parse so the scaffold is guaranteed valid before it's written.
	canon, err := definition.Canonical(d)
	if err != nil {
		return err
	}
	if _, err := definition.Parse(canon); err != nil {
		return fmt.Errorf("scaffold invalid: %w", err)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists (refusing to overwrite)", *out)
	}
	if err := os.WriteFile(*out, canon, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s — edit spec.compose.services (each service's image:/build:, env, ports), spec.secrets, and spec.edge.routes, then `mooring validate`\n", *out)
	return nil
}
