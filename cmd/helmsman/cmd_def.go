package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/helmsman/helmsman/internal/compose"
	"github.com/helmsman/helmsman/internal/definition"
)

// cmdValidate is the read-plane `helmsman validate` — parse + reconcile a
// helmsman.yaml through the SAME §5.6/§6.2 chokepoints an apply uses, with NO DB and
// NO write plane (safe to run in CI, below the §0 floor). Exit non-zero on any
// violation. This is the CLI/dashboard parity guarantee: a def that validates here
// is one the dashboard would accept, because both go through the one reconciler.
func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	from := fs.String("from", "helmsman.yaml", "path to the definition file")
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
	// Resolve ${VAR} for an inline compose from a sibling .env, never Helmsman's env.
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

// cmdInit scaffolds a helmsman.yaml from an existing compose file (`--from-compose`),
// pointing at it via source: repo_path. The operator then fills in env/secrets/edge.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fromCompose := fs.String("from-compose", "", "scaffold from this compose file (repo-relative path)")
	slug := fs.String("slug", "", "app slug (immutable after first apply)")
	out := fs.String("out", "helmsman.yaml", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fromCompose == "" || *slug == "" {
		return fmt.Errorf("usage: helmsman init --slug <slug> --from-compose <compose.yml> [--out helmsman.yaml]")
	}
	// Both paths must be repo-relative + non-traversing — fail fast at scaffold time
	// rather than relying on the apply-time confinement, and never write outside the
	// operator's working directory.
	if err := relPath("--from-compose", *fromCompose); err != nil {
		return err
	}
	if err := relPath("--out", *out); err != nil {
		return err
	}
	d := &definition.Definition{
		APIVersion: definition.APIVersion,
		Kind:       "App",
		Metadata:   definition.Metadata{Slug: *slug},
		Spec: definition.Spec{
			Compose: definition.Compose{Source: definition.SourceRepoPath, Path: *fromCompose},
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
	fmt.Printf("wrote %s — edit spec.env / spec.secrets / spec.edge.routes, then `helmsman validate`\n", *out)
	return nil
}
