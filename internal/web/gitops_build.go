package web

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daboss2003/Helmsman/internal/builder"
	"github.com/daboss2003/Helmsman/internal/definition"
	"github.com/daboss2003/Helmsman/internal/git"
)

// loadRepoDefinition reads the repo's helmsman.yaml at the pinned commit and parses it
// (Helmsman generates the compose from it — the repo never supplies a compose). If the
// repo has no helmsman.yaml, it scaffolds a default from the repo's detected stack so
// "connect a repo" still works. The app's identity is its REGISTRATION slug, so the
// parsed slug is overridden — a repo can't deploy itself under a different app's name.
func (s *Server) loadRepoDefinition(ctx context.Context, repo *git.Repo, sha, slug string) (*definition.Definition, bool, error) {
	if b, err := repo.CatFile(ctx, sha, "helmsman.yaml"); err == nil {
		d, perr := definition.Parse(b)
		if perr != nil {
			return nil, false, fmt.Errorf("helmsman.yaml: %w", perr)
		}
		d.Metadata.Slug = slug
		return d, false, nil
	}
	// No helmsman.yaml — scaffold a single build service from the detected stack.
	files, err := repo.LsFiles(ctx, sha)
	if err != nil {
		return nil, false, fmt.Errorf("list repo files: %w", err)
	}
	b, derr := builder.Resolve(builder.Spec{Language: "auto"}, topLevelSet(files))
	if derr != nil {
		return nil, false, fmt.Errorf("no helmsman.yaml in the repo and %w — add a helmsman.yaml", derr)
	}
	d := &definition.Definition{
		APIVersion: definition.APIVersion,
		Kind:       "App",
		Metadata:   definition.Metadata{Slug: slug},
		Spec: definition.Spec{
			Compose: definition.Compose{
				Source:   definition.SourceGenerated,
				Services: map[string]definition.Service{"app": {Build: &definition.Build{Language: b.Name()}}},
			},
		},
	}
	return d, true, nil
}

// writeGeneratedDockerfiles renders the Helmsman-owned Dockerfile for each build
// service and writes it under the run dir at builder.DockerfilePath (confined,
// symlink-safe). Detection (language: auto) reads the repo's top-level file list at
// the pinned commit.
func (s *Server) writeGeneratedDockerfiles(ctx context.Context, repo *git.Repo, sha, rd string, def *definition.Definition, onLine func(string)) error {
	if defHasBuild(def) {
		// CRITICAL: the build context is the run dir, which also holds .helmsman/
		// (rendered config + secret VALUES). Exclude it so `COPY . .` can never bake
		// a secret into an image layer.
		if err := ensureDockerignore(rd); err != nil {
			return fmt.Errorf("write .dockerignore: %w", err)
		}
	}
	var top map[string]bool
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := def.Spec.Compose.Services[name]
		if svc.Build == nil {
			continue
		}
		if top == nil {
			files, err := repo.LsFiles(ctx, sha)
			if err != nil {
				return fmt.Errorf("list repo files: %w", err)
			}
			top = topLevelSet(files)
		}
		dockerfile, err := builder.Generate(buildSpecFor(name, svc), top)
		if err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
		dest := filepath.Join(rd, filepath.FromSlash(builder.DockerfilePath(name)))
		if !confinedUnder(dest, rd) {
			return fmt.Errorf("service %q: generated Dockerfile path escapes the run dir", name)
		}
		// Symlink-safe write (temp + rename; ancestors checked) — see atomicWrite.
		if err := atomicWrite(dest, []byte(dockerfile), 0o644, rd); err != nil {
			return fmt.Errorf("service %q: write Dockerfile: %w", name, err)
		}
		onLine("generated Dockerfile for " + name)
	}
	return nil
}

// buildSpecFor projects a definition build onto the builder spec (non-root defaults on).
func buildSpecFor(name string, svc definition.Service) builder.Spec {
	b := svc.Build
	nonroot := true
	if b.Nonroot != nil {
		nonroot = *b.Nonroot
	}
	return builder.Spec{
		Service:  name,
		Language: b.Language,
		Version:  b.Version,
		Base:     b.Base,
		Install:  b.Install,
		Build:    b.BuildCmd,
		Start:    b.Start,
		Env:      b.Env,
		Packages: b.Packages,
		Nonroot:  nonroot,
	}
}

// materializeManaged renders each service's config_files (from the repo @ pinned
// commit, or an inline template) and writes each secret_files value (from the
// encrypted store) into the run dir at the Helmsman-managed paths — the read-only
// bind mounts for these were already emitted into the generated compose by reconcile.
// All writes are confined + symlink-safe (atomicWrite). secret values are 0600.
// (cert_bindings sync is a follow-on — it integrates with the edge cert issuance.)
func (s *Server) materializeManaged(ctx context.Context, repo *git.Repo, sha, rd, project string, def *definition.Definition) error {
	names := make([]string, 0, len(def.Spec.Compose.Services))
	for n := range def.Spec.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := def.Spec.Compose.Services[name]
		for i, cf := range svc.ConfigFiles {
			var content []byte
			if cf.Repo != "" {
				b, err := repo.CatFile(ctx, sha, cf.Repo) // pinned commit; rejects symlinks/gitlinks
				if err != nil {
					return fmt.Errorf("service %q config file %q: %w", name, cf.Repo, err)
				}
				content = b
			} else {
				content = []byte(cf.Template)
			}
			dest := filepath.Join(rd, filepath.FromSlash(definition.ManagedConfigPath(name, i)))
			if !confinedUnder(dest, rd) {
				return fmt.Errorf("service %q config file path escapes the run dir", name)
			}
			if err := atomicWrite(dest, content, 0o640, rd); err != nil {
				return fmt.Errorf("service %q config file: %w", name, err)
			}
		}
		for _, sec := range svc.SecretFiles {
			if s.envStore == nil {
				return fmt.Errorf("service %q secret_files %q: secret store unavailable", name, sec)
			}
			val, ok, err := s.envStore.Reveal(project, sec)
			if err != nil {
				return fmt.Errorf("service %q secret_files %q: %w", name, sec, err)
			}
			if !ok {
				return fmt.Errorf("service %q secret_files %q: secret has no value — set it before deploying", name, sec)
			}
			dest := filepath.Join(rd, filepath.FromSlash(definition.ManagedSecretPath(name, sec)))
			if !confinedUnder(dest, rd) {
				return fmt.Errorf("service %q secret file path escapes the run dir", name)
			}
			if err := atomicWrite(dest, []byte(val), 0o600, rd); err != nil {
				return fmt.Errorf("service %q secret file: %w", name, err)
			}
		}
	}
	return nil
}

// ensureDockerignore guarantees the build context excludes Helmsman's managed dir
// (.helmsman/ holds rendered config + secret VALUES + the generated Dockerfile), so a
// `COPY . .` in a generated Dockerfile can never bake secrets into image layers. It
// merges with the repo's own .dockerignore if present.
func ensureDockerignore(rd string) error {
	p := filepath.Join(rd, ".dockerignore")
	var existing []byte
	if b, err := os.ReadFile(p); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSuffix(strings.TrimSpace(line), "/") == ".helmsman" {
				return nil // already excluded
			}
		}
		existing = b
	}
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString("# added by Helmsman — never send rendered config/secrets into the build context\n.helmsman/\n")
	return atomicWrite(p, buf.Bytes(), 0o644, rd)
}

// defBindSources is every run_dir-relative bind source declared across the stack's
// services (named volumes excluded — Docker manages those).
func defBindSources(def *definition.Definition) []string {
	var out []string
	for _, svc := range def.Spec.Compose.Services {
		for _, v := range svc.Volumes {
			if v.Source != "" && v.Name == "" {
				out = append(out, v.Source)
			}
		}
	}
	return out
}

// materializeBindDirs pre-creates each bind source as a Helmsman-owned directory under
// the run dir BEFORE `docker compose up`, so a missing bind isn't created by the Docker
// daemon as root. Each is confined under the run dir (symlink-safe); an existing path
// (file or dir) is left untouched.
func materializeBindDirs(rd string, binds []string) error {
	for _, src := range binds {
		if src == "" {
			continue
		}
		dest := filepath.Join(rd, filepath.FromSlash(src))
		// confinedUnder resolves symlinks, so a dest (or ancestor) pointing outside rd
		// is rejected here.
		if !confinedUnder(dest, rd) {
			return fmt.Errorf("bind source %q escapes the app directory", src)
		}
		if fi, err := os.Lstat(dest); err == nil {
			// A symlinked bind source could be swapped to escape rd — refuse it; a
			// regular file/dir is left untouched.
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("bind source %q is a symlink", src)
			}
			continue
		}
		// No ancestor may be a symlink BEFORE we create through it (no-follow), and we
		// re-check AFTER MkdirAll to fail closed on a symlink planted during the race.
		if err := noSymlinkComponents(dest, rd); err != nil {
			return fmt.Errorf("bind source %q: %w", src, err)
		}
		if err := os.MkdirAll(dest, 0o750); err != nil {
			return fmt.Errorf("create bind dir %q: %w", src, err)
		}
		if err := noSymlinkComponents(dest, rd); err != nil {
			return fmt.Errorf("bind source %q: %w", src, err)
		}
	}
	return nil
}

// defHasBuild reports whether any service builds from source (→ compose --build).
func defHasBuild(def *definition.Definition) bool {
	for _, svc := range def.Spec.Compose.Services {
		if svc.Build != nil {
			return true
		}
	}
	return false
}

// topLevelSet is the set of a repo's top-level file names (for stack detection).
func topLevelSet(files []string) map[string]bool {
	top := map[string]bool{}
	for _, f := range files {
		f = strings.TrimPrefix(f, "./")
		if f == "" || strings.Contains(f, "/") {
			continue // only top-level entries signal the stack
		}
		top[f] = true
	}
	return top
}
