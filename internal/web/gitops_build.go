package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
				Services: []definition.Service{{Name: "app", Build: &definition.Build{Language: b.Name()}}},
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
	var top map[string]bool
	for _, svc := range def.Spec.Compose.Services {
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
		dockerfile, err := builder.Generate(buildSpecFor(svc), top)
		if err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		dest := filepath.Join(rd, filepath.FromSlash(builder.DockerfilePath(svc.Name)))
		if !confinedUnder(dest, rd) {
			return fmt.Errorf("service %q: generated Dockerfile path escapes the run dir", svc.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return err
		}
		if noSymlinkComponents(dest, rd) != nil {
			return fmt.Errorf("service %q: generated Dockerfile path crosses a symlink", svc.Name)
		}
		if err := os.WriteFile(dest, []byte(dockerfile), 0o644); err != nil {
			return fmt.Errorf("service %q: write Dockerfile: %w", svc.Name, err)
		}
		onLine("generated Dockerfile for " + svc.Name)
	}
	return nil
}

// buildSpecFor projects a definition build onto the builder spec (non-root defaults on).
func buildSpecFor(svc definition.Service) builder.Spec {
	b := svc.Build
	nonroot := true
	if b.Nonroot != nil {
		nonroot = *b.Nonroot
	}
	return builder.Spec{
		Service:  svc.Name,
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
