package web

import (
	"fmt"
	"os"
	"path/filepath"
)

// evalExisting resolves symlinks on the longest existing prefix of p, rejoining
// the non-existing tail — so an existing symlink component is FOLLOWED before a
// confinement check (mirrors the compose validator; review #1/#9). A purely
// lexical check (filepath.Clean) misses a `run_dir/data -> /outside` symlink.
func evalExisting(p string) string {
	p = filepath.Clean(p)
	suffix := ""
	cur := p
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			if suffix == "" {
				return real
			}
			return filepath.Join(real, suffix)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		suffix = filepath.Join(filepath.Base(cur), suffix)
		cur = parent
	}
}

// confinedUnder reports whether dest stays within runDir AFTER symlink
// resolution of both.
func confinedUnder(dest, runDir string) bool {
	return pathUnder(evalExisting(filepath.Clean(dest)), evalExisting(filepath.Clean(runDir)))
}

// noSymlinkComponents refuses any existing ancestor of dest (down to, but not
// below, runDir) that is a symlink — a no-follow guard against a parent-symlink
// redirect planted between the confinement check and the write (TOCTOU).
func noSymlinkComponents(dest, runDir string) error {
	runDir = filepath.Clean(runDir)
	dir := filepath.Dir(filepath.Clean(dest))
	for {
		if !pathUnder(dir, runDir) || dir == runDir {
			return nil
		}
		if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}
