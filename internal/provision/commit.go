package provision

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daboss2003/mooring/internal/crypto"
)

// File is one artifact to write into the app run dir at commit (compose, an
// optional Dockerfile). RelPath is run_dir-relative and confined.
type File struct {
	RelPath string
	Data    []byte
	Mode    os.FileMode
}

// Commit writes files into a fresh 0700 staging dir under appsRoot, then promotes
// it to runDir via an atomic rename(2) — there is never a half-written app, and a
// crash leaves only a sweepable .staging-* dir (plan §7). appsRoot MUST be the
// parent of runDir on the SAME filesystem (rename(2) cannot cross filesystems).
// If runDir already exists it is atomically replaced (old moved aside, removed
// after the swap).
func Commit(appsRoot, runDir string, files []File) error {
	appsRoot = filepath.Clean(appsRoot)
	runDir = filepath.Clean(runDir)
	if filepath.Dir(runDir) != appsRoot {
		return fmt.Errorf("provision: run dir %q is not directly under apps root %q", runDir, appsRoot)
	}
	if err := os.MkdirAll(appsRoot, 0o700); err != nil {
		return err
	}
	staging := filepath.Join(appsRoot, stagingPrefix+crypto.RandomToken(9))
	if err := os.Mkdir(staging, 0o700); err != nil {
		return fmt.Errorf("provision: mkdir staging: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()

	for _, f := range files {
		if err := writeConfined(staging, f); err != nil {
			return err
		}
	}

	// Atomic promote. If the target exists, move it aside first so the final
	// rename(2) lands on a non-existent path (rename onto a non-empty dir fails).
	var aside string
	if _, err := os.Lstat(runDir); err == nil {
		aside = filepath.Join(appsRoot, oldPrefix+crypto.RandomToken(9))
		if err := os.Rename(runDir, aside); err != nil {
			return fmt.Errorf("provision: move existing app aside: %w", err)
		}
	}
	if err := os.Rename(staging, runDir); err != nil {
		if aside != "" {
			_ = os.Rename(aside, runDir) // best-effort rollback
		}
		return fmt.Errorf("provision: promote staging: %w", err)
	}
	committed = true
	if aside != "" {
		_ = os.RemoveAll(aside)
	}
	return nil
}

// writeConfined writes one file under staging, rejecting traversal/absolute/
// symlinked-parent paths (the RelPath is operator-influenced for Mode-2 binds).
func writeConfined(staging string, f File) error {
	clean := filepath.Clean(f.RelPath)
	if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return fmt.Errorf("provision: unsafe artifact path %q", f.RelPath)
	}
	dest := filepath.Join(staging, clean)
	rel, err := filepath.Rel(staging, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("provision: artifact path %q escapes the staging dir", f.RelPath)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o640
	}
	// O_EXCL: staging is freshly created, so no pre-existing file/symlink to follow.
	fd, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("provision: write %q: %w", clean, err)
	}
	if _, err := fd.Write(f.Data); err != nil {
		fd.Close()
		return err
	}
	return fd.Close()
}

const (
	stagingPrefix = ".staging-"
	oldPrefix     = ".old-"
)

// SweepStaging removes stale staging / aside directories left by an interrupted
// commit (plan §7: a boot-time sweep clears stale staging). It never touches a
// committed app dir.
func SweepStaging(appsRoot string) {
	entries, err := os.ReadDir(appsRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, stagingPrefix) || strings.HasPrefix(n, oldPrefix) {
			_ = os.RemoveAll(filepath.Join(appsRoot, n))
		}
	}
}
