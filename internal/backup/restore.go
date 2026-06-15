package backup

import (
	"archive/tar"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// restore.go hardens the most dangerous step (plan §7.10 Tier 3): a restore archive
// is HOSTILE input. Every tar member is confined under a fresh staging dir
// (canonicalize-then-Rel), special files are rejected, and zip-bomb caps bound the
// decompressed size / member count so a malicious archive can't escape run_dir or
// OOM the box.

// ExtractLimits bounds a restore extraction (fail-closed defaults via Sane()).
type ExtractLimits struct {
	MaxTotalBytes  int64 // total decompressed bytes across all members
	MaxMemberBytes int64 // a single member's size
	MaxMembers     int   // number of members
}

// SaneLimits returns conservative defaults for an app-volume restore.
func SaneLimits() ExtractLimits {
	return ExtractLimits{MaxTotalBytes: 8 << 30, MaxMemberBytes: 4 << 30, MaxMembers: 200_000}
}

// FileWriter is how SafeExtract emits a confined file (injected so the caller owns
// the actual filesystem write / staging dir; tests use an in-memory sink).
type FileWriter interface {
	WriteFile(relPath string, mode int64, r io.Reader) error
	Mkdir(relPath string) error
}

// SafeExtract walks a tar stream, enforcing confinement + special-file rejection +
// the zip-bomb caps, and emits each confined member through w. It returns the first
// violation (fail-closed: a single bad member aborts the whole restore).
func SafeExtract(tr *tar.Reader, w FileWriter, lim ExtractLimits) error {
	var total int64
	members := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("backup: malformed tar: %w", err)
		}
		members++
		if lim.MaxMembers > 0 && members > lim.MaxMembers {
			return fmt.Errorf("backup: archive exceeds %d members (possible zip bomb)", lim.MaxMembers)
		}

		// Only regular files and directories — NEVER a symlink, hardlink, device,
		// FIFO, or char/block special (a symlink would redirect a later write outside
		// the staging dir; a device is a host-resource grab).
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeDir:
		default:
			return fmt.Errorf("backup: archive member %q has a forbidden type %q (only regular files/dirs allowed)", h.Name, string(h.Typeflag))
		}

		rel, err := confine(h.Name)
		if err != nil {
			return err
		}
		if rel == "." {
			continue // the archive's root entry ("./") — a no-op, not a real member
		}

		if h.Typeflag == tar.TypeDir {
			if err := w.Mkdir(rel); err != nil {
				return err
			}
			continue
		}
		if h.Size < 0 || (lim.MaxMemberBytes > 0 && h.Size > lim.MaxMemberBytes) {
			return fmt.Errorf("backup: member %q size %d exceeds the per-file cap", h.Name, h.Size)
		}
		total += h.Size
		if lim.MaxTotalBytes > 0 && total > lim.MaxTotalBytes {
			return fmt.Errorf("backup: archive exceeds the %d-byte total cap (possible zip bomb)", lim.MaxTotalBytes)
		}
		// Bound the actual read to the declared size — a member whose body exceeds its
		// header size can't blow past the cap. Strip setuid/setgid/sticky from the
		// archive-provided mode (a restored setuid file is a privilege-escalation
		// grab) — only permission bits survive.
		if err := w.WriteFile(rel, h.Mode&0o777, io.LimitReader(tr, h.Size)); err != nil {
			return err
		}
	}
}

// confine validates + normalizes a tar member name to a relative path that stays
// under the staging root (canonicalize-then-Rel; reject absolute, "..", NUL, and
// any path that escapes).
func confine(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("backup: member name contains NUL")
	}
	if name == "" {
		return "", fmt.Errorf("backup: empty member name")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("backup: member %q is an absolute path", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backup: member %q escapes the staging dir (traversal)", name)
	}
	// Defense in depth: Rel from "." must not climb out.
	rel, err := filepath.Rel(".", clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backup: member %q escapes the staging dir", name)
	}
	return rel, nil
}
