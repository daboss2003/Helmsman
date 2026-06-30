package serverinfo

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// debRe matches ONLY a Mooring release .deb. The cleanup feature will never look
// at, list, or delete anything that doesn't match this exactly — so it can't be
// pointed at system packages or unrelated files even if deb_cache_dir is set to a
// busy directory.
var debRe = regexp.MustCompile(`^mooring_([0-9]+\.[0-9]+\.[0-9]+)_linux_(amd64|arm64)\.deb$`)

// ErrNotADeb is returned when a delete target isn't a recognized Mooring .deb.
var ErrNotADeb = errors.New("serverinfo: not a mooring .deb")

// ErrRunningDeb is returned when a delete target is the currently-running version.
var ErrRunningDeb = errors.New("serverinfo: refusing to delete the running version")

// Deb is one Mooring release package found in the configured cache dir.
type Deb struct {
	Name    string
	Version string
	Arch    string
	Size    uint64
	Mod     time.Time
	Running bool // version matches the running binary → never deletable
}

// normVersion drops a leading "v" so "v0.3.50" and "0.3.50" compare equal.
func normVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// ListDebs returns the Mooring .deb files directly inside dir (non-recursive),
// newest first, marking the one matching runningVersion as Running. A missing dir
// yields an empty list (not an error) — the feature is simply "nothing to clean".
func ListDebs(dir, runningVersion string) ([]Deb, error) {
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	run := normVersion(runningVersion)
	out := make([]Deb, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		m := debRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, Deb{
			Name:    e.Name(),
			Version: m[1],
			Arch:    m[2],
			Size:    uint64(info.Size()),
			Mod:     info.ModTime(),
			Running: run != "" && m[1] == run,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mod.After(out[j].Mod) })
	return out, nil
}

// DeleteDeb removes one Mooring .deb from dir. It is intentionally narrow: name
// must be a bare filename (no path separators) matching debRe exactly, must not be
// the running version, and the resolved file must be a regular file located
// directly in dir (re-checked after symlink resolution so a symlinked name can't
// escape). The web layer additionally gates this behind password+TOTP re-auth.
func DeleteDeb(dir, name, runningVersion string) error {
	if dir == "" {
		return ErrNotFound
	}
	if name != filepath.Base(name) || strings.ContainsRune(name, 0) {
		return ErrNotADeb
	}
	m := debRe.FindStringSubmatch(name)
	if m == nil {
		return ErrNotADeb
	}
	if normVersion(runningVersion) != "" && m[1] == normVersion(runningVersion) {
		return ErrRunningDeb
	}
	real, err := canon(filepath.Join(dir, name))
	if err != nil {
		return ErrNotFound
	}
	realDir, err := canon(dir)
	if err != nil {
		return ErrNotFound
	}
	// The file must sit DIRECTLY in dir (parent == dir) — not in a subdir reached
	// via a symlinked name.
	if filepath.Dir(real) != realDir {
		return ErrDenied
	}
	info, err := os.Lstat(real)
	if err != nil {
		return ErrNotFound
	}
	if !info.Mode().IsRegular() {
		return ErrDenied
	}
	return os.Remove(real)
}
