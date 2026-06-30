// Package serverinfo backs the read-only "Server" tab: it sizes Mooring's own
// on-disk footprint, lists release artifacts for cleanup, and serves an
// allow-listed, read-only file view. Everything here is deliberately bounded and
// fail-closed — it is a LOOK-but-don't-break tool. The only mutation any of it
// performs is deleting an OLD downloaded mooring *.deb (DebManager), which the
// web layer gates behind password+TOTP re-auth.
package serverinfo

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"time"
)

// Usage is the size + entry count of one directory subtree.
type Usage struct {
	Label string // human label, e.g. "App run dirs"
	Path  string // the directory measured
	Bytes uint64 // total size of regular files in the subtree
	Files int    // number of regular files counted
}

// Footprint is Mooring's measured on-disk usage, grouped by purpose, plus the
// wall-clock time the measurement took (so the UI can warn if it's getting slow).
type Footprint struct {
	At      time.Time
	Groups  []Usage
	Total   uint64
	Files   int
	Partial bool // a group's walk hit the budget/timeout and may undercount
}

// Target names a directory to size and the label to show for it.
type Target struct {
	Label string
	Path  string
}

// MeasureFootprint sizes each target subtree. It is intended to run on the slow
// monitor cadence (NOT per request) because a WalkDir over large git stores can
// be slow; a per-target deadline (derived from ctx) keeps one huge tree from
// stalling the whole measurement. Missing directories contribute zero (not an
// error) — Mooring creates them lazily. A walk that trips the context budget
// marks the result Partial rather than failing.
func MeasureFootprint(ctx context.Context, targets []Target) Footprint {
	fp := Footprint{At: time.Now()}
	for _, t := range targets {
		if t.Path == "" {
			continue
		}
		bytes, files, partial := dirSize(ctx, t.Path)
		fp.Groups = append(fp.Groups, Usage{Label: t.Label, Path: t.Path, Bytes: bytes, Files: files})
		fp.Total += bytes
		fp.Files += files
		if partial {
			fp.Partial = true
		}
	}
	sort.SliceStable(fp.Groups, func(i, j int) bool { return fp.Groups[i].Bytes > fp.Groups[j].Bytes })
	return fp
}

// dirSize sums the sizes of regular files under root. Symlinks are NOT followed
// (WalkDir does not follow them), so it can't be lured outside root or into a
// cycle. It checks ctx between entries so a cancelled/expired context stops the
// walk and reports partial=true.
func dirSize(ctx context.Context, root string) (bytes uint64, files int, partial bool) {
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, never abort the whole walk
		}
		if ctx.Err() != nil {
			partial = true
			return filepath.SkipAll
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			bytes += uint64(info.Size())
			files++
		}
		return nil
	})
	return bytes, files, partial
}
