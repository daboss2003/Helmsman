package serverinfo

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	// ErrNotFound is returned for an unknown root name or a missing path.
	ErrNotFound = errors.New("serverinfo: not found")
	// ErrDenied is returned for anything outside an allow-listed root, anything
	// under a denied prefix, or a traversal/symlink-escape attempt.
	ErrDenied = errors.New("serverinfo: denied")
	// ErrTooBig is returned when a file exceeds the read cap.
	ErrTooBig = errors.New("serverinfo: file too large to view")
)

// Root is one allow-listed directory the operator may browse, read-only.
type Root struct {
	Name string // stable key used in the UI + URL (e.g. "logs")
	Path string // absolute, symlink-resolved root directory
}

// Entry is one listed directory child.
type Entry struct {
	Name  string
	IsDir bool
	Size  uint64
	Mod   time.Time
}

// FileBrowser serves an allow-listed, read-only view of the filesystem. Two
// independent gates apply to EVERY path, after resolving symlinks on the final
// target: (1) it must stay within one declared root; (2) it must not fall under
// any denied prefix (secrets, keys, the DB, the config). The deny list wins.
type FileBrowser struct {
	roots []Root
	deny  []string // absolute, symlink-resolved denied prefixes
	// maxList bounds entries returned from one listing; maxRead bounds a file read.
	maxList int
	maxRead int64
}

// NewFileBrowser canonicalizes the given roots and denied prefixes (resolving
// symlinks so the containment checks compare real paths). Roots that don't exist
// or resolve under a denied prefix are dropped (fail-closed). With no usable
// roots the browser lists/reads nothing.
func NewFileBrowser(roots []Root, deny []string, maxList int, maxRead int64) *FileBrowser {
	b := &FileBrowser{maxList: maxList, maxRead: maxRead}
	for _, d := range deny {
		if abs, err := canon(d); err == nil {
			b.deny = append(b.deny, abs)
		} else if ap, err := filepath.Abs(d); err == nil {
			b.deny = append(b.deny, filepath.Clean(ap)) // keep even if it doesn't exist yet
		}
	}
	for _, r := range roots {
		real, err := canon(r.Path)
		if err != nil {
			continue // root missing/unreadable → drop (fail-closed)
		}
		if b.isDenied(real) {
			continue // an operator must never expose a secret dir as a root
		}
		b.roots = append(b.roots, Root{Name: r.Name, Path: real})
	}
	return b
}

// Roots returns the usable allow-listed roots (for the UI's root picker).
func (b *FileBrowser) Roots() []Root { return append([]Root(nil), b.roots...) }

// Enabled reports whether any root is browsable.
func (b *FileBrowser) Enabled() bool { return len(b.roots) > 0 }

// List returns the children of rel within the named root (rel "" = the root).
func (b *FileBrowser) List(rootName, rel string) ([]Entry, error) {
	real, _, err := b.resolve(rootName, rel)
	if err != nil {
		return nil, err
	}
	dirents, err := os.ReadDir(real)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(dirents))
	for _, de := range dirents {
		child := filepath.Join(real, de.Name())
		// Drop any child that resolves under a denied prefix (defense in depth so a
		// denied subtree never even appears in a listing). Symlinks are resolved.
		if rp, err := canon(child); err == nil && b.isDenied(rp) {
			continue
		} else if err != nil && b.isDenied(filepath.Clean(child)) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		e := Entry{Name: de.Name(), IsDir: de.IsDir(), Mod: info.ModTime()}
		if info.Mode().IsRegular() {
			e.Size = uint64(info.Size())
		}
		out = append(out, e)
		if len(out) >= b.maxList {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir // dirs first
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Read returns a regular file's contents, capped at maxRead. binary=true (with no
// content) when the file looks binary, so the UI can refuse to render it inline.
func (b *FileBrowser) Read(rootName, rel string) (content []byte, binary bool, err error) {
	real, _, err := b.resolve(rootName, rel)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Stat(real)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, ErrDenied // no devices/fifos/dirs
	}
	if info.Size() > b.maxRead {
		return nil, false, ErrTooBig
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, false, err
	}
	if looksBinary(data) {
		return nil, true, nil
	}
	return data, false, nil
}

// resolve maps (rootName, rel) to a real path and enforces both gates. It rejects
// absolute rel, NUL bytes, traversal that escapes the root, and any symlink whose
// target leaves the root or lands under a denied prefix. EvalSymlinks runs on the
// FINAL target so a symlinked leaf can't smuggle access.
func (b *FileBrowser) resolve(rootName, rel string) (string, *Root, error) {
	if strings.ContainsRune(rel, 0) || filepath.IsAbs(rel) {
		return "", nil, ErrDenied
	}
	var root *Root
	for i := range b.roots {
		if b.roots[i].Name == rootName {
			root = &b.roots[i]
			break
		}
	}
	if root == nil {
		return "", nil, ErrNotFound
	}
	joined := filepath.Join(root.Path, rel) // Clean collapses any ".." here
	real, err := canon(joined)
	if err != nil {
		return "", nil, ErrNotFound
	}
	if !underDir(real, root.Path) {
		return "", nil, ErrDenied // escaped the root (via .. or a symlink)
	}
	if b.isDenied(real) {
		return "", nil, ErrDenied
	}
	return real, root, nil
}

func (b *FileBrowser) isDenied(real string) bool {
	for _, d := range b.deny {
		if underDir(real, d) {
			return true
		}
	}
	return false
}

// canon returns the absolute, symlink-resolved form of p.
func canon(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// underDir reports whether p is dir itself or lives somewhere under dir. Both are
// expected to be clean absolute paths.
func underDir(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// looksBinary reports whether data appears to be non-text (a NUL byte in the first
// sniff window is the classic signal).
func looksBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}
