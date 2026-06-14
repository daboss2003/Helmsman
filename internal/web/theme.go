package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// maxThemeBytes caps the operator theme overlay so a huge file can't be buffered
// or shipped to every page (review: bounded operator-supplied asset).
const maxThemeBytes = 256 << 10

// handleThemeCSS serves an OPTIONAL operator-provided CSS overlay from a FIXED
// path (DataDir/theme.css) — never a user-influenced path, so there is no
// traversal surface. It is the safe half of "customizability": CSS only (no
// script; the CSP is style-src 'self'), served same-origin. Missing/oversized/
// unreadable → an empty stylesheet (fail-closed: customization can degrade, the
// admin plane never breaks). It is read fresh each request so an SSH edit shows
// up immediately (an ETag lets the browser skip the body when unchanged).
func (s *Server) handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache") // always revalidate via ETag

	if s.cfg.DataDir == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	path := filepath.Join(s.cfg.DataDir, "theme.css")
	// Open with O_NOFOLLOW so a symlink at theme.css is never followed — serving
	// the target of a planted symlink as CSS would be a file-read primitive. We
	// then fstat the OPEN descriptor (not the path) so the regular-file + size
	// checks apply to exactly the bytes we read, closing the TOCTOU window a
	// stat-then-read would leave (review finding).
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		w.WriteHeader(http.StatusOK) // missing / symlink / unreadable → empty
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxThemeBytes {
		w.WriteHeader(http.StatusOK)
		return
	}
	etag := fmt.Sprintf(`"%x-%x"`, fi.ModTime().UnixNano(), fi.Size())
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	// Bounded read off the same descriptor (defense-in-depth vs a post-stat grow).
	data, err := io.ReadAll(io.LimitReader(f, maxThemeBytes))
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(data)
}
