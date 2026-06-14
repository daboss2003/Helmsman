package opsclient

import (
	"strings"
	"testing"
)

// §15 Phase-3 fuzzing of the relative-path grammar — the descriptor-supplied path
// is attacker-influenced (class C), so ValidateRelPath is load-bearing for "the
// descriptor cannot move the outbound host". The invariant: anything it ACCEPTS is
// a single-slash-rooted, traversal-free, authority-free path.
func FuzzValidateRelPath(f *testing.F) {
	for _, s := range []string{
		"", "/", "/health", "/a/b/c", "//evil.com", "/../etc/passwd",
		"/a/../../b", "http://x", "/x?y=1", "/%2e%2e/", "\x00", strings.Repeat("/a", 200),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if !ValidateRelPath(p) {
			return
		}
		// Accepted ⇒ the grammar guarantees:
		if !strings.HasPrefix(p, "/") {
			t.Errorf("accepted %q without a leading slash", p)
		}
		if strings.HasPrefix(p, "//") {
			t.Errorf("accepted protocol-relative authority %q", p)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				t.Errorf("accepted a traversal segment in %q", p)
			}
		}
		if strings.ContainsAny(p, "?#") || strings.Contains(p, "://") {
			t.Errorf("accepted a non-path construct in %q", p)
		}
	})
}
