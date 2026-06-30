package serverinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// build a root dir with a file and a secret-sibling dir, return (root, secretDir).
func fixture(t *testing.T) (root, secret string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "logs")
	secret = filepath.Join(base, "secrets")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.log"), []byte("hello log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "master.key"), []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, secret
}

func TestFileBrowserReadsWithinRoot(t *testing.T) {
	root, secret := fixture(t)
	b := NewFileBrowser([]Root{{Name: "logs", Path: root}}, []string{secret}, 1000, 1<<20)
	if !b.Enabled() {
		t.Fatal("browser should be enabled with a valid root")
	}
	data, bin, err := b.Read("logs", "app.log")
	if err != nil || bin || string(data) != "hello log\n" {
		t.Fatalf("read within root failed: data=%q bin=%v err=%v", data, bin, err)
	}
	ents, err := b.List("logs", "")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	if len(ents) == 0 {
		t.Fatal("expected entries in root")
	}
}

func TestFileBrowserBlocksTraversalAndSecrets(t *testing.T) {
	root, secret := fixture(t)
	b := NewFileBrowser([]Root{{Name: "logs", Path: root}}, []string{secret}, 1000, 1<<20)

	bad := []string{
		"../secrets/master.key", // traversal out of root
		"../../etc/passwd",      // deep traversal
		"/etc/passwd",           // absolute
		"sub/../../secrets/master.key",
	}
	for _, p := range bad {
		if _, _, err := b.Read("logs", p); err == nil {
			t.Errorf("Read(%q) should be denied, got nil error", p)
		}
		if _, err := b.List("logs", p); err == nil {
			t.Errorf("List(%q) should be denied, got nil error", p)
		}
	}
	// Unknown root name.
	if _, err := b.List("nope", ""); err == nil {
		t.Error("unknown root must be ErrNotFound")
	}
}

func TestFileBrowserSymlinkEscapeDenied(t *testing.T) {
	root, secret := fixture(t)
	// Plant a symlink INSIDE the root that points at the secret dir.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	b := NewFileBrowser([]Root{{Name: "logs", Path: root}}, []string{secret}, 1000, 1<<20)
	if _, _, err := b.Read("logs", "escape/master.key"); err == nil {
		t.Error("symlink escape to secret must be denied")
	}
	// The symlinked dir must not appear (or must be skipped) in a listing's traversal.
	if _, err := b.List("logs", "escape"); err == nil {
		t.Error("listing through an escaping symlink must be denied")
	}
}

func TestFileBrowserRootUnderDenyIsDropped(t *testing.T) {
	root, _ := fixture(t)
	// Declaring a root that is itself denied must yield no usable roots.
	b := NewFileBrowser([]Root{{Name: "logs", Path: root}}, []string{root}, 1000, 1<<20)
	if b.Enabled() {
		t.Error("a root that is under the deny list must be dropped (fail-closed)")
	}
}

func TestFileBrowserBinarySniff(t *testing.T) {
	root, secret := fixture(t)
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), []byte{1, 2, 0, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewFileBrowser([]Root{{Name: "logs", Path: root}}, []string{secret}, 1000, 1<<20)
	_, bin, err := b.Read("logs", "blob.bin")
	if err != nil || !bin {
		t.Fatalf("binary file should be flagged binary: bin=%v err=%v", bin, err)
	}
}
