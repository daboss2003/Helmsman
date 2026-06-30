package serverinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("deb"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestListAndDeleteDebs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"mooring_0.3.48_linux_amd64.deb",
		"mooring_0.3.49_linux_amd64.deb",
		"mooring_0.3.50_linux_amd64.deb",
		"mooring_0.3.50_linux_arm64.deb",
		"notmooring_1.0_linux_amd64.deb", // must be ignored
		"mooring_0.3.50_linux_amd64.txt", // must be ignored
		"random.tar.gz",                  // must be ignored
	} {
		writeFile(t, filepath.Join(dir, n))
	}

	debs, err := ListDebs(dir, "v0.3.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(debs) != 4 {
		t.Fatalf("expected 4 mooring debs, got %d: %+v", len(debs), debs)
	}
	running := 0
	for _, d := range debs {
		if d.Running {
			running++
			if d.Version != "0.3.50" {
				t.Errorf("running marked on wrong version %s", d.Version)
			}
		}
	}
	if running != 2 { // both arches of 0.3.50
		t.Errorf("expected 2 debs marked running (0.3.50 amd64+arm64), got %d", running)
	}

	// Deleting the running version is refused.
	if err := DeleteDeb(dir, "mooring_0.3.50_linux_amd64.deb", "0.3.50"); err != ErrRunningDeb {
		t.Errorf("deleting running version should be ErrRunningDeb, got %v", err)
	}
	// Deleting an OLD version works.
	if err := DeleteDeb(dir, "mooring_0.3.48_linux_amd64.deb", "0.3.50"); err != nil {
		t.Errorf("deleting old deb should succeed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mooring_0.3.48_linux_amd64.deb")); !os.IsNotExist(err) {
		t.Error("old deb should be gone")
	}
}

func TestDeleteDebRejectsNonDebAndTraversal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mooring_0.3.49_linux_amd64.deb"))
	// A real secret-ish sibling we must never reach.
	outside := filepath.Join(filepath.Dir(dir), "passwd")
	writeFile(t, outside)

	bad := map[string]error{
		"notmooring_1.0_linux_amd64.deb":     ErrNotADeb,
		"mooring_0.3.49_linux_amd64.txt":     ErrNotADeb,
		"../passwd":                          ErrNotADeb, // has separator → rejected before glob
		"sub/mooring_0.3.49_linux_amd64.deb": ErrNotADeb,
		"mooring_0.3.49_linux_riscv.deb":     ErrNotADeb, // unsupported arch
	}
	for name, want := range bad {
		if err := DeleteDeb(dir, name, "0.3.50"); err != want {
			t.Errorf("DeleteDeb(%q) = %v, want %v", name, err, want)
		}
	}
	// The real deb is still there (nothing above deleted it).
	if _, err := os.Stat(filepath.Join(dir, "mooring_0.3.49_linux_amd64.deb")); err != nil {
		t.Errorf("legit deb should be untouched: %v", err)
	}
}

func TestListDebsMissingDir(t *testing.T) {
	debs, err := ListDebs(filepath.Join(t.TempDir(), "nope"), "0.3.50")
	if err != nil || debs != nil {
		t.Errorf("missing dir should be (nil,nil), got %+v %v", debs, err)
	}
	if debs, err := ListDebs("", "0.3.50"); err != nil || debs != nil {
		t.Errorf("empty dir should be (nil,nil), got %+v %v", debs, err)
	}
}
