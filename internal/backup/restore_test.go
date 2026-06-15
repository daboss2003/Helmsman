package backup

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
)

// memFS records confined writes for assertion.
type memFS struct {
	files map[string][]byte
	dirs  []string
}

func newMemFS() *memFS { return &memFS{files: map[string][]byte{}} }
func (m *memFS) WriteFile(rel string, _ int64, r io.Reader) error {
	b, _ := io.ReadAll(r)
	m.files[rel] = b
	return nil
}
func (m *memFS) Mkdir(rel string) error { m.dirs = append(m.dirs, rel); return nil }

// buildTar makes a tar from members (name→body); a nil body + trailing "/" = dir.
func buildTar(t *testing.T, members []tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range members {
		hh := h
		if hh.Typeflag == tar.TypeReg {
			hh.Size = int64(len(bodies[h.Name]))
		}
		if err := tw.WriteHeader(&hh); err != nil {
			t.Fatal(err)
		}
		if hh.Typeflag == tar.TypeReg {
			tw.Write([]byte(bodies[h.Name]))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func extract(t *testing.T, tarBytes []byte, lim ExtractLimits) (*memFS, error) {
	t.Helper()
	fs := newMemFS()
	err := SafeExtract(tar.NewReader(bytes.NewReader(tarBytes)), fs, lim)
	return fs, err
}

func TestSafeExtractHappyPath(t *testing.T) {
	b := buildTar(t, []tar.Header{
		{Name: "data/", Typeflag: tar.TypeDir},
		{Name: "data/file.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"data/file.txt": "hello"})
	fs, err := extract(t, b, SaneLimits())
	if err != nil {
		t.Fatal(err)
	}
	if string(fs.files["data/file.txt"]) != "hello" {
		t.Errorf("file not extracted: %v", fs.files)
	}
}

func TestSafeExtractRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../escape", "../../etc/passwd", "/etc/passwd", "a/../../b"} {
		b := buildTar(t, []tar.Header{{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}}, map[string]string{name: "x"})
		if _, err := extract(t, b, SaneLimits()); err == nil {
			t.Errorf("traversal/absolute %q must be rejected", name)
		}
	}
}

func TestSafeExtractRejectsSpecialFiles(t *testing.T) {
	cases := map[string]byte{
		"symlink":  tar.TypeSymlink,
		"hardlink": tar.TypeLink,
		"device":   tar.TypeBlock,
		"char":     tar.TypeChar,
		"fifo":     tar.TypeFifo,
	}
	for name, typ := range cases {
		h := tar.Header{Name: name, Typeflag: typ, Linkname: "/etc/passwd"}
		b := buildTar(t, []tar.Header{h}, nil)
		if _, err := extract(t, b, SaneLimits()); err == nil {
			t.Errorf("%s member must be rejected", name)
		}
	}
}

func TestSafeExtractZipBombCaps(t *testing.T) {
	// Total-bytes cap.
	big := buildTar(t, []tar.Header{{Name: "big", Typeflag: tar.TypeReg}}, map[string]string{"big": strings.Repeat("x", 5000)})
	if _, err := extract(t, big, ExtractLimits{MaxTotalBytes: 1000, MaxMemberBytes: 1 << 30, MaxMembers: 10}); err == nil {
		t.Error("exceeding the total-bytes cap must be rejected")
	}
	// Member-count cap.
	var hdrs []tar.Header
	bodies := map[string]string{}
	for i := 0; i < 50; i++ {
		n := "f" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		hdrs = append(hdrs, tar.Header{Name: n, Typeflag: tar.TypeReg})
		bodies[n] = "y"
	}
	many := buildTar(t, hdrs, bodies)
	if _, err := extract(t, many, ExtractLimits{MaxTotalBytes: 1 << 30, MaxMemberBytes: 1 << 30, MaxMembers: 10}); err == nil {
		t.Error("exceeding the member-count cap must be rejected")
	}
}

func TestSafeExtractMemberSizeCap(t *testing.T) {
	b := buildTar(t, []tar.Header{{Name: "f", Typeflag: tar.TypeReg}}, map[string]string{"f": strings.Repeat("z", 2000)})
	if _, err := extract(t, b, ExtractLimits{MaxTotalBytes: 1 << 30, MaxMemberBytes: 1000, MaxMembers: 10}); err == nil {
		t.Error("a member exceeding the per-file cap must be rejected")
	}
}
