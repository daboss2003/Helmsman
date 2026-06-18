package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintQR(t *testing.T) {
	var buf bytes.Buffer
	url := "otpauth://totp/Helmsman:operator?secret=JBSWY3DPEHPK3PXP&issuer=Helmsman&algorithm=SHA1&digits=6&period=30"
	if err := printQR(&buf, url); err != nil {
		t.Fatalf("printQR: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "▀") {
		t.Error("output has no half-block glyphs")
	}
	if !strings.Contains(out, "\x1b[30;40m") {
		t.Error("no dark-on-dark module — the QR appears blank (encoding failed)")
	}
	if !strings.Contains(out, "\x1b[37;47m") {
		t.Error("no light-on-light module — the quiet zone is missing")
	}
	// Every character row must be the same module width (a square grid) and there must
	// be enough rows for a real QR — a regression that truncates would trip this.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 11 {
		t.Fatalf("QR has too few rows: %d", len(lines))
	}
	width := strings.Count(lines[0], "▀")
	for i, ln := range lines {
		if w := strings.Count(ln, "▀"); w != width {
			t.Fatalf("row %d width %d != %d (not square)", i, w, width)
		}
	}
	// The first and last character rows are the quiet zone → all light.
	for _, idx := range []int{0, len(lines) - 1} {
		if strings.Contains(lines[idx], "\x1b[30;40m") || strings.Contains(lines[idx], "\x1b[30;47m") {
			t.Errorf("quiet-zone row %d contains a dark module", idx)
		}
	}
}
