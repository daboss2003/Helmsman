package main

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// printQR renders s as a scannable QR code to w using Unicode upper-half blocks
// (▀) with EXPLICIT black/white ANSI colors, so it reads correctly on any terminal
// theme (light or dark) rather than depending on the default fg/bg. Each character
// row encodes two QR module rows — the glyph's foreground is the top module, its
// background the bottom — which keeps the code compact enough to fit an 80-column
// terminal. A 4-module "quiet zone" border is added so scanners lock on.
//
// It is the offline `gen-totp` convenience only (run over SSH); a render failure is
// non-fatal — the caller still prints the otpauth URL + secret for manual entry.
func printQR(w io.Writer, s string) error {
	code, err := qr.Encode(s, qr.M)
	if err != nil {
		return err
	}
	const quiet = 4 // modules of light border the spec requires for reliable scanning
	size := code.Size
	// dark reports whether module (x,y) is dark; anything in the quiet-zone border
	// (or past the grid on a final odd row) is light.
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		if x < 0 || y < 0 || x >= size || y >= size {
			return false
		}
		return code.Black(x, y)
	}
	total := size + 2*quiet
	var b strings.Builder
	for y := 0; y < total; y += 2 {
		for x := 0; x < total; x++ {
			fg := "37" // white (light module) for the TOP half
			if dark(x, y) {
				fg = "30" // black (dark module)
			}
			bg := "47" // white for the BOTTOM half
			if dark(x, y+1) {
				bg = "40" // black
			}
			fmt.Fprintf(&b, "\x1b[%s;%sm▀", fg, bg)
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
