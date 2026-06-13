package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/helmsman/helmsman/internal/ops"
)

// All operator-facing assets are embedded in the binary (plan §2): no asset
// pipeline, no node_modules. All rendering uses html/template (never
// text/template / template.HTML on external content — plan §15 lint).

//go:embed templates/*.html static/*
var embeddedAssets embed.FS

var templateFuncs = template.FuncMap{
	"humanBytes": humanBytes,
	"pct1":       func(f float64) string { return fmt.Sprintf("%.1f", f) },
	// pathEscape encodes an untrusted compose project name into a single safe
	// URL path segment (review #3/#10): '/' '?' '#' etc. become %-encoded so the
	// {project} route matches and r.PathValue decodes back to the exact value.
	"pathEscape": url.PathEscape,
	"unixTime":   func(ts int64) string { return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05Z") },
	// sparkPoints builds an SVG polyline "points" string from Helmsman-computed
	// health scores (0..1). The values are numeric (never app strings), so the
	// output is safe to embed in an html/template-escaped attribute.
	"sparkPoints": sparkPoints,
}

const sparkW, sparkH = 220.0, 32.0

func sparkPoints(pts []ops.SnapshotPoint) string {
	if len(pts) < 2 {
		return ""
	}
	var b strings.Builder
	last := float64(len(pts) - 1)
	for i, p := range pts {
		x := float64(i) / last * sparkW
		v := p.Value
		if v < 0 {
			v = 0
		} else if v > 1 {
			v = 1
		}
		y := (1 - v) * sparkH
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

func parseTemplates() (*template.Template, error) {
	return template.New("").Funcs(templateFuncs).ParseFS(embeddedAssets, "templates/*.html")
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
