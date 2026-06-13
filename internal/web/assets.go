package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/url"
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
