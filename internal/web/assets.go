package web

import (
	"embed"
	"html/template"
)

// All operator-facing assets are embedded in the binary (plan §2): no asset
// pipeline, no node_modules. All rendering uses html/template (never
// text/template / template.HTML on external content — plan §15 lint).

//go:embed templates/*.html static/*
var embeddedAssets embed.FS

func parseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(embeddedAssets, "templates/*.html")
}
