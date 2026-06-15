package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daboss2003/Helmsman/internal/monitor"
	"github.com/daboss2003/Helmsman/internal/ops"
)

// These tests execute the M3 templates directly so a template bug (bad variable
// scoping, a missing func) fails deterministically without needing a live app.

func TestAppDetailTemplateRendersRich(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	app := &monitor.App{
		Project:     "shop",
		DisplayName: "shop",
		Services:    []monitor.ServiceStatus{{Service: "web", State: "running", Health: "healthy"}},
		Ops: &ops.Result{
			Mode:         ops.RICH,
			Version:      "1.0",
			Capabilities: []string{"health", "queues"},
			Indicators: []ops.Indicator{
				{Name: "db", Status: "up", Source: "ops.v1"},
				{Name: "cache", Status: "down", Message: "timeout", Source: "ops.v1"},
			},
			Queues:   []ops.Queue{{Name: "emails", IsPaused: true, Counts: []ops.QueueCount{{Name: "waiting", Value: 3}}}},
			Snapshot: []ops.SnapshotPoint{{At: 1, Value: 1}, {At: 2, Value: 0.5}, {At: 3, Value: 1}},
		},
	}
	var buf bytes.Buffer
	if err := e.srv.templates.ExecuteTemplate(&buf, "appdetail", tmplData{App: app, CSRFToken: "tok123"}); err != nil {
		t.Fatalf("appdetail template error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"RICH", "db", "cache", "timeout", "ind-up", "ind-down",
		"<polyline", "emails", "/apps/shop/queues/emails/pause", "tok123",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered RICH appdetail missing %q", want)
		}
	}
}

func TestOpsConfigTemplateRenders(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	cfg := &ops.Config{Project: "shop", Enabled: true, BaseURL: "http://web:8080", SecretHeader: "X-Ops-Secret", HasSecret: true, OpsMode: "auto", Adapter: "ops.v1"}
	var buf bytes.Buffer
	if err := e.srv.templates.ExecuteTemplate(&buf, "ops_config.html", tmplData{Title: "x", Project: "shop", CSRFToken: "tok", OpsCfg: cfg}); err != nil {
		t.Fatalf("ops_config template error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"http://web:8080", "X-Ops-Secret", "leave blank to keep", "Clear the stored secret", `name="csrf_token"`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ops_config missing %q", want)
		}
	}
	// The plaintext secret must never appear in the form.
	if strings.Contains(out, "super-secret") {
		t.Error("secret leaked into the form")
	}
}
