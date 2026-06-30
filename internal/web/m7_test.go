package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/monitor"
)

func insertEvt(t *testing.T, e *testEnv, ts int64, action, outcome, level string) {
	t.Helper()
	if _, err := e.srv.db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail) VALUES(?, 'op', '', ?, 't', ?, ?, '')`,
		ts, action, outcome, level); err != nil {
		t.Fatal(err)
	}
}

func TestEventsFilterAndPagination(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}

	// A security/deny row, plus enough info rows to force a second page.
	insertEvt(t, e, 1000, "allowlist_deny", "deny", "security")
	for i := 0; i < eventsPageSize; i++ {
		insertEvt(t, e, int64(2000+i), "poll", "ok", "info")
	}

	// Level filter: only the security row.
	sec := readBody(e.req(t, "GET", "/events?level=security", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(sec, "allowlist_deny") {
		t.Error("security filter dropped the security row")
	}
	if strings.Contains(sec, ">poll<") {
		t.Error("security filter leaked an info row")
	}

	// Outcome filter: deny only.
	deny := readBody(e.req(t, "GET", "/events?outcome=deny", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(deny, "allowlist_deny") {
		t.Error("deny filter dropped the deny row")
	}

	// Unfiltered first page is full → an "Older" link must appear.
	page1 := readBody(e.req(t, "GET", "/events", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page1, "Older") || !strings.Contains(page1, "before=") {
		t.Error("full first page should offer an Older link")
	}
}

func TestThemeOverlayServedAndFailClosed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")

	// No theme file yet → empty 200 text/css (fail-closed, never breaks the page).
	resp := e.req(t, "GET", "/static/theme.css", "127.0.0.1:1", nil, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("theme.css (missing) = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("theme.css content-type = %q", ct)
	}
	if body := readBody(resp); body != "" {
		t.Errorf("missing theme.css should be empty, got %q", body)
	}

	// Operator drops a theme.css in the data dir → it is served.
	css := ".tile{border:2px solid hotpink}"
	if err := os.WriteFile(filepath.Join(e.srv.cfg.DataDir, "theme.css"), []byte(css), 0o600); err != nil {
		t.Fatal(err)
	}
	resp2 := e.req(t, "GET", "/static/theme.css", "127.0.0.1:1", nil, nil, nil)
	if got := readBody(resp2); got != css {
		t.Errorf("theme.css body = %q, want %q", got, css)
	}
	if resp2.Header.Get("ETag") == "" {
		t.Error("served theme.css should carry an ETag")
	}
}

// A symlink planted at theme.css must NEVER be followed (it would be a file-read
// primitive); the handler serves an empty stylesheet instead of the target.
func TestThemeOverlayRejectsSymlink(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("TOPSECRET-do-not-serve"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.srv.cfg.DataDir, "theme.css")
	if err := os.Symlink(secretFile, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	body := readBody(e.req(t, "GET", "/static/theme.css", "127.0.0.1:1", nil, nil, nil))
	if strings.Contains(body, "TOPSECRET") {
		t.Fatal("theme.css followed a symlink and served the target file")
	}
	if body != "" {
		t.Errorf("symlinked theme.css should serve empty, got %q", body)
	}
}

func TestTileOrderPersistAndApply(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	resp := e.req(t, "POST", "/settings/tile-order", "127.0.0.1:1", hdr, cookies,
		url.Values{"order": {"shop,blog"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("tile-order = %d, want 204", resp.StatusCode)
	}

	// orderedApps applies the saved order; unknown saved names are ignored and a
	// new app (not in the order) is appended.
	snap := &monitor.Snapshot{Apps: []monitor.App{{Project: "blog"}, {Project: "shop"}, {Project: "wiki"}}}
	got := e.srv.orderedApps(snap)
	order := []string{got[0].Project, got[1].Project, got[2].Project}
	if order[0] != "shop" || order[1] != "blog" || order[2] != "wiki" {
		t.Errorf("orderedApps = %v, want [shop blog wiki]", order)
	}
}

// Protected/managed projects (the read-plane proxy) must never appear as operator
// app tiles; they belong in the read-only System section. orderedApps drops them and
// systemApps surfaces exactly them — even when a saved tile order names one.
func TestManagedProjectsPartitionedFromApps(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"mooring-socket-proxy"}

	snap := &monitor.Snapshot{Apps: []monitor.App{
		{Project: "blog"}, {Project: "mooring-socket-proxy"}, {Project: "shop"},
	}}

	// No saved order: managed infra is excluded from app tiles.
	apps := e.srv.orderedApps(snap)
	for _, a := range apps {
		if a.Project == "mooring-socket-proxy" {
			t.Fatalf("orderedApps leaked a protected project: %v", apps)
		}
	}
	if len(apps) != 2 {
		t.Fatalf("orderedApps = %d apps, want 2 (blog, shop)", len(apps))
	}

	// systemApps surfaces exactly the protected project.
	sys := e.srv.systemApps(snap)
	if len(sys) != 1 || sys[0].Project != "mooring-socket-proxy" {
		t.Fatalf("systemApps = %v, want [mooring-socket-proxy]", sys)
	}

	// Even if the saved order explicitly names the protected project, it stays out.
	if err := e.srv.setSetting(context.Background(), tileOrderKey, "mooring-socket-proxy,shop,blog"); err != nil {
		t.Fatal(err)
	}
	apps = e.srv.orderedApps(snap)
	if len(apps) != 2 || apps[0].Project != "shop" || apps[1].Project != "blog" {
		t.Fatalf("orderedApps with order = %v, want [shop blog] (proxy excluded)", apps)
	}
}

func TestTileOrderRejectsOversize(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	big := strings.Repeat("a", maxTileOrder+1)
	resp := e.req(t, "POST", "/settings/tile-order", "127.0.0.1:1", hdr, cookies,
		url.Values{"order": {big}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize tile-order = %d, want 413", resp.StatusCode)
	}
}
