package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/daboss2003/Helmsman/internal/backupstore"
)

// withBackups attaches an enabled backup store (same package, so we can set the
// unexported field) keyed with the test's 32-zero master key.
func withBackups(t *testing.T, e *testEnv) {
	t.Helper()
	e.srv.backups = backupstore.New(e.srv.db, t.TempDir(), make([]byte, 32))
	if !e.srv.backups.Available() {
		t.Fatal("backup store should be available")
	}
}

func TestBackupsScreenCreateListDelete(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	withBackups(t, e)
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")

	// Empty state renders with the "Back up now" action (feature enabled).
	get := e.req(t, "GET", "/settings/backups", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings/backups = %d", get.StatusCode)
	}
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie on the backups page")
	}
	if !strings.Contains(readBody(get), "Back up now") {
		t.Error("enabled backups screen should show the create action")
	}

	// Create a backup via the real handler.
	post := e.req(t, "POST", "/settings/backups/create", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf},
		map[string][]string{"csrf_token": {csrf.Value}})
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("create = %d, want 303", post.StatusCode)
	}
	recs, _ := e.srv.backups.List(context.Background())
	if len(recs) != 1 {
		t.Fatalf("expected 1 backup after create, got %d", len(recs))
	}
	id := recs[0].ID

	// It shows on the page with a download link.
	body := readBody(e.req(t, "GET", "/settings/backups", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil))
	if !strings.Contains(body, "/settings/backups/download?id="+id) {
		t.Error("created backup should appear with a download link")
	}

	// Download streams the (encrypted) archive.
	dl := e.req(t, "GET", "/settings/backups/download?id="+id, "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if dl.StatusCode != http.StatusOK || !strings.Contains(dl.Header.Get("Content-Disposition"), id) {
		t.Errorf("download = %d, disp %q", dl.StatusCode, dl.Header.Get("Content-Disposition"))
	}

	// Delete via the real handler.
	del := e.req(t, "POST", "/settings/backups/delete", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf},
		map[string][]string{"csrf_token": {csrf.Value}, "id": {id}})
	if del.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", del.StatusCode)
	}
	if recs, _ := e.srv.backups.List(context.Background()); len(recs) != 0 {
		t.Error("backup still listed after delete")
	}
}
