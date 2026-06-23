package web

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// /session/status reports liveness (204 authed, 401 not) WITHOUT advancing last_seen —
// so the focus-loss watchdog can poll it from an unfocused tab to observe the idle-out
// instead of postponing it. The route is auth-exempt and returns the status itself.
func TestSessionStatusEndpoint(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")

	// No cookie → 401 (and NOT a 302 to /login — a fetch must see the status).
	resp := e.req(t, "GET", "/session/status", "127.0.0.1:1", nil, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /session/status = %d, want 401", resp.StatusCode)
	}

	raw, err := e.srv.sessions.Create(context.Background(), "operator", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Minute).Unix()
	if _, err := e.srv.db.Exec(`UPDATE sessions SET last_seen_at = ?`, old); err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: e.srv.cookieName(), Value: raw}
	resp = e.req(t, "GET", "/session/status", "127.0.0.1:1", nil, []*http.Cookie{cookie}, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("authenticated /session/status = %d, want 204", resp.StatusCode)
	}
	// Crucial: probing must be NON-refreshing (the middleware Peeks this path).
	var after int64
	if err := e.srv.db.QueryRow(`SELECT last_seen_at FROM sessions`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != old {
		t.Errorf("/session/status advanced last_seen %d -> %d (must be non-refreshing)", old, after)
	}
}

// Guard the const-vs-literal split: the middleware special-cases sessionStatusPath, but
// the route in server.go is registered with a string literal (for the authz-posture AST
// check). They must stay equal.
func TestSessionStatusPathMatchesRoute(t *testing.T) {
	if sessionStatusPath != "/session/status" {
		t.Fatalf("sessionStatusPath = %q; must equal the literal route in server.go (%q)", sessionStatusPath, "/session/status")
	}
}
