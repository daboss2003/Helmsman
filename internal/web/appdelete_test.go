package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/crypto"
	"github.com/daboss2003/Helmsman/internal/dockerexec"
	"github.com/daboss2003/Helmsman/internal/envstore"
	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/secret"
)

// A correct password tears the app down completely: every per-app store row, the run
// dir, and the git object store (repo clone) are gone.
func TestAppDeleteFullTeardown(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	ctx := context.Background()
	slug := "shop"

	// Seed state across several subsystems + on-disk trees.
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.envStore.Save(ctx, slug, []envstore.Entry{{Key: "API_KEY", Value: secret.New("s3cr3t"), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	runDir := e.srv.appRunDir(slug)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(runDir, "docker-compose.yml"), []byte("services: {}\n"), 0o644)
	objDir := e.srv.gitObjectDir(slug)
	if err := os.MkdirAll(objDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Wrong password → 403, nothing deleted.
	resp := e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", hdr, cookies,
		url.Values{"csrf_token": {csrf.Value}, "password": {"not-the-password"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong password = %d, want 403", resp.StatusCode)
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); !ok {
		t.Fatal("a wrong password must NOT delete the app")
	}

	// Correct password → 303 home, everything gone.
	resp = e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", hdr, cookies,
		url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("delete = %d loc=%q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); ok {
		t.Error("git config not deleted")
	}
	if cur, _, _ := e.srv.envStore.Current(slug); len(cur) != 0 {
		t.Errorf("env/secrets not deleted: %d entries remain", len(cur))
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Errorf("run dir not removed: %v", err)
	}
	if _, err := os.Stat(objDir); !os.IsNotExist(err) {
		t.Errorf("git object store (repo) not removed: %v", err)
	}
}

// Protected (Helmsman-managed) projects can never be deleted.
func TestAppDeleteRejectsProtected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = append(e.srv.cfg.ProtectedProjects, "locked")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/locked/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("protected delete = %d, want 403", resp.StatusCode)
	}
}

// A delete for an unknown app is a 404 (after the password check passes).
func TestAppDeleteUnknownApp(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/ghost/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown app delete = %d, want 404", resp.StatusCode)
	}
}

// The teardown GATE: if the shared git/deploy lock is held (a deploy/fetch in flight)
// so the containers can't be stopped, the delete ABORTS — nothing is removed and the
// app stays intact (no orphaned containers/volumes, no false "deleted").
func TestAppDeleteGateAbortsWhenLockHeld(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "test") // non-nil → gate runs
	ctx := context.Background()
	slug := "shop"
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	// Hold the global git/deploy slot so the teardown can't acquire it.
	if err := e.srv.gitDeploy.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	defer e.srv.gitDeploy.Release()

	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	gateErr, errs := e.srv.teardownApp(bounded, slug)
	if gateErr == nil {
		t.Fatal("expected a gate abort while the lock is held")
	}
	if len(errs) != 0 {
		t.Errorf("a gate abort must not run any destructive step, got errs=%v", errs)
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); !ok {
		t.Error("the app must remain intact when the teardown gate aborts")
	}
}

// With 2FA enabled, deleting requires a TOTP code too: a correct password but no code
// is rejected and the app survives.
func TestAppDeleteRequiresTOTPWhenEnabled(t *testing.T) {
	secret, _ := crypto.GenerateTOTPSecret()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, secret)
	peer := "127.0.0.1:1"
	get := e.req(t, "GET", "/login", peer, nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	code, err := crypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	post := e.req(t, "POST", "/login", peer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf},
		url.Values{"username": {"operator"}, "password": {testPassword}, "totp": {code}, "csrf_token": {csrf.Value}})
	sess := cookieByName(post, e.srv.cookieName())
	if sess == nil {
		t.Fatal("login with TOTP failed")
	}
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	// Password correct, but no TOTP code → rejected, app intact.
	resp := e.req(t, "POST", "/apps/shop/delete", peer, map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without TOTP = %d, want 403", resp.StatusCode)
	}
	if _, ok, _ := e.srv.gitStore.Get("shop"); !ok {
		t.Error("app must survive a delete that lacked the required TOTP code")
	}
}
