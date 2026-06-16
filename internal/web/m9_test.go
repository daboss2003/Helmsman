package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/sandbox"
)

// reqUpload posts a single-file multipart form (with the CSRF token in the header so
// requireCSRF doesn't consume the multipart body).
func (e *testEnv) reqUpload(t *testing.T, path, peer, csrf, field, filename, content string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	r := httptest.NewRequest("POST", path, &buf)
	r.RemoteAddr = peer
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("X-CSRF-Token", csrf)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, r)
	return rec.Result()
}

// setupYAML builds a helmsman.yaml whose spec.setup is the script under test.
func setupYAML(slug, script, trigger string, produces ...string) string {
	q := make([]string, len(produces))
	for i, p := range produces {
		q[i] = strconv.Quote(p)
	}
	return "apiVersion: helmsman/v1\nkind: App\nmetadata: {slug: " + slug + "}\n" +
		"spec:\n  compose: {source: generated, services: {web: {image: nginx:1}}}\n" +
		"  setup: {script: " + strconv.Quote(script) + ", trigger: " + trigger + ", produces: [" + strings.Join(q, ", ") + "]}\n"
}

// Setup is DECLARED in helmsman.yaml and synced via upload; the page then shows it
// read-only and reports disabled (the default).
func TestSetupSyncAndGet(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}

	yaml := setupYAML("shop", "#!/bin/sh\necho hi\n", "on_demand", "env:TOKEN")
	resp := e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "helmsman.yaml", yaml, cookies)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sync = %d, want 303", resp.StatusCode)
	}
	ss, ok, _ := e.srv.setupStore.Get("shop")
	if !ok || ss.Trigger != "on_demand" || len(ss.Produces) != 1 {
		t.Fatalf("stored script wrong: %+v ok=%v", ss, ok)
	}
	body := readBody(e.req(t, "GET", "/apps/shop/setup", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(body, "Setup script") || !strings.Contains(strings.ToLower(body), "disabled") {
		t.Errorf("setup page missing/disabled-status: %.200s", body)
	}
}

// The synced script is shown read-only on the page (no editor).
func TestSetupScriptShownReadOnly(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	yaml := setupYAML("shop", "#!/bin/sh\necho hello-marker\n", "on_demand")
	if r := e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "helmsman.yaml", yaml, cookies); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("sync = %d, want 303", r.StatusCode)
	}
	body := readBody(e.req(t, "GET", "/apps/shop/setup", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(body, "hello-marker") || strings.Contains(body, "<textarea name=\"script\"") {
		t.Errorf("script must be shown read-only (no editor): %.300s", body)
	}
}

// auto_deploy + an auto setup trigger is a hard reject (plan §7).
func TestSetupRejectsAutoWithAutoDeploy(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", AutoDeploy: true,
	}); err != nil {
		t.Fatal(err)
	}
	yaml := setupYAML("shop", "echo hi", "on_first_deploy")
	resp := e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "helmsman.yaml", yaml, cookies)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("auto_deploy + on_first_deploy = %d, want 422", resp.StatusCode)
	}
}

func TestSetupSyncProtectedRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"edge"}
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	yaml := setupYAML("edge", "echo hi", "on_demand")
	resp := e.reqUpload(t, "/apps/edge/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "helmsman.yaml", yaml, cookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected setup sync = %d, want 403", resp.StatusCode)
	}
}

// Run is refused when setup is disabled (the default).
func TestSetupRunRefusedWhenDisabled(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	if err := e.srv.setupStore.Save(context.Background(), "shop", sandbox.ScriptSet{Script: "echo hi", Trigger: "on_demand"}, false); err != nil {
		t.Fatal(err)
	}
	resp := e.req(t, "POST", "/apps/shop/setup/run", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("run while disabled = %d, want 403", resp.StatusCode)
	}
}

// Even when enabled, a run without a valid confirm token (bound to the checksum)
// is refused — the confirmation gate stands on its own.
func TestSetupRunRefusedWithoutConfirmToken(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.Setup.Enabled = true
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	if err := e.srv.setupStore.Save(context.Background(), "shop", sandbox.ScriptSet{Script: "echo hi", Trigger: "on_demand"}, false); err != nil {
		t.Fatal(err)
	}
	resp := e.req(t, "POST", "/apps/shop/setup/run", "127.0.0.1:1", hdr, cookies,
		url.Values{"confirm_token": {"bogus"}, "confirm_app_id": {"shop"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("run with bogus confirm token = %d, want 403", resp.StatusCode)
	}
}

func TestConfirmStoreSingleUseBound(t *testing.T) {
	cs := newConfirmStore(time.Minute)
	tok := cs.mint("shop", "checksum-abc")
	// Wrong slug / wrong checksum never matches (and consumes).
	if cs.take(tok, "other", "checksum-abc") {
		t.Error("token matched the wrong slug")
	}
	if cs.take(tok, "shop", "checksum-abc") {
		t.Error("token survived a prior take (must be single-use)")
	}
	// Correct match, exactly once.
	tok2 := cs.mint("shop", "checksum-abc")
	if !cs.take(tok2, "shop", "checksum-abc") {
		t.Error("valid token rejected")
	}
	if cs.take(tok2, "shop", "checksum-abc") {
		t.Error("token reused")
	}
	// A changed checksum (script edit) voids a minted token.
	tok3 := cs.mint("shop", "checksum-abc")
	if cs.take(tok3, "shop", "checksum-XYZ") {
		t.Error("token matched a different checksum")
	}
}

// A hostile script that plants a SYMLINKED PARENT in scratch cannot exfiltrate a
// host file via a declared capture (canonicalize-then-confine).
func TestCaptureRejectsSymlinkedParent(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	scratch := t.TempDir()
	secretDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secretDir, "x"), []byte("HOSTSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Inside the jail this is `ln -s <secretDir> /work/certs`.
	if err := os.Symlink(secretDir, filepath.Join(scratch, "certs")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	ss := sandbox.ScriptSet{Script: "x", Trigger: "on_demand", Produces: []string{"file:certs/x"}}
	if _, err := e.srv.captureSetupOutputs(scratch, "shop", ss, "op"); err == nil {
		t.Fatal("capture through a symlinked parent must be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(e.srv.appRunDir("shop"), "certs", "x")); statErr == nil {
		t.Error("exfiltrated host file was written into the run dir")
	}
}

// A symlinked .helmsman.env must not be followed (no host-file read via env capture).
func TestCaptureEnvRejectsSymlink(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	scratch := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(outside, []byte("STOLEN=hostsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(scratch, ".helmsman.env")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	ss := sandbox.ScriptSet{Script: "x", Trigger: "on_demand", Produces: []string{"env:STOLEN"}}
	if _, err := e.srv.captureSetupOutputs(scratch, "shop", ss, "op"); err == nil {
		t.Error("symlinked env capture should be rejected")
	}
	if _, ok, _ := e.srv.envStore.Reveal("shop", "STOLEN"); ok {
		t.Error("host secret was captured via a symlinked env file")
	}
}

// Declared env captures are validated as hostile data; undeclared keys are ignored.
func TestCaptureEnvHostileDataAndDeclaredOnly(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	scratch := t.TempDir()

	// A value with a ${...} interpolation sequence is rejected.
	if err := os.WriteFile(filepath.Join(scratch, ".helmsman.env"), []byte("BAD=x${INJECT}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ssBad := sandbox.ScriptSet{Script: "x", Trigger: "on_demand", Produces: []string{"env:BAD"}}
	if _, err := e.srv.captureSetupOutputs(scratch, "shop", ssBad, "op"); err == nil {
		t.Error("hostile ${ env value should be rejected")
	}

	// A clean DECLARED key is captured as a secret; an undeclared key is ignored.
	if err := os.WriteFile(filepath.Join(scratch, ".helmsman.env"), []byte("TOKEN=abc123\nUNDECLARED=zzz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ssOK := sandbox.ScriptSet{Script: "x", Trigger: "on_demand", Produces: []string{"env:TOKEN"}}
	if _, err := e.srv.captureSetupOutputs(scratch, "shop", ssOK, "op"); err != nil {
		t.Fatalf("clean capture failed: %v", err)
	}
	if v, ok, _ := e.srv.envStore.Reveal("shop", "TOKEN"); !ok || v != "abc123" {
		t.Errorf("declared key not captured: %q ok=%v", v, ok)
	}
	if _, ok, _ := e.srv.envStore.Reveal("shop", "UNDECLARED"); ok {
		t.Error("undeclared key was captured")
	}
}

// On a non-Linux dev host the run fail-closes (sandbox unavailable) even past the
// confirm gate.
func TestSetupRunFailClosedOffLinux(t *testing.T) {
	if ok, _ := sandbox.Available(); ok {
		t.Skip("sandbox available (Linux)")
	}
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.Setup.Enabled = true
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	ss := sandbox.ScriptSet{Script: "echo hi", Trigger: "on_demand"}
	if err := e.srv.setupStore.Save(context.Background(), "shop", ss, false); err != nil {
		t.Fatal(err)
	}
	// Mint a valid confirm token bound to the real checksum.
	checksum := ss.Checksum(e.srv.setupLimits())
	tok := e.srv.setupConfirm.mint("shop", checksum)
	resp := e.req(t, "POST", "/apps/shop/setup/run", "127.0.0.1:1", hdr, cookies,
		url.Values{"confirm_token": {tok}, "confirm_app_id": {"shop"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("run on non-Linux = %d, want 503 (fail-closed)", resp.StatusCode)
	}
}
