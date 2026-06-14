package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func provForm(mode string, extra url.Values) url.Values {
	f := url.Values{"mode": {mode}}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

// Mode 1 validate returns a generated compose that passes §5.6.
func TestProvisionValidateMode1(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := provForm("generated", url.Values{
		"slug": {"shop"}, "image": {"nginx:1.27"}, "ports": {"8080"}, "publish": {"on"},
		"env": {"LOG_LEVEL=info"}, "restart": {"unless-stopped"}, "csrf_token": {csrf.Value},
	})
	body := readBody(e.req(t, "POST", "/apps/new/validate", "127.0.0.1:1", hdr, cookies, f))
	if !strings.Contains(body, "image: nginx:1.27") || !strings.Contains(body, "§5.6: OK") {
		t.Fatalf("validate preview wrong:\n%s", body)
	}
	if !strings.Contains(body, "127.0.0.1:8080:8080") {
		t.Errorf("expected loopback-bound publish:\n%s", body)
	}
}

// The generated compose binds publishes to loopback by default (a public publish
// requires the explicit ack); validate is a dry preview.
func TestProvisionValidateLoopbackDefault(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := provForm("generated", url.Values{
		"slug": {"shop"}, "image": {"nginx:1.27"}, "ports": {"8080"}, "publish": {"on"},
		"csrf_token": {csrf.Value},
	})
	body := readBody(e.req(t, "POST", "/apps/new/validate", "127.0.0.1:1", hdr, cookies, f))
	if !strings.Contains(body, "127.0.0.1:8080:8080") || !strings.Contains(body, "§5.6: OK") {
		t.Fatalf("validate preview wrong:\n%s", body)
	}
}

// Mode 1 commit writes the run dir atomically, registers the app, stores env
// literals, and redirects.
func TestProvisionCommitMode1(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := provForm("generated", url.Values{
		"slug": {"shop"}, "image": {"nginx:1.27"}, "ports": {"8080"}, "publish": {"on"},
		"env": {"LOG_LEVEL=info"}, "restart": {"unless-stopped"}, "csrf_token": {csrf.Value},
	})
	resp := e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("commit = %d, want 303", resp.StatusCode)
	}
	// Compose landed in the run dir.
	b, err := os.ReadFile(filepath.Join(e.srv.appRunDir("shop"), "docker-compose.yml"))
	if err != nil || !strings.Contains(string(b), "image: nginx:1.27") {
		t.Fatalf("compose not committed: %v %q", err, b)
	}
	// Registry row exists.
	if _, ok, _ := e.srv.provStore.Get("shop"); !ok {
		t.Error("provisioned app not registered")
	}
	// Env literal stored.
	if v, ok, _ := e.srv.envStore.Reveal("shop", "LOG_LEVEL"); !ok || v != "info" {
		t.Errorf("env literal not stored: %q ok=%v", v, ok)
	}
}

// An invalid image (no explicit tag) is rejected by the generator at commit and
// leaves no app — there is no raw-compose path to smuggle dangerous keys through.
func TestProvisionCommitInvalidImageRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := provForm("generated", url.Values{"slug": {"evil"}, "image": {"nginx"}, "csrf_token": {csrf.Value}})
	resp := e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("invalid image commit = %d, want 422", resp.StatusCode)
	}
	if _, statErr := os.Stat(e.srv.appRunDir("evil")); statErr == nil {
		t.Error("run dir created despite rejected commit")
	}
	if _, ok, _ := e.srv.provStore.Get("evil"); ok {
		t.Error("rejected app should not be registered")
	}
}

func TestProvisionCommitBadSlugRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	f := provForm("generated", url.Values{"slug": {"Bad Slug"}, "image": {"nginx:1.27"}, "csrf_token": {csrf.Value}})
	resp := e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("bad slug commit = %d, want 422", resp.StatusCode)
	}
}

// Deploy is a write-plane action; with no runner it is unavailable (503).
func TestProvisionDeployRequiresWritePlane(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	// Commit first so the app exists.
	f := provForm("generated", url.Values{"slug": {"shop"}, "image": {"nginx:1.27"}, "restart": {"no"}, "csrf_token": {csrf.Value}})
	e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)

	resp := e.req(t, "POST", "/apps/shop/provision-deploy", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("deploy without runner = %d, want 503", resp.StatusCode)
	}
}

// Delete removes the run dir and the registry row.
func TestProvisionDelete(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	f := provForm("generated", url.Values{"slug": {"shop"}, "image": {"nginx:1.27"}, "restart": {"no"}, "csrf_token": {csrf.Value}})
	e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)

	if _, statErr := os.Stat(e.srv.appRunDir("shop")); statErr != nil {
		t.Fatal("run dir should exist after commit")
	}
	resp := e.req(t, "POST", "/apps/shop/provision-delete", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", resp.StatusCode)
	}
	if _, statErr := os.Stat(e.srv.appRunDir("shop")); statErr == nil {
		t.Error("run dir should be removed after delete")
	}
	if _, ok, _ := e.srv.provStore.Get("shop"); ok {
		t.Error("registry row should be gone after delete")
	}
}

// The protected set can never be provisioned over.
func TestProvisionCommitProtectedRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"shop"}
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	f := provForm("generated", url.Values{"slug": {"shop"}, "image": {"nginx:1.27"}, "restart": {"no"}, "csrf_token": {csrf.Value}})
	resp := e.req(t, "POST", "/apps/new/commit", "127.0.0.1:1", hdr, cookies, f)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected commit = %d, want 403", resp.StatusCode)
	}
}
