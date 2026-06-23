package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/daboss2003/Helmsman/internal/provstore"
)

// The single-service "New app" provision FORM was retired: apps are now defined by a
// repo's helmsman.yaml. GET /apps/new redirects to the repo-connect flow.
func TestNewAppRedirectsToRepoConnect(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.authed(t)
	resp := e.req(t, "GET", "/apps/new", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("GET /apps/new = %d, want 303 redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/git/new" {
		t.Errorf("redirect Location = %q, want /git/new", loc)
	}
}

// seedLegacyProvisioned registers a legacy form-provisioned app directly (the commit
// handler is gone) so the deploy/delete lifecycle — which stays for legacy apps — can
// still be exercised.
func seedLegacyProvisioned(t *testing.T, e *testEnv, slug string) {
	t.Helper()
	if err := e.srv.provStore.Save(context.Background(), provstore.App{Slug: slug, Source: "generated", ComposePath: "docker-compose.yml", SpecJSON: `{"slug":"` + slug + `"}`}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.srv.appRunDir(slug), 0o700); err != nil {
		t.Fatal(err)
	}
}

// Deploy is a write-plane action; with no runner it is unavailable (503).
func TestProvisionDeployRequiresWritePlane(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	resp := e.req(t, "POST", "/apps/shop/provision-deploy", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("deploy without runner = %d, want 503", resp.StatusCode)
	}
}

// Delete removes the run dir and the registry row of a legacy provisioned app.
func TestProvisionDelete(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	seedLegacyProvisioned(t, e, "shop")

	if _, statErr := os.Stat(e.srv.appRunDir("shop")); statErr != nil {
		t.Fatal("run dir should exist after seed")
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

// The protected set can never be deployed/deleted through the provision lifecycle.
func TestProvisionDeleteProtectedRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"shop"}
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	resp := e.req(t, "POST", "/apps/shop/provision-delete", "127.0.0.1:1", hdr, cookies, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected delete = %d, want 403", resp.StatusCode)
	}
}
