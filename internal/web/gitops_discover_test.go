package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/gitstore"
)

func TestMooringVariantLabel(t *testing.T) {
	cases := map[string]string{
		"mooring.yaml":         "default",
		"mooring.yml":          "default",
		"mooring.staging.yaml": "staging",
		"mooring.prod.yml":     "prod",
		"mooring.us-east.yaml": "us-east",
	}
	for in, want := range cases {
		if got := mooringVariantLabel(in); got != want {
			t.Errorf("mooringVariantLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortCandidatesDefaultFirst(t *testing.T) {
	c := []discoveryCandidate{
		{Path: "mooring.prod.yaml", Label: "prod"},
		{Path: "mooring.yaml", Label: "default"},
		{Path: "mooring.staging.yaml", Label: "staging"},
	}
	sortCandidates(c)
	if c[0].Label != "default" {
		t.Fatalf("default must sort first, got %q", c[0].Label)
	}
	if c[1].Label != "prod" || c[2].Label != "staging" {
		t.Errorf("rest must be alpha by label, got %q then %q", c[1].Label, c[2].Label)
	}
}

func TestDiscoveryFlashSingleUseAndExpiry(t *testing.T) {
	f := newDiscoveryFlash(time.Hour)
	h := f.put(&discoveryStash{repoURL: "https://x/y.git"})
	if _, ok := f.take(h); !ok {
		t.Fatal("first take must succeed")
	}
	if _, ok := f.take(h); ok {
		t.Error("second take must fail (single-use)")
	}

	// An expired entry is not returned.
	fe := newDiscoveryFlash(time.Hour)
	h2 := fe.put(&discoveryStash{repoURL: "https://x/y.git"})
	fe.mu.Lock()
	fe.m[h2].exp = time.Now().Add(-time.Minute)
	fe.mu.Unlock()
	if _, ok := fe.take(h2); ok {
		t.Error("expired entry must not be returned")
	}
}

// buildCandidates offers each distinct, valid slug once and skips the rest with a
// reason: a missing/invalid slug, or a duplicate of one an earlier file already claimed.
func TestBuildCandidatesDedupAndSkip(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	cands, skipped := e.srv.buildCandidates([]discoveredFile{
		{Path: "mooring.yaml", Slug: "app"},
		{Path: "mooring.staging.yaml", Slug: "app"}, // duplicate slug → skipped
		{Path: "mooring.broken.yaml", Slug: ""},     // invalid slug → skipped
		{Path: "mooring.prod.yaml", Slug: "app-prod"},
	})
	if len(cands) != 2 {
		t.Fatalf("creatable candidates = %d, want 2 (%+v)", len(cands), cands)
	}
	if cands[0].Label != "default" {
		t.Errorf("default must sort first, got %q", cands[0].Label)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %d, want 2 (%+v)", len(skipped), skipped)
	}
	for _, s := range skipped {
		if !s.Invalid || s.Reason == "" {
			t.Errorf("skipped candidate must be Invalid with a reason: %+v", s)
		}
	}
}

func TestPeekMetadata(t *testing.T) {
	slug, name := definition.PeekMetadata([]byte("apiVersion: mooring/v1\nkind: App\nmetadata:\n  slug: shop\n  name: My Shop\n"))
	if slug != "shop" || name != "My Shop" {
		t.Errorf("PeekMetadata = (%q, %q), want (shop, My Shop)", slug, name)
	}
	// Garbage / missing metadata yields empties, never a panic.
	if s, n := definition.PeekMetadata([]byte("not: yaml: [")); s != "" || n != "" {
		t.Errorf("PeekMetadata(garbage) = (%q, %q), want empties", s, n)
	}
}

// handleGitChoose only acts on a path that was in the stashed candidate allow-list —
// a forged/unknown path is rejected, never turned into a CatFile/app create.
func TestGitChooseRejectsUnknownPath(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	hdr := map[string]string{"Origin": "https://example.com"}
	handle := e.srv.discoFlash.put(&discoveryStash{
		repoURL:    "https://github.com/o/r.git",
		ref:        "refs/heads/main",
		candidates: []discoveryCandidate{{Path: "mooring.yaml", Slug: "newapp", Label: "default"}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", hdr, []*http.Cookie{sess, csrf},
		url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.evil.yaml"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown selection = %d, want 400", resp.StatusCode)
	}
}

// A valid choice for a brand-new slug creates the app and redirects to its git page.
func TestGitChooseCreatesNewApp(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	hdr := map[string]string{"Origin": "https://example.com"}
	handle := e.srv.discoFlash.put(&discoveryStash{
		repoURL:    "https://github.com/o/r.git",
		ref:        "refs/heads/main",
		candidates: []discoveryCandidate{{Path: "mooring.staging.yaml", Slug: "stg", Label: "staging"}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", hdr, []*http.Cookie{sess, csrf},
		url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.staging.yaml"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/apps/stg/git" {
		t.Fatalf("create = %d loc=%q, want 303 /apps/stg/git", resp.StatusCode, resp.Header.Get("Location"))
	}
	cfg, ok, _ := e.srv.gitStore.Get("stg")
	if !ok || cfg.MooringFile != "mooring.staging.yaml" || cfg.RepoURL != "https://github.com/o/r.git" {
		t.Errorf("app not created with the variant file: %+v ok=%v", cfg, ok)
	}
}

// Choosing a file whose slug already names an app REDIRECTS to it and must NOT
// overwrite that app's existing config (the anti-overwrite / anti-hijack guard).
func TestGitChooseExistingRedirectsWithoutOverwrite(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	hdr := map[string]string{"Origin": "https://example.com"}

	// Pre-existing app "taken" connected to the ORIGINAL repo.
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "taken", RepoURL: "https://github.com/o/ORIGINAL.git", Ref: "refs/heads/main", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	handle := e.srv.discoFlash.put(&discoveryStash{
		repoURL:    "https://github.com/o/ATTACKER.git",
		ref:        "refs/heads/main",
		candidates: []discoveryCandidate{{Path: "mooring.yaml", Slug: "taken", Label: "default", Exists: true}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", hdr, []*http.Cookie{sess, csrf},
		url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.yaml"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/apps/taken/git" {
		t.Fatalf("existing = %d loc=%q, want 303 /apps/taken/git", resp.StatusCode, resp.Header.Get("Location"))
	}
	cfg, _, _ := e.srv.gitStore.Get("taken")
	if cfg.RepoURL != "https://github.com/o/ORIGINAL.git" {
		t.Errorf("existing app was OVERWRITTEN: repo = %q, want the ORIGINAL", cfg.RepoURL)
	}
}
