package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
)

func TestDeriveSlug(t *testing.T) {
	ok := map[string]string{
		"MyApp":          "myapp",
		"my_app.v2":      "my-app-v2",
		"  Spaced Name ": "spaced-name",
		"weird!!chars":   "weirdchars",
		"--leading--":    "leading",
	}
	for in, want := range ok {
		if got := deriveSlug(in); got != want {
			t.Errorf("deriveSlug(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "123", "!!!", "-", "9to5"} {
		if got := deriveSlug(in); got != "" {
			t.Errorf("deriveSlug(%q) = %q, want empty (unusable)", in, got)
		}
	}
}

// The GitHub-picker chooser finalize: choosing a variant installs a read-only deploy
// key NAMED for that file's slug and saves the app pointing at the variant file with
// the SSH deploy key as its credential.
func TestGitHubChooseInstallsKeyAndSavesVariant(t *testing.T) {
	e := buildGitHubServer(t)

	var keyPath string
	var readOnly bool
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/keys") {
			keyPath = r.URL.Path
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			readOnly, _ = body["read_only"].(bool)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mock.Close()
	e.srv.githubClient = github.New(mock.Client(), mock.URL, mock.URL)
	if err := e.srv.gitStore.SaveGitHubConn(context.Background(), "octocat", "gho_token"); err != nil {
		t.Fatal(err)
	}

	sess, csrf := e.authed(t)
	handle := e.srv.discoFlash.put(&discoveryStash{
		github: true, ghOwner: "octocat", ghName: "app", ghBranch: "main",
		candidates: []discoveryCandidate{{Path: "mooring.prod.yaml", Slug: "app-prod", Label: "prod"}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.prod.yaml"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/apps/app-prod/git" {
		t.Fatalf("choose = %d loc=%q, want 303 /apps/app-prod/git", resp.StatusCode, resp.Header.Get("Location"))
	}
	if keyPath != "/repos/octocat/app/keys" || !readOnly {
		t.Errorf("deploy key not installed read-only on the repo: path=%q readOnly=%v", keyPath, readOnly)
	}
	cfg, ok, _ := e.srv.gitStore.Get("app-prod")
	if !ok || cfg.MooringFile != "mooring.prod.yaml" || cfg.CredKind != "ssh" || cfg.RepoURL != "git@github.com:octocat/app.git" {
		t.Errorf("app not saved with the variant + ssh deploy key: %+v ok=%v", cfg, ok)
	}
}

// Fail-closed: if the deploy-key title is already taken on the repo (GitHub 422 →
// ErrKeyExists), our freshly-minted key was NOT installed — so the connect must error
// (409) and NOT save an app whose credential can never fetch.
func TestGitHubChooseKeyConflictFailsClosed(t *testing.T) {
	e := buildGitHubServer(t)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity) // title already taken
	}))
	defer mock.Close()
	e.srv.githubClient = github.New(mock.Client(), mock.URL, mock.URL)
	if err := e.srv.gitStore.SaveGitHubConn(context.Background(), "octocat", "gho_token"); err != nil {
		t.Fatal(err)
	}
	sess, csrf := e.authed(t)
	handle := e.srv.discoFlash.put(&discoveryStash{
		github: true, ghOwner: "octocat", ghName: "app", ghBranch: "main",
		candidates: []discoveryCandidate{{Path: "mooring.yaml", Slug: "app-x", Label: "default"}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.yaml"}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("key-title conflict = %d, want 409", resp.StatusCode)
	}
	if _, ok, _ := e.srv.gitStore.Get("app-x"); ok {
		t.Error("an app must NOT be saved when its deploy key wasn't installed")
	}
}

// Choosing a GitHub variant whose slug already exists redirects to it and does NOT
// reinstall a key or overwrite the app.
func TestGitHubChooseExistingRedirects(t *testing.T) {
	e := buildGitHubServer(t)
	var keyCalls int
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyCalls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer mock.Close()
	e.srv.githubClient = github.New(mock.Client(), mock.URL, mock.URL)
	if err := e.srv.gitStore.SaveGitHubConn(context.Background(), "octocat", "gho_token"); err != nil {
		t.Fatal(err)
	}
	// Pre-existing app with the same slug, on a different repo.
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "app-prod", RepoURL: "git@github.com:octocat/ORIGINAL.git", Ref: "refs/heads/main", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}

	sess, csrf := e.authed(t)
	handle := e.srv.discoFlash.put(&discoveryStash{
		github: true, ghOwner: "octocat", ghName: "app", ghBranch: "main",
		candidates: []discoveryCandidate{{Path: "mooring.prod.yaml", Slug: "app-prod", Label: "prod", Exists: true}},
	})
	resp := e.req(t, "POST", "/git/choose", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "handle": {handle}, "path": {"mooring.prod.yaml"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/apps/app-prod/git" {
		t.Fatalf("existing = %d loc=%q, want 303 /apps/app-prod/git", resp.StatusCode, resp.Header.Get("Location"))
	}
	if keyCalls != 0 {
		t.Errorf("an existing slug must NOT trigger a deploy-key install, got %d calls", keyCalls)
	}
	cfg, _, _ := e.srv.gitStore.Get("app-prod")
	if cfg.RepoURL != "git@github.com:octocat/ORIGINAL.git" {
		t.Errorf("existing app overwritten: repo = %q", cfg.RepoURL)
	}
}
