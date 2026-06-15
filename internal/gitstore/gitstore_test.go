package gitstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, cipher)
}

func TestSaveGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tok := "ghp_exampletoken"
	if err := s.Save(ctx, SaveInput{
		Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never", AutoDeploy: true,
		NewCred: &tok, CredKind: "token",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := s.Get("shop")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if cfg.RepoURL != "https://github.com/o/r.git" || cfg.Ref != "refs/heads/main" || !cfg.AutoDeploy || cfg.CredKind != "token" {
		t.Errorf("round-trip mismatch: %+v", cfg)
	}
	// Credentials decrypt back to the original token.
	creds, err := s.Creds("shop")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Token != tok {
		t.Errorf("token = %q, want %q", creds.Token, tok)
	}
}

func TestCredTriStateKeepAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tok := "tok-1"
	must := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: &tok, CredKind: "token"}))

	// Edit with NewCred nil → keep the stored token.
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r2.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: nil}))
	creds, _ := s.Creds("app")
	if creds.Token != tok {
		t.Errorf("keep: token = %q, want %q", creds.Token, tok)
	}
	cfg, _, _ := s.Get("app")
	if cfg.CredKind != "token" {
		t.Errorf("keep: cred_kind = %q, want token", cfg.CredKind)
	}

	// Clear with NewCred "" → no credential.
	empty := ""
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r2.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: &empty}))
	creds, _ = s.Creds("app")
	if creds.Token != "" {
		t.Errorf("clear: token = %q, want empty", creds.Token)
	}
}

func TestSaveRejectsUnsafeURLAndSlug(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "ok", RepoURL: "https://127.0.0.1/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err == nil {
		t.Error("loopback repo URL accepted")
	}
	if err := s.Save(ctx, SaveInput{Project: "Bad Slug!", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err == nil {
		t.Error("invalid slug accepted")
	}
	if err := s.Save(ctx, SaveInput{Project: "ok", RepoURL: "https://github.com/o/r.git", Ref: "main", BuildPolicy: "never"}); err == nil {
		t.Error("non-fully-qualified ref accepted")
	}
}

func TestWebhookRotateLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	token, err := s.RotateWebhook(ctx, "shop")
	if err != nil || token == "" {
		t.Fatalf("rotate: %v token=%q", err, token)
	}
	project, hmacSecret, ok := s.WebhookLookup(token)
	if !ok || project != "shop" || len(hmacSecret) == 0 {
		t.Fatalf("lookup: ok=%v project=%q secretlen=%d", ok, project, len(hmacSecret))
	}
	// An unknown token never resolves.
	if _, _, ok := s.WebhookLookup("bogus-token"); ok {
		t.Error("bogus token resolved")
	}
	// Rotation invalidates the old token.
	token2, _ := s.RotateWebhook(ctx, "shop")
	if token2 == token {
		t.Error("rotation produced the same token")
	}
	if _, _, ok := s.WebhookLookup(token); ok {
		t.Error("old token still resolves after rotation")
	}
	if _, _, ok := s.WebhookLookup(token2); !ok {
		t.Error("new token does not resolve")
	}
}

func TestFSMTransitions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	sha := "0123456789abcdef0123456789abcdef01234567"
	s.SetFetchResult(ctx, "shop", sha, 3, "update_available")
	cfg, _, _ := s.Get("shop")
	if cfg.StagedCommit != sha || cfg.CommitsBehind != 3 || cfg.UpdateState != "update_available" {
		t.Errorf("after fetch: %+v", cfg)
	}
	s.SetDeployed(ctx, "shop", sha)
	cfg, _, _ = s.Get("shop")
	if cfg.DeployedCommit != sha || cfg.UpdateState != "up_to_date" || cfg.CommitsBehind != 0 {
		t.Errorf("after deploy: %+v", cfg)
	}
	// An invalid state is ignored (fail-safe).
	s.SetState(ctx, "shop", "garbage")
	cfg, _, _ = s.Get("shop")
	if cfg.UpdateState != "up_to_date" {
		t.Errorf("invalid state applied: %q", cfg.UpdateState)
	}
}
