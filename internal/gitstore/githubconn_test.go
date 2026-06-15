package gitstore

import (
	"context"
	"strings"
	"testing"
)

func TestGitHubConnRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// None configured initially.
	if _, ok, err := s.GitHubConn(ctx); ok || err != nil {
		t.Fatalf("expected no connection, got ok=%v err=%v", ok, err)
	}

	if err := s.SaveGitHubConn(ctx, "octocat", "gho_secret_token"); err != nil {
		t.Fatal(err)
	}
	conn, ok, err := s.GitHubConn(ctx)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if conn.Login != "octocat" || conn.Token != "gho_secret_token" {
		t.Errorf("round-trip mismatch: %+v", conn)
	}

	// Upsert replaces.
	if err := s.SaveGitHubConn(ctx, "octocat", "gho_rotated"); err != nil {
		t.Fatal(err)
	}
	conn, _, _ = s.GitHubConn(ctx)
	if conn.Token != "gho_rotated" {
		t.Errorf("expected rotated token, got %q", conn.Token)
	}

	// The token is encrypted at rest (never stored in cleartext).
	var raw []byte
	if err := s.db.QueryRow(`SELECT token_enc FROM github_connection WHERE id=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "gho_rotated") {
		t.Error("token must be encrypted at rest, found cleartext")
	}

	// Disconnect clears it.
	if err := s.DeleteGitHubConn(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GitHubConn(ctx); ok {
		t.Error("connection must be gone after disconnect")
	}
}

func TestSaveGitHubConnRejectsEmptyToken(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveGitHubConn(context.Background(), "octocat", ""); err == nil {
		t.Error("an empty token must be refused")
	}
}
