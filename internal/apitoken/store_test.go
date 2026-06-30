package apitoken

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db)
}

func TestStoreInsertGetRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := mustTime()
	m, err := Mint([]string{"status:read", "deploy:write:web"}, []string{"10.0.0.0/8", "203.0.113.0/24"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, m.Record, "ci-runner", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, m.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != m.Record.Hash || len(got.Scopes) != 2 || len(got.CIDRs) != 2 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// The persisted record verifies the original secret.
	_, secret, _ := SplitBearer(m.Plaintext)
	if !got.VerifySecret(secret, now.Unix()) {
		t.Error("persisted record must verify the minted secret")
	}
}

func TestStoreGetUnknownIsNotFound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, "deadbeefdeadbeefdeadbeef"); err != ErrNotFound {
		t.Errorf("unknown id must be ErrNotFound, got %v", err)
	}
	// Malformed id is also ErrNotFound (no distinct error reveals validity).
	if _, err := s.Get(ctx, "not-a-valid-id"); err != ErrNotFound {
		t.Errorf("malformed id must be ErrNotFound, got %v", err)
	}
}

func TestStoreRevokeExcludesFromUnionAndVerify(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := mustTime()
	m, _ := Mint([]string{"status:read"}, []string{"10.0.0.0/8"}, time.Hour, now)
	if err := s.Insert(ctx, m.Record, "", now); err != nil {
		t.Fatal(err)
	}
	// Present in the union while active.
	union, _ := s.ActiveCIDRUnion(ctx, now)
	if len(union) != 1 {
		t.Fatalf("active token must contribute to the union, got %v", union)
	}
	if err := s.Revoke(ctx, m.Record.ID); err != nil {
		t.Fatal(err)
	}
	// Gone from the union, and the loaded record refuses to verify.
	union, _ = s.ActiveCIDRUnion(ctx, now)
	if len(union) != 0 {
		t.Errorf("revoked token must drop out of the union, got %v", union)
	}
	got, _ := s.Get(ctx, m.Record.ID)
	_, secret, _ := SplitBearer(m.Plaintext)
	if got.VerifySecret(secret, now.Unix()) {
		t.Error("a revoked token must not verify")
	}
	// Revoking an unknown id is ErrNotFound.
	if err := s.Revoke(ctx, "deadbeefdeadbeefdeadbeef"); err != ErrNotFound {
		t.Errorf("revoking an unknown id must be ErrNotFound, got %v", err)
	}
}

func TestStoreUnionExcludesExpired(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := mustTime()
	m, _ := Mint([]string{"status:read"}, []string{"10.0.0.0/8"}, time.Hour, now)
	if err := s.Insert(ctx, m.Record, "", now); err != nil {
		t.Fatal(err)
	}
	// Far in the future, past expiry → empty union.
	later := now.Add(2 * time.Hour)
	union, _ := s.ActiveCIDRUnion(ctx, later)
	if len(union) != 0 {
		t.Errorf("expired token must be excluded from the union, got %v", union)
	}
}

func TestStoreRejectsMalformedRecord(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := mustTime()
	bad := Record{ID: "short", Hash: "x", ExpiresAt: now.Add(time.Hour).Unix()}
	if err := s.Insert(ctx, bad, "", now); err == nil {
		t.Error("a malformed record (bad id, no scopes/cidrs) must be refused")
	}
}
