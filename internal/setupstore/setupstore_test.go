package setupstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/helmsman/helmsman/internal/sandbox"
	"github.com/helmsman/helmsman/internal/secret"
	"github.com/helmsman/helmsman/internal/store"
)

func newStore(t *testing.T) *Store {
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

func TestSetupStoreRoundTripEncrypted(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ss := sandbox.ScriptSet{Script: "#!/bin/sh\necho secret-logic\n", Trigger: sandbox.TriggerOnDemand, Produces: []string{"env:TOKEN", "file:x.pem"}}
	if err := s.Save(ctx, "shop", ss, false); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("shop")
	if err != nil || !ok || got.Script != ss.Script || got.Trigger != ss.Trigger || len(got.Produces) != 2 {
		t.Fatalf("round trip: %+v ok=%v err=%v", got, ok, err)
	}
	// The script is encrypted at rest (raw column must not contain the plaintext).
	var raw []byte
	if err := s.db.QueryRow(`SELECT script_enc FROM setup_scripts WHERE slug='shop'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || contains(raw, "secret-logic") {
		t.Error("script stored in plaintext")
	}
}

func TestSetupStoreRejectsAutoConflict(t *testing.T) {
	s := newStore(t)
	ss := sandbox.ScriptSet{Script: "echo hi", Trigger: sandbox.TriggerOnFirstDeploy}
	if err := s.Save(context.Background(), "shop", ss, true); err == nil {
		t.Error("auto_deploy + on_first_deploy should be rejected at the store")
	}
}

func TestSetupRunLedgerIdempotence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if s.HasSuccessfulRun("shop", "csum") {
		t.Error("no runs yet")
	}
	id := s.RecordRunStart(ctx, "shop", "csum", "op")
	s.RecordRunFinish(ctx, id, "ok", 0)
	if !s.HasSuccessfulRun("shop", "csum") {
		t.Error("successful run should be recorded")
	}
	// A different checksum has not run.
	if s.HasSuccessfulRun("shop", "other") {
		t.Error("different checksum should not be marked run")
	}
	// A failed run does not count.
	id2 := s.RecordRunStart(ctx, "blog", "c2", "op")
	s.RecordRunFinish(ctx, id2, "error", 1)
	if s.HasSuccessfulRun("blog", "c2") {
		t.Error("failed run should not count as successful")
	}
}

func contains(b []byte, sub string) bool {
	return len(sub) > 0 && len(b) >= len(sub) && indexOf(string(b), sub) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
