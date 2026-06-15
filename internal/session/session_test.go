package session

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/daboss2003/Helmsman/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "sess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateLoadDelete(t *testing.T) {
	ctx := context.Background()
	m := New(openDB(t), 30*time.Minute, 12*time.Hour)
	raw, err := m.Create(ctx, "operator", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := m.Load(ctx, raw)
	if err != nil || sess.Username != "operator" {
		t.Fatalf("load failed: %v / %+v", err, sess)
	}
	if err := m.Delete(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete, load = %v, want ErrNotFound", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	m := New(db, 1*time.Second, 12*time.Hour)
	raw, _ := m.Create(ctx, "operator", "127.0.0.1", "test")
	// Force last_seen far into the past.
	_, _ = db.Exec(`UPDATE sessions SET last_seen_at = ?`, time.Now().Add(-time.Hour).Unix())
	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Errorf("idled-out session loaded: %v", err)
	}
}

// The high-severity fix (review #1): a backward wall-clock step plus a restart
// must NOT resurrect an already-expired session.
func TestBackwardClockCannotResurrectSession(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	realNow := time.Now()

	// Persist a clock high-water mark at "real now": the system has observed time
	// up to here, even though the wall clock is about to be stepped back.
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)`,
		highWaterKey, strconv.FormatInt(realNow.Unix(), 10)); err != nil {
		t.Fatal(err)
	}
	// Insert a session that is ALREADY expired relative to the high-water mark
	// (absolute_exp one hour before realNow).
	raw := "raw-session-id-for-test"
	if _, err := db.Exec(
		`INSERT INTO sessions(id_hash, username, created_at, last_seen_at, absolute_exp, created_mono, peer_ip, user_agent)
		 VALUES(?, ?, ?, ?, ?, 0, '', '')`,
		hashID(raw), "operator",
		realNow.Add(-13*time.Hour).Unix(), realNow.Add(-13*time.Hour).Unix(), realNow.Add(-time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart AFTER a backward wall-clock step (boot wall = 13h ago).
	m := New(db, 30*time.Minute, 12*time.Hour)
	m.bootWall = realNow.Add(-13 * time.Hour)
	m.bootMono = monoNow()
	// New already seeded hw from the persisted high-water; the stepped-back
	// bootWall does not lower it.

	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session resurrected after backward clock step: err=%v", err)
	}
	// And GC must purge it rather than strand it.
	if err := m.GC(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Errorf("GC left %d expired session(s) after backward step", n)
	}
}
