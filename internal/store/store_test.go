package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAndMigrate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_meta`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("no migrations recorded")
	}
	// idempotent re-open
	db2, err := Open(db.Path)
	if err != nil {
		t.Fatalf("re-open failed: %v", err)
	}
	db2.Close()
}

// review #23: a DB whose schema version is newer than this binary must be refused.
func TestMigrateRefusesDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_meta(version, name) VALUES(99, 'from-the-future')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("expected downgrade refusal, got %v", err)
	}
}
