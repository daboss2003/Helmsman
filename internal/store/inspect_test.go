package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// Inspect must accept a real Helmsman DB and REJECT a blank or foreign SQLite file —
// the guard that stops `restore` from installing a bogus archive over the live DB.
func TestInspect(t *testing.T) {
	dir := t.TempDir()

	// A real Helmsman DB (migrated by Open).
	good := filepath.Join(dir, "good.db")
	db, err := Open(good)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if v, err := Inspect(good); err != nil || v < 1 {
		t.Errorf("Inspect(real) = %d, %v; want a positive version, nil", v, err)
	}

	// A 0-byte file → not a Helmsman DB.
	blank := filepath.Join(dir, "blank.db")
	if err := os.WriteFile(blank, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(blank); err == nil {
		t.Error("Inspect(0-byte) must error")
	}

	// A valid SQLite file with only foreign tables → not a Helmsman DB.
	foreign := filepath.Join(dir, "foreign.db")
	fdb, err := sql.Open("sqlite", "file:"+foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fdb.Exec(`CREATE TABLE evil(x)`); err != nil {
		t.Fatal(err)
	}
	fdb.Close()
	if _, err := Inspect(foreign); err == nil {
		t.Error("Inspect(foreign sqlite) must error (no schema_meta)")
	}
}
