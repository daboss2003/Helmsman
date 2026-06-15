// Package store opens the SQLite database (pure-Go modernc driver, CGO-free) and
// runs embedded migrations transactionally (plan §2, §9). It sets a 0077 umask
// before open so the -wal/-shm side files are never group/world readable.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB wraps *sql.DB with the helpers the rest of the binary uses.
type DB struct {
	*sql.DB
	Path string
}

// Open opens (creating if needed) the SQLite DB at path with the plan-mandated
// pragmas and runs all pending migrations.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
		}
	}
	// Tighten umask so -wal/-shm aren't group-readable (plan §2). Restore after.
	old := umask(0o077)
	defer umask(old)

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// modernc/sqlite is happiest with a single writer connection; WAL allows
	// concurrent readers via separate read connections, but the control plane is
	// low-traffic and serializing writes avoids busy errors on a tiny box.
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	db := &DB{DB: sqldb, Path: path}
	if err := db.migrate(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// Inspect opens path READ-ONLY and returns the highest recorded schema version,
// erroring if the file is not a Helmsman database (missing/empty schema_meta). Unlike
// Open it never creates or migrates — restore uses it to reject a blank or foreign
// archive before it would otherwise be installed as the live DB.
func Inspect(path string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(2000)&mode=ro&_pragma=query_only(ON)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_meta`).Scan(&v); err != nil {
		return 0, fmt.Errorf("not a Helmsman database (no schema_meta): %w", err)
	}
	if v == 0 {
		return 0, errors.New("not a Helmsman database (empty schema)")
	}
	return v, nil
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var ver int
		// filenames look like 0001_init.sql
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &ver); err != nil {
			return nil, fmt.Errorf("store: bad migration filename %q: %w", e.Name(), err)
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: ver, name: e.Name(), sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

func (db *DB) migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_meta (
		version INTEGER PRIMARY KEY,
		name    TEXT NOT NULL,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		return fmt.Errorf("store: create schema_meta: %w", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_meta`).Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	// Enforce the invariant the comment used to only claim (review #23):
	// on-disk migrations must be contiguous 1..N (no gaps, no duplicates)...
	for i, m := range ms {
		if m.version != i+1 {
			return fmt.Errorf("store: migrations not contiguous: expected version %d, got %d (%s)", i+1, m.version, m.name)
		}
	}
	// ...and the DB must not know a higher version than this binary (downgrade).
	highest := 0
	if len(ms) > 0 {
		highest = ms[len(ms)-1].version
	}
	if current > highest {
		return fmt.Errorf("store: database schema version %d is newer than this binary's highest migration %d (downgrade refused)", current, highest)
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_meta(version, name) VALUES(?, ?)`, m.version, m.name); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", m.name, err)
		}
	}
	return nil
}
