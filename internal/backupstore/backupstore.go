// Package backupstore manages Helmsman's own-state backups: a consistent snapshot of
// the SQLite database (via VACUUM INTO), AES-256-GCM-encrypted with the master key
// (the chunked, tamper-evident stream from internal/backup), written under the data
// dir and recorded in a catalog. This is the "recover Helmsman onto a fresh box"
// backup — it carries every app's config, definitions, edge routes, and (already-
// encrypted) secrets. App-internal data volumes are a separate snapshot type.
package backupstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/helmsman/helmsman/internal/backup"
	"github.com/helmsman/helmsman/internal/store"
)

var idRe = regexp.MustCompile(`^[a-f0-9]{24}$`)

// Record is one catalogued backup.
type Record struct {
	ID        string
	CreatedAt int64
	SizeBytes int64
	File      string
	SHA256    string
	Kind      string
	Note      string
}

// Store creates, lists, and deletes encrypted state backups.
type Store struct {
	db  *store.DB
	dir string
	key []byte // 32-byte master key (AES-256)
}

// New builds a Store. dir is where archives are written (created 0700 on first use).
func New(db *store.DB, dir string, key []byte) *Store {
	return &Store{db: db, dir: dir, key: key}
}

// Available reports whether backups can be taken (a valid key is configured).
func (s *Store) Available() bool { return s != nil && len(s.key) == 32 && s.db != nil }

// Create takes a consistent snapshot of the DB, encrypts it, and records it. The
// plaintext snapshot exists only transiently (0600, in the 0700 backups dir) and is
// removed as soon as it's encrypted.
func (s *Store) Create(ctx context.Context, now time.Time) (Record, error) {
	if !s.Available() {
		return Record{}, errors.New("backupstore: not available (no master key)")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Record{}, fmt.Errorf("backupstore: mkdir: %w", err)
	}
	_ = os.Chmod(s.dir, 0o700) // tighten a pre-existing, looser dir (MkdirAll won't)
	id, err := randHex(12)
	if err != nil {
		return Record{}, err
	}
	tmp := filepath.Join(s.dir, "."+id+".snapshot")
	final := filepath.Join(s.dir, id+".hmbk")
	// Register cleanup BEFORE the snapshot, so a VACUUM that fails mid-write (disk full,
	// I/O error, cancellation) can't leave a partial PLAINTEXT copy of the DB behind.
	defer os.Remove(tmp)
	// VACUUM INTO writes a consistent copy of the live DB (committed WAL included) to a
	// NEW file. The path is server-generated (not user input); bind it as a parameter.
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return Record{}, fmt.Errorf("backupstore: snapshot: %w", err)
	}
	// The transient snapshot is a full plaintext copy of the DB. VACUUM INTO honors the
	// process umask (often 0022 → 0644), so force owner-only before we read it.
	if err := os.Chmod(tmp, 0o600); err != nil {
		return Record{}, fmt.Errorf("backupstore: secure snapshot: %w", err)
	}

	in, err := os.Open(tmp)
	if err != nil {
		return Record{}, err
	}
	defer in.Close()
	out, err := os.OpenFile(final, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Record{}, err
	}
	if err := backup.Encrypt(out, in, s.key, 0); err != nil {
		out.Close()
		os.Remove(final)
		return Record{}, fmt.Errorf("backupstore: encrypt: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(final)
		return Record{}, err
	}
	size, sum, err := fileSizeSHA(final)
	if err != nil {
		os.Remove(final)
		return Record{}, err
	}
	rec := Record{ID: id, CreatedAt: now.Unix(), SizeBytes: size, File: id + ".hmbk", SHA256: sum, Kind: "helmsman-state"}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO backups(id, created_at, size_bytes, file, sha256, kind, note) VALUES(?, ?, ?, ?, ?, ?, '')`,
		rec.ID, rec.CreatedAt, rec.SizeBytes, rec.File, rec.SHA256, rec.Kind); err != nil {
		os.Remove(final)
		return Record{}, err
	}
	return rec, nil
}

// List returns catalogued backups, newest first.
func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, size_bytes, file, sha256, kind, note FROM backups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.CreatedAt, &r.SizeBytes, &r.File, &r.SHA256, &r.Kind, &r.Note); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one record by id (ok=false if absent/malformed).
func (s *Store) Get(ctx context.Context, id string) (Record, bool, error) {
	if !idRe.MatchString(id) {
		return Record{}, false, nil
	}
	var r Record
	err := s.db.QueryRowContext(ctx,
		`SELECT id, created_at, size_bytes, file, sha256, kind, note FROM backups WHERE id=?`, id).
		Scan(&r.ID, &r.CreatedAt, &r.SizeBytes, &r.File, &r.SHA256, &r.Kind, &r.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// FilePath returns the absolute path of a record's archive, confined to the backups
// dir (the stored file name is always a generated <id>.hmbk, never user input).
func (s *Store) FilePath(r Record) string { return filepath.Join(s.dir, filepath.Base(r.File)) }

// Delete removes the archive file and the catalog row.
func (s *Store) Delete(ctx context.Context, id string) error {
	rec, ok, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	_ = os.Remove(s.FilePath(rec))
	_, err = s.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id)
	return err
}

func fileSizeSHA(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
