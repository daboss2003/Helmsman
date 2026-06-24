// Package envstore is the per-app encrypted environment store (plan §5.5, M5).
// The whole env blob is AES-256-GCM at rest under the master key; every save is
// a new immutable version (auditable history + rollback). Secret-flagged values
// are write-only in the UI and only ever leave via the audited reveal endpoint.
// Helmsman owns the live env: at deploy it renders a fresh 0600 --env-file from
// this store (plan: env-import "own vs import").
package envstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

// keyRe bounds env var names so a key can never carry `=`, whitespace, newlines,
// or NUL (which would break or inject lines in the rendered --env-file).
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Entry is one environment variable. Value is wrapped so it never logs in clear.
type Entry struct {
	Key    string
	Value  secret.Redacted
	Secret bool
	// Enc marks how Value is encoded for storage. "" means a plain value; "b64"
	// means Value is std-base64 and must be decoded before use (this is how
	// multi-line secrets — generated PEM keypairs — survive the no-newline rule).
	Enc string
}

// Version describes one saved blob version.
type Version struct {
	Version   int
	CreatedAt int64
	Actor     string
}

// entryJSON is the on-disk (pre-encryption) shape.
type entryJSON struct {
	Key    string `json:"k"`
	Value  string `json:"v"`
	Secret bool   `json:"s"`
	Enc    string `json:"e,omitempty"`
}

// Store persists encrypted, versioned env blobs.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

var (
	// ErrBadKey means an env key failed the name grammar.
	ErrBadKey = errors.New("envstore: invalid key (use letters, digits, underscore; not starting with a digit)")
	// ErrBadValue means a value contained NUL or a bare CR/LF.
	ErrBadValue = errors.New("envstore: value must not contain NUL or newlines")
)

// Current returns the latest version's entries (sorted by key) and its version
// number (0 if none yet).
func (s *Store) Current(project string) ([]Entry, int, error) {
	var (
		version int
		blob    []byte
	)
	err := s.db.QueryRow(
		`SELECT version, blob_enc FROM env_blobs WHERE project = ? ORDER BY version DESC LIMIT 1`, project,
	).Scan(&version, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	entries, err := s.decode(blob)
	return entries, version, err
}

func (s *Store) decode(blob []byte) ([]Entry, error) {
	pt, err := s.cipher.Open(blob)
	if err != nil {
		return nil, err
	}
	var js []entryJSON
	if err := json.Unmarshal(pt, &js); err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(js))
	for _, e := range js {
		entries = append(entries, Entry{Key: e.Key, Value: secret.New(e.Value), Secret: e.Secret, Enc: e.Enc})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

// Save validates and writes a new version. Duplicate keys are rejected.
func (s *Store) Save(ctx context.Context, project string, entries []Entry, actor string) (int, error) {
	seen := map[string]bool{}
	js := make([]entryJSON, 0, len(entries))
	for _, e := range entries {
		if !keyRe.MatchString(e.Key) {
			return 0, fmt.Errorf("%w: %q", ErrBadKey, e.Key)
		}
		v := e.Value.Reveal()
		if strings.ContainsAny(v, "\x00\n\r") {
			return 0, fmt.Errorf("%w: %q", ErrBadValue, e.Key)
		}
		if seen[e.Key] {
			return 0, fmt.Errorf("envstore: duplicate key %q", e.Key)
		}
		seen[e.Key] = true
		js = append(js, entryJSON{Key: e.Key, Value: v, Secret: e.Secret, Enc: e.Enc})
	}
	sort.Slice(js, func(i, j int) bool { return js[i].Key < js[j].Key })
	pt, err := json.Marshal(js)
	if err != nil {
		return 0, err
	}
	blob, err := s.cipher.Seal(pt)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur int
	_ = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM env_blobs WHERE project = ?`, project).Scan(&cur)
	next := cur + 1
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO env_blobs(project, version, created_at, actor, blob_enc) VALUES(?, ?, ?, ?, ?)`,
		project, next, time.Now().Unix(), actor, blob); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// Versions lists the version history (newest first).
func (s *Store) Versions(project string) ([]Version, error) {
	rows, err := s.db.Query(`SELECT version, created_at, actor FROM env_blobs WHERE project = ? ORDER BY version DESC`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vs []Version
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.Version, &v.CreatedAt, &v.Actor); err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, rows.Err()
}

// Rollback re-saves a prior version's content as a NEW version (never a pointer
// flip — the history stays linear and auditable, plan philosophy).
func (s *Store) Rollback(ctx context.Context, project string, version int, actor string) (int, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT blob_enc FROM env_blobs WHERE project = ? AND version = ?`, project, version).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("envstore: version not found")
	}
	if err != nil {
		return 0, err
	}
	entries, err := s.decode(blob)
	if err != nil {
		return 0, err
	}
	return s.Save(ctx, project, entries, actor+" (rollback to v"+itoa(version)+")")
}

// Render returns the current env as a key→value map for deploy and validation.
func (s *Store) Render(project string) (map[string]string, error) {
	entries, _, err := s.Current(project)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.Key] = e.Value.Reveal()
	}
	return out, nil
}

// Reveal returns one key's plaintext value (for the audited reveal endpoint).
func (s *Store) Reveal(project, key string) (string, bool, error) {
	entries, _, err := s.Current(project)
	if err != nil {
		return "", false, err
	}
	for _, e := range entries {
		if e.Key == key {
			return e.Value.Reveal(), true, nil
		}
	}
	return "", false, nil
}

// DeleteApp removes ALL env versions (literals + encrypted secrets) for an app —
// the entire history, so no secret material survives. Used by the app-delete teardown.
func (s *Store) DeleteApp(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM env_blobs WHERE project=?`, project)
	return err
}

// Get returns one key's full entry, including its Enc marker (so a caller that
// writes the value to a file can decode it). Prefer this over Reveal for
// secret_files materialization.
func (s *Store) Get(project, key string) (Entry, bool, error) {
	entries, _, err := s.Current(project)
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range entries {
		if e.Key == key {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

// DecodedValue returns the entry's value with any storage encoding undone: a
// "b64" entry (a generated PEM keypair) decodes back to the raw PEM bytes.
func (e Entry) DecodedValue() ([]byte, error) {
	v := e.Value.Reveal()
	if e.Enc == "b64" {
		return base64.StdEncoding.DecodeString(v)
	}
	return []byte(v), nil
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
