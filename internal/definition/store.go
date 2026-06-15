package definition

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/helmsman/helmsman/internal/store"
)

// ErrTampered means a stored definition's HMAC did not verify (changed outside
// Helmsman). It is never loaded — fail-closed.
var ErrTampered = errors.New("definition HMAC mismatch (tampered)")

// Store persists applied canonical definitions (the history; the latest per slug is
// the live canonical). Every read RE-PARSES + RE-VALIDATES the stored YAML through
// the full pipeline (re-derive, never a verbatim replay), and the per-row HMAC is
// defence-in-depth so a DB tamper that still parses is caught.
type Store struct {
	db  *store.DB
	key []byte
}

// NewStore derives a domain-separated HMAC key from the encryption key.
func NewStore(db *store.DB, encKey []byte) *Store {
	h := sha256.New()
	h.Write([]byte("helmsman/definition-hmac/v1\x00"))
	h.Write(encKey)
	return &Store{db: db, key: h.Sum(nil)}
}

func (s *Store) mac(b []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(b)
	return m.Sum(nil)
}

// VersionMeta is one history row (no content).
type VersionMeta struct {
	ID        int64
	Note      string
	CreatedAt int64
}

// SaveCanonical re-marshals an already-validated definition to canonical YAML and
// records it as a new version (which becomes the live canonical). Returns its id.
func (s *Store) SaveCanonical(ctx context.Context, d *Definition, note string) (int64, error) {
	canon, err := Canonical(d)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO definition_versions(slug, yaml, hmac, note, created_at) VALUES(?,?,?,?, unixepoch())`,
		d.Metadata.Slug, string(canon), s.mac(canon), note)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Current returns the live canonical definition for a slug (the latest version),
// HMAC-verified and RE-PARSED. No version yet → (nil, nil).
func (s *Store) Current(slug string) (*Definition, error) {
	var yamlText string
	var mac []byte
	err := s.db.QueryRow(`SELECT yaml, hmac FROM definition_versions WHERE slug=? ORDER BY id DESC LIMIT 1`, slug).Scan(&yamlText, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.verifyAndParse([]byte(yamlText), mac)
}

// Version returns a specific past version for ROLLBACK — HMAC-verified and re-derived
// (re-parsed + re-validated through the full pipeline, never a verbatim replay).
func (s *Store) Version(slug string, id int64) (*Definition, error) {
	var yamlText string
	var mac []byte
	err := s.db.QueryRow(`SELECT yaml, hmac FROM definition_versions WHERE slug=? AND id=?`, slug, id).Scan(&yamlText, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return s.verifyAndParse([]byte(yamlText), mac)
}

func (s *Store) verifyAndParse(yamlText, mac []byte) (*Definition, error) {
	if !hmac.Equal(mac, s.mac(yamlText)) {
		return nil, ErrTampered
	}
	return Parse(yamlText) // re-derive: a stored def is re-validated, never trusted blindly
}

// List returns a slug's version history, newest first.
func (s *Store) List(slug string) ([]VersionMeta, error) {
	rows, err := s.db.Query(`SELECT id, note, created_at FROM definition_versions WHERE slug=? ORDER BY id DESC`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionMeta
	for rows.Next() {
		var m VersionMeta
		if err := rows.Scan(&m.ID, &m.Note, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
