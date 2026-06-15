// Package provstore persists the registry of Helmsman-provisioned apps (plan §7):
// the compose path and the typed form spec (helmsman.yaml under the hood) that is
// the source of truth for regenerate/drift. Helmsman GENERATES and owns the
// compose — there is no raw-compose paste — so source is always "generated". It
// holds NO secrets (env values live in the encrypted env store), so rows are safe
// at rest without a cipher.
package provstore

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/daboss2003/Helmsman/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// App is one provisioned-app registry row.
type App struct {
	Slug        string
	Source      string // always "generated" — Helmsman owns the compose (no raw paste)
	ComposePath string
	SpecJSON    string
	CreatedAt   int64
	UpdatedAt   int64
}

// Store persists provisioned apps.
type Store struct{ db *store.DB }

// New builds a Store.
func New(db *store.DB) *Store { return &Store{db: db} }

// Save upserts a provisioned app. created_at is preserved across updates.
func (s *Store) Save(ctx context.Context, a App) error {
	if !slugRe.MatchString(a.Slug) {
		return errors.New("provstore: invalid slug")
	}
	if a.Source != "generated" {
		return errors.New("provstore: source must be generated (Helmsman owns the compose)")
	}
	if a.ComposePath == "" {
		a.ComposePath = "docker-compose.yml"
	}
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_provisioned(slug, source, compose_path, spec_json, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(slug) DO UPDATE SET
		   source=excluded.source, compose_path=excluded.compose_path,
		   spec_json=excluded.spec_json, updated_at=excluded.updated_at`,
		a.Slug, a.Source, a.ComposePath, a.SpecJSON, now, now)
	return err
}

// Get returns a provisioned app.
func (s *Store) Get(slug string) (App, bool, error) {
	var a App
	err := s.db.QueryRow(
		`SELECT slug, source, compose_path, spec_json, created_at, updated_at FROM app_provisioned WHERE slug=?`, slug).
		Scan(&a.Slug, &a.Source, &a.ComposePath, &a.SpecJSON, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return App{}, false, nil
	}
	if err != nil {
		return App{}, false, err
	}
	return a, true, nil
}

// List returns all provisioned apps, newest first.
func (s *Store) List() ([]App, error) {
	rows, err := s.db.Query(
		`SELECT slug, source, compose_path, spec_json, created_at, updated_at FROM app_provisioned ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.Slug, &a.Source, &a.ComposePath, &a.SpecJSON, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Delete removes a provisioned app's registry row (the run dir is removed
// separately by the caller).
func (s *Store) Delete(ctx context.Context, slug string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_provisioned WHERE slug=?`, slug)
	return err
}
