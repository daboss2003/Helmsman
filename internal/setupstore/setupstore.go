// Package setupstore persists per-app setup scripts (encrypted at rest) and the
// run ledger (plan §9). The script set + the run idempotence are keyed by the
// full script_set_checksum so a confirmation is void on any byte change and
// on_first_deploy runs exactly once per checksum.
package setupstore

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/sandbox"
	"github.com/daboss2003/Helmsman/internal/secret"
	"github.com/daboss2003/Helmsman/internal/store"
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// Store persists setup scripts + runs.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

// Save validates + upserts an app's setup script set (script encrypted at rest).
// autoDeploy is the app's git.auto_deploy flag (auto-setup + auto-deploy is a
// hard reject — plan §7).
func (s *Store) Save(ctx context.Context, slug string, ss sandbox.ScriptSet, autoDeploy bool) error {
	if !slugRe.MatchString(slug) {
		return errors.New("setupstore: invalid slug")
	}
	if err := ss.Validate(autoDeploy); err != nil {
		return err
	}
	enc, err := s.cipher.Seal([]byte(ss.Script))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO setup_scripts(slug, script_enc, trigger, produces, pinned_sha, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(slug) DO UPDATE SET
		   script_enc=excluded.script_enc, trigger=excluded.trigger,
		   produces=excluded.produces, pinned_sha=excluded.pinned_sha, updated_at=excluded.updated_at`,
		slug, enc, ss.Trigger, strings.Join(ss.Produces, "\n"), ss.PinnedSHA, time.Now().Unix())
	return err
}

// Get returns the decrypted script set for an app.
func (s *Store) Get(slug string) (sandbox.ScriptSet, bool, error) {
	var enc []byte
	var ss sandbox.ScriptSet
	var produces string
	err := s.db.QueryRow(`SELECT script_enc, trigger, produces, pinned_sha FROM setup_scripts WHERE slug=?`, slug).
		Scan(&enc, &ss.Trigger, &produces, &ss.PinnedSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return sandbox.ScriptSet{}, false, nil
	}
	if err != nil {
		return sandbox.ScriptSet{}, false, err
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return sandbox.ScriptSet{}, false, err
	}
	ss.Script = string(pt)
	if produces != "" {
		ss.Produces = strings.Split(produces, "\n")
	}
	return ss, true, nil
}

// Delete removes an app's setup script.
func (s *Store) Delete(ctx context.Context, slug string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM setup_scripts WHERE slug=?`, slug)
	return err
}

// DeleteApp removes an app's setup script AND its run ledger. Used by the app-delete
// teardown (the plain Delete only drops the script).
func (s *Store) DeleteApp(ctx context.Context, slug string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM setup_scripts WHERE slug=?`, slug); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM setup_runs WHERE slug=?`, slug)
	return err
}

// RecordRunStart inserts a run row and returns its id.
func (s *Store) RecordRunStart(ctx context.Context, slug, checksum, actor string) int64 {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO setup_runs(slug, checksum, actor, started_at) VALUES(?, ?, ?, ?)`,
		slug, checksum, actor, time.Now().Unix())
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// RecordRunFinish finalizes a run row.
func (s *Store) RecordRunFinish(ctx context.Context, id int64, outcome string, exit int) {
	if id == 0 {
		return
	}
	_, _ = s.db.Exec(`UPDATE setup_runs SET outcome=?, exit_code=?, finished_at=? WHERE id=?`,
		outcome, exit, time.Now().Unix(), id)
}

// HasSuccessfulRun reports whether (slug, checksum) already ran successfully — the
// on_first_deploy idempotence key (plan §7).
func (s *Store) HasSuccessfulRun(slug, checksum string) bool {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM setup_runs WHERE slug=? AND checksum=? AND outcome='ok'`, slug, checksum).Scan(&n)
	return err == nil && n > 0
}
