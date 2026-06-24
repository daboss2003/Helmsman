package apitoken

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/daboss2003/Helmsman/internal/store"
)

// ErrNotFound means no token row matched the id (an unknown/expired/garbage id
// looks identical to a wrong secret to the caller — no enumeration oracle).
var ErrNotFound = errors.New("apitoken: not found")

// Store persists api_tokens. The id selects exactly one row, so a request runs at
// most one argon2id verify; minting is CLI-only (no web path constructs a Store
// write for token creation).
type Store struct{ db *store.DB }

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Insert persists a freshly-minted Record (the plaintext is never stored). label is
// an informational operator note.
func (s *Store) Insert(ctx context.Context, r Record, label string, now time.Time) error {
	if !ValidID(r.ID) || r.Hash == "" || len(r.Scopes) == 0 || len(r.CIDRs) == 0 || r.ExpiresAt <= 0 {
		return errors.New("apitoken: refusing to store a malformed record")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens(id, hash, scopes, cidrs, label, created_at, expires_at, revoked)
		 VALUES(?, ?, ?, ?, ?, ?, ?, 0)`,
		r.ID, r.Hash, joinScopes(r.Scopes), joinCIDRs(r.CIDRs), strings.TrimSpace(label),
		now.Unix(), r.ExpiresAt)
	return err
}

// Get loads one token by id. It returns ErrNotFound for any id that is malformed or
// absent — the caller cannot distinguish "no such token" from "wrong secret".
func (s *Store) Get(ctx context.Context, id string) (Record, error) {
	if !ValidID(id) {
		return Record{}, ErrNotFound
	}
	var (
		r            Record
		scopes, cidr string
		revoked      int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, hash, scopes, cidrs, expires_at, revoked FROM api_tokens WHERE id=?`, id).
		Scan(&r.ID, &r.Hash, &scopes, &cidr, &r.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	r.Scopes = splitScopes(scopes)
	r.CIDRs = parseStoredCIDRs(cidr)
	r.Revoked = revoked != 0
	return r, nil
}

// List returns all tokens (for the CLI listing + the CIDR-union recompute on
// startup/SIGHUP).
func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hash, scopes, cidrs, expires_at, revoked FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var (
			r            Record
			scopes, cidr string
			revoked      int
		)
		if err := rows.Scan(&r.ID, &r.Hash, &scopes, &cidr, &r.ExpiresAt, &revoked); err != nil {
			return nil, err
		}
		r.Scopes = splitScopes(scopes)
		r.CIDRs = parseStoredCIDRs(cidr)
		r.Revoked = revoked != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// Revoke marks a token revoked (idempotent). A revoked token fails active() and is
// excluded from the CIDR union on the next recompute.
func (s *Store) Revoke(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAppScoped revokes any token whose ONLY capability is deploying THIS app
// (scopes == "deploy:write:<slug>"), used by the app-delete teardown. It deliberately
// leaves multi-scope tokens alone — yanking a token that also serves other apps would
// be collateral damage, and a leftover scope for a now-gone app is inert (its deploy
// route no longer resolves). Returns the number of tokens revoked.
func (s *Store) RevokeAppScoped(ctx context.Context, slug string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked=1 WHERE revoked=0 AND scopes=?`, "deploy:write:"+slug)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TouchLastUsed records a best-effort last-use timestamp (never gates auth — a
// failure here must not deny a valid request, so callers ignore the error).
func (s *Store) TouchLastUsed(ctx context.Context, id string, now time.Time) {
	if !ValidID(id) {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=? WHERE id=?`, now.Unix(), id)
}

// ActiveCIDRUnion returns the union of every currently-active token's CIDR set — the
// precomputed allowlist addition the IP gate checks the peer against BEFORE any
// bearer is parsed.
func (s *Store) ActiveCIDRUnion(ctx context.Context, now time.Time) ([]netip.Prefix, error) {
	recs, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	return CIDRUnion(recs, now.Unix()), nil
}

func joinScopes(s []string) string { return strings.Join(s, " ") }

func splitScopes(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

func joinCIDRs(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, " ")
}

// parseStoredCIDRs reparses the persisted set. Values were validated by ParseCIDRs
// before storage, so a parse failure means tampering — drop the bad entry rather
// than admit a malformed prefix (fail-closed: a token with an unparseable CIDR
// simply contributes nothing to the union and matches no peer).
func parseStoredCIDRs(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, f := range strings.Fields(s) {
		p, err := netip.ParsePrefix(f)
		if err != nil || p.Bits() == 0 {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}
