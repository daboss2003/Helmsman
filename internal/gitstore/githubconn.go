package gitstore

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GitHubConn is the operator's GitHub OAuth connection (account-level; one row). The
// token is held encrypted at rest and used only to list repos + install per-repo
// read-only deploy keys — never for day-to-day fetching.
type GitHubConn struct {
	Login string
	Token string
}

// SaveGitHubConn upserts the single GitHub connection (token encrypted at rest).
func (s *Store) SaveGitHubConn(ctx context.Context, login, token string) error {
	if token == "" {
		return errors.New("gitstore: refusing to store an empty github token")
	}
	enc, err := s.cipher.Seal([]byte(token))
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO github_connection(id, login, token_enc, created_at, updated_at)
		 VALUES(1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET login=excluded.login, token_enc=excluded.token_enc, updated_at=excluded.updated_at`,
		login, enc, now, now)
	return err
}

// GitHubConn loads the connection (ok=false when none is configured). The decrypted
// token never leaves this layer except to the GitHub client.
func (s *Store) GitHubConn(ctx context.Context) (conn GitHubConn, ok bool, err error) {
	var enc []byte
	row := s.db.QueryRowContext(ctx, `SELECT login, token_enc FROM github_connection WHERE id=1`)
	if err := row.Scan(&conn.Login, &enc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GitHubConn{}, false, nil
		}
		return GitHubConn{}, false, err
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return GitHubConn{}, false, err
	}
	conn.Token = string(pt)
	return conn, true, nil
}

// DeleteGitHubConn removes the connection (operator clicks Disconnect). Existing
// per-repo deploy keys keep working — they don't depend on this token.
func (s *Store) DeleteGitHubConn(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM github_connection WHERE id=1`)
	return err
}
