package web

import (
	"context"
	"database/sql"
	"time"
)

// Login lockout (plan §5.2): failures are keyed on BOTH (real peer, username)
// and a global per-username counter, so an attacker rotating XFF/source cannot
// out-run the per-username throttle. Keys use the unspoofable peer, never XFF.
const (
	peerMaxFailures = 5
	peerLockWindow  = 15 * time.Minute
	peerLockFor     = 15 * time.Minute

	userMaxFailures = 50
	userLockWindow  = 1 * time.Hour
	userLockFor     = 30 * time.Minute
)

// locked reports whether either the (peer,user) or the per-user counter is
// currently in a lockout window.
func (s *Server) locked(ctx context.Context, peer, user string) bool {
	now := time.Now().Unix()
	check := func(scope, key string) bool {
		var lockedUntil int64
		err := s.db.QueryRowContext(ctx,
			`SELECT locked_until FROM login_attempts WHERE scope = ? AND key = ?`,
			scope, key).Scan(&lockedUntil)
		if err != nil {
			return false
		}
		return lockedUntil > now
	}
	return check("peer_user", peer+"|"+user) || check("user", user)
}

// recordFailure bumps both counters and arms a lockout when a threshold is hit.
func (s *Server) recordFailure(ctx context.Context, peer, user string) {
	s.bump(ctx, "peer_user", peer+"|"+user, peerMaxFailures, peerLockWindow, peerLockFor)
	s.bump(ctx, "user", user, userMaxFailures, userLockWindow, userLockFor)
}

func (s *Server) bump(ctx context.Context, scope, key string, maxFail int, window, lockFor time.Duration) {
	// Single atomic UPSERT so concurrent failed logins cannot lose an increment
	// (review #16). The CASE expressions reset the window when it has elapsed,
	// increment otherwise, and arm the lock when the threshold is reached — all
	// computed in SQL from the existing row, never read-modify-write in Go.
	now := time.Now().Unix()
	winSecs := int64(window / time.Second)
	lockSecs := int64(lockFor / time.Second)
	_, _ = s.db.ExecContext(ctx,
		`INSERT INTO login_attempts(scope, key, failures, first_failure, locked_until)
		 VALUES(@scope, @key, 1, @now, CASE WHEN 1 >= @maxfail THEN @now + @lockfor ELSE 0 END)
		 ON CONFLICT(scope, key) DO UPDATE SET
		   failures = CASE WHEN @now - first_failure > @window THEN 1 ELSE failures + 1 END,
		   first_failure = CASE WHEN @now - first_failure > @window THEN @now ELSE first_failure END,
		   locked_until = CASE
		     WHEN (CASE WHEN @now - first_failure > @window THEN 1 ELSE failures + 1 END) >= @maxfail
		       THEN @now + @lockfor ELSE locked_until END`,
		sql.Named("scope", scope), sql.Named("key", key), sql.Named("now", now),
		sql.Named("window", winSecs), sql.Named("maxfail", maxFail), sql.Named("lockfor", lockSecs))
}

// clearFailures resets the counters on a successful login.
func (s *Server) clearFailures(ctx context.Context, peer, user string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE scope = ? AND key = ?`, "peer_user", peer+"|"+user)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE scope = ? AND key = ?`, "user", user)
}
