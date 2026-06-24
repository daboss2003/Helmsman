package web

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/crypto"
)

// totpLastStepKey holds the last consumed TOTP time step (single-operator), so a
// code cannot be replayed within its validity window (review #4).
const totpLastStepKey = "auth_totp_last_step"

// requireAuth gates protected routes (pipeline step 6). Unauthenticated GETs are
// redirected to /login; other methods get 401. It runs BEFORE requireCSRF where
// both wrap a state-changing handler.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if SessionFrom(r.Context()) == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if SessionFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, "")
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	totp := r.PostFormValue("totp")
	peer := ClientIP(ctx).String()
	sec := s.security()

	// Lockout check first (plan §5.2). A generic message — never reveal whether
	// the username exists or whether the lock is peer- or user-scoped.
	if s.locked(ctx, peer, username) {
		_ = s.audit.Log(ctx, audit.Event{
			Actor: username, IP: peer, Action: "login", Outcome: audit.Deny,
			Level: audit.Security, Detail: "locked out",
		})
		s.renderLogin(w, r, "Too many attempts. Try again later.")
		return
	}

	// Constant-time username compare; argon2id verify ALWAYS runs (dummy hash on
	// mismatch) so response timing never reveals whether the user exists.
	userMatch := crypto.ConstantTimeEqualString(username, sec.username)
	hashToCheck := sec.passwordHash
	if !userMatch {
		hashToCheck = sec.dummyHash
	}
	// Bounded-concurrency gate around the expensive argon2id verify so a burst of
	// concurrent logins can't OOM a tiny box (review #10). Acquire, verify,
	// release immediately.
	select {
	case s.verifySem <- struct{}{}:
	case <-time.After(2 * time.Second):
		http.Error(w, "server busy, try again", http.StatusServiceUnavailable)
		return
	case <-ctx.Done():
		return
	}
	pwOK, _ := crypto.VerifyPassword(hashToCheck, []byte(password))
	<-s.verifySem
	ok := userMatch && pwOK

	// TOTP, when configured. Only checked when the password already matched (&&
	// short-circuits), so an attacker without the password can't burn the watermark.
	if ok {
		ok = s.verifyTOTPOnce(ctx, totp)
	}

	if !ok {
		s.recordFailure(ctx, peer, username)
		_ = s.audit.Log(ctx, audit.Event{
			Actor: username, IP: peer, Action: "login", Outcome: audit.Deny,
			Level: audit.Security, Detail: "invalid credentials",
		})
		s.renderLogin(w, r, "Invalid credentials.")
		return
	}

	// Success: clear counters, rotate to a fresh session id (plan §5.3).
	s.clearFailures(ctx, peer, username)
	rawID, err := s.sessions.Create(ctx, sec.username, peer, r.UserAgent())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, rawID)
	_ = s.audit.Log(ctx, audit.Event{
		Actor: sec.username, IP: peer, Action: "login", Outcome: audit.OK, Level: audit.Security,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// verifyTOTPOnce validates a TOTP code against the configured secret and atomically
// advances the single-use watermark so the same code can't be replayed within its
// window — across login AND any other re-auth (e.g. the destructive app-delete). When
// 2FA is not configured it returns true (nothing to check). Not widened under clock
// skew (plan §5.9). Callers must gate this behind a prior password match (&&-short-
// circuit) so an attacker without the password can't burn the watermark.
func (s *Server) verifyTOTPOnce(ctx context.Context, code string) bool {
	sec := s.security()
	if sec.totpSecret == "" {
		return true
	}
	step, vok := crypto.ValidateTOTPStep(sec.totpSecret, code, time.Now(), 1)
	if !vok {
		return false
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES(@k, @s)
		 ON CONFLICT(key) DO UPDATE SET value = @s WHERE CAST(value AS INTEGER) < @s`,
		sql.Named("k", totpLastStepKey), sql.Named("s", int64(step)))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1 // n==0 → already consumed (replay)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
		_ = s.sessions.Delete(ctx, c.Value)
	}
	s.clearSessionCookie(w)
	if sess := SessionFrom(ctx); sess != nil {
		_ = s.audit.Log(ctx, audit.Event{
			Actor: sess.Username, IP: ClientIP(ctx).String(), Action: "logout", Outcome: audit.OK,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
