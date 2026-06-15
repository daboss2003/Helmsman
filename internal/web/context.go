package web

import (
	"context"
	"net/netip"

	"github.com/helmsman/helmsman/internal/session"
)

type ctxKey int

const (
	clientIPKey ctxKey = iota
	sessionKey
	csrfTokenKey
	tokenIDKey
)

func withClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIP returns the resolved client IP (the real peer, or the single
// overwritten XFF value when the peer is a trusted proxy). Zero value if unset.
func ClientIP(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey).(netip.Addr)
	return ip
}

func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// SessionFrom returns the loaded session, or nil if unauthenticated.
func SessionFrom(ctx context.Context) *session.Session {
	s, _ := ctx.Value(sessionKey).(*session.Session)
	return s
}

func withCSRF(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfTokenKey, token)
}

// CSRFToken returns the per-request CSRF token for template injection.
func CSRFToken(ctx context.Context) string {
	t, _ := ctx.Value(csrfTokenKey).(string)
	return t
}

func withTokenID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, tokenIDKey, id)
}

// TokenID returns the authenticated API token id (for audit), or "" on the browser
// plane.
func TokenID(ctx context.Context) string {
	id, _ := ctx.Value(tokenIDKey).(string)
	return id
}
