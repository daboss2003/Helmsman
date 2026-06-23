package web

import "net/http"

// sessionStatusPath is the non-refreshing session liveness probe. The session
// middleware special-cases it to use Peek (not Load), so polling it never advances
// last_seen — the focus-loss watchdog must be able to observe an idle-out, not delay it.
const sessionStatusPath = "/session/status"

// handleSessionStatus reports whether the caller still has a live session, WITHOUT
// keeping it alive. 204 = logged in; 401 = logged out (idle/absolute expiry, or no
// cookie). The dashboard's focus-loss watchdog polls this once it's been unfocused past
// the idle window and redirects to /login on 401 — so the logout is both enforced
// server-side (the session is already gone) and surfaced in the UI. It carries no
// session data, so it is deliberately auth-exempt and handles the unauthenticated case
// itself rather than via requireAuth (which would 302 a fetch).
func (s *Server) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if SessionFrom(r.Context()) == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
