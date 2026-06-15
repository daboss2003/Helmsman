package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/daboss2003/Helmsman/internal/crypto"
)

// CSRF model (plan §5.4): a synchronizer/double-submit token in an HttpOnly
// `<prefix>csrf` cookie, mirrored into rendered forms; verified together with an
// Origin/Referer check on every state-changing request. SameSite=Strict is set
// on both the session and CSRF cookies.

const csrfCookieSuffix = "csrf"
const csrfTokenBytes = 32

func (s *Server) csrfCookieName() string { return s.cfg.Cookie.Prefix + csrfCookieSuffix }

// ensureCSRFToken returns the request's CSRF token, issuing a new cookie if
// absent. Safe to call on GET (form rendering) and before verifying on POST.
func (s *Server) ensureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(s.csrfCookieName()); err == nil && c.Value != "" {
		return c.Value
	}
	token := crypto.RandomToken(csrfTokenBytes)
	http.SetCookie(w, &http.Cookie{
		Name:     s.csrfCookieName(),
		Value:    token,
		Path:     s.cookiePath(), // co-scope with the session cookie (review #18)
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

// withCSRFToken issues (if needed) and exposes the CSRF token to the handler via
// context, for template injection. For safe (GET/HEAD) routes that render forms.
func (s *Server) withCSRFToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.ensureCSRFToken(w, r)
		next(w, r.WithContext(withCSRF(r.Context(), token)))
	}
}

// requireCSRF gates a state-changing handler: it checks Origin/Referer against
// the request host AND a constant-time token match between the submitted value
// (header X-CSRF-Token or form field csrf_token) and the cookie. 403 on any
// mismatch (pipeline step 7).
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !originOK(r) {
			http.Error(w, "forbidden: bad origin", http.StatusForbidden)
			return
		}
		cookie, err := r.Cookie(s.csrfCookieName())
		if err != nil || cookie.Value == "" {
			http.Error(w, "forbidden: missing csrf token", http.StatusForbidden)
			return
		}
		submitted := r.Header.Get("X-CSRF-Token")
		if submitted == "" {
			submitted = r.FormValue("csrf_token")
		}
		if submitted == "" || !crypto.ConstantTimeEqualString(submitted, cookie.Value) {
			http.Error(w, "forbidden: csrf token mismatch", http.StatusForbidden)
			return
		}
		// Keep the token in context so a re-rendered form carries it forward.
		next(w, r.WithContext(withCSRF(r.Context(), cookie.Value)))
	}
}

// originOK requires the Origin (or, fallback, Referer) to match the request
// host AND scheme. A state-changer with neither header is rejected — modern
// browsers always send Origin on cross-form POSTs. The scheme is checked
// (review #17): only https is accepted, except http is allowed for loopback (the
// documented SSH-tunnel access path) so a same-host plaintext origin cannot be
// treated as same-origin with the HTTPS admin plane.
func originOK(r *http.Request) bool {
	host := r.Host
	if o := r.Header.Get("Origin"); o != "" {
		return sameOrigin(o, host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return sameOrigin(ref, host)
	}
	return false
}

func sameOrigin(raw, host string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Host, host) {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHostname(u.Hostname())
	default:
		return false
	}
}

func isLoopbackHostname(h string) bool {
	if h == "localhost" {
		return true
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.IsLoopback()
	}
	return false
}
