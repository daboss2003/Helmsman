package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/crypto"
	"github.com/helmsman/helmsman/internal/store"
)

const testPassword = "test-password-123"

type testEnv struct {
	srv *Server
}

func buildServer(t *testing.T, allowlist []string, trustProxy bool, trustedProxies []string, totpSecret string) *testEnv {
	t.Helper()
	hash, err := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))

	var b strings.Builder
	fmt.Fprintf(&b, "bind_addr: \"127.0.0.1:9000\"\n")
	fmt.Fprintf(&b, "encryption_key: %q\n", key)
	fmt.Fprintf(&b, "ip_allowlist:\n")
	for _, a := range allowlist {
		fmt.Fprintf(&b, "  - %q\n", a)
	}
	if trustProxy {
		fmt.Fprintf(&b, "trust_proxy: true\ntrusted_proxies:\n")
		for _, p := range trustedProxies {
			fmt.Fprintf(&b, "  - %q\n", p)
		}
	}
	fmt.Fprintf(&b, "auth:\n  username: \"operator\"\n  password_hash: %q\n", hash)
	if totpSecret != "" {
		fmt.Fprintf(&b, "  totp_secret: %q\n", totpSecret)
	}
	fmt.Fprintf(&b, "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n")

	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	srv, err := New(cfg, Deps{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{srv: srv}
}

// req drives one request through the full middleware chain.
func (e *testEnv) req(t *testing.T, method, path, peer string, headers map[string]string, cookies []*http.Cookie, form url.Values) *http.Response {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = peer
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, r)
	return rec.Result()
}

func cookieByName(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- exit-criteria tests ---

func TestHealthzIsPublic(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, false, nil, "")
	// peer is NOT allowlisted, but /healthz is exempt.
	resp := e.req(t, "GET", "/healthz", "9.9.9.9:1234", nil, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz from non-allowlisted peer = %d, want 200", resp.StatusCode)
	}
}

func TestNonAllowlistedGets404(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, false, nil, "")
	resp := e.req(t, "GET", "/", "9.9.9.9:1234", nil, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-allowlisted GET / = %d, want 404 (bare notfound)", resp.StatusCode)
	}
}

func TestAllowlistedReachesLoginRedirect(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	resp := e.req(t, "GET", "/", "127.0.0.1:5555", nil, nil, nil)
	// reaches the router; unauthenticated → redirect to /login
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("allowlisted GET / = %d, want 303 redirect to /login", resp.StatusCode)
	}
}

// The headline red-team test (plan M1 exit + §5.2): a forged XFF from an
// untrusted peer must NOT bypass the allowlist.
func TestSpoofedXFFRejected(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, false, nil, "")
	// peer 9.9.9.9 is not trusted; XFF claims the allowlisted IP.
	resp := e.req(t, "GET", "/", "9.9.9.9:1234",
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("spoofed XFF from untrusted peer = %d, want 404 (XFF must be ignored)", resp.StatusCode)
	}
}

func TestTrustedProxySingleXFFAccepted(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, true, []string{"127.0.0.1/32"}, "")
	resp := e.req(t, "GET", "/", "127.0.0.1:1234",
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("trusted proxy + single allowlisted XFF = %d, want 303 (reaches router)", resp.StatusCode)
	}
}

// An appended XFF chain (proxy appends instead of overwrites) must fail closed.
func TestAppendedXFFChainRejected(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, true, []string{"127.0.0.1/32"}, "")
	resp := e.req(t, "GET", "/", "127.0.0.1:1234",
		map[string]string{"X-Forwarded-For": "203.0.113.7, 6.6.6.6"}, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("appended XFF chain = %d, want 404 (must not trust appended values)", resp.StatusCode)
	}
}

// A trusted proxy that forgets to set XFF: peer is the edge (not allowlisted) → deny.
func TestTrustedProxyMissingXFFDenied(t *testing.T) {
	e := buildServer(t, []string{"203.0.113.7/32"}, true, []string{"127.0.0.1/32"}, "")
	resp := e.req(t, "GET", "/", "127.0.0.1:1234", nil, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("trusted proxy missing XFF = %d, want 404 (fail closed)", resp.StatusCode)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	resp := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	h := resp.Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("missing/weak CSP: %q", h.Get("Content-Security-Policy"))
	}
	if strings.Contains(h.Get("Content-Security-Policy"), "unsafe-inline") {
		t.Errorf("CSP contains unsafe-inline")
	}
	for _, want := range []string{"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Strict-Transport-Security"} {
		if h.Get(want) == "" {
			t.Errorf("missing security header %s", want)
		}
	}
}

// --- login + CSRF flow ---

// login performs the full GET-then-POST login dance and returns the session cookie.
func (e *testEnv) login(t *testing.T, peer, password, totp string) (*http.Cookie, *http.Response) {
	t.Helper()
	get := e.req(t, "GET", "/login", peer, nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie issued on GET /login")
	}
	form := url.Values{
		"username":   {"operator"},
		"password":   {password},
		"csrf_token": {csrf.Value},
	}
	if totp != "" {
		form.Set("totp", totp)
	}
	post := e.req(t, "POST", "/login", peer,
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{csrf}, form)
	return cookieByName(post, e.srv.cookieName()), post
}

func TestSuccessfulLogin(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, post := e.login(t, "127.0.0.1:1", testPassword, "")
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("login POST = %d, want 303", post.StatusCode)
	}
	if sess == nil || sess.Value == "" {
		t.Fatal("no session cookie set on successful login")
	}
	if !sess.HttpOnly || !sess.Secure || sess.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie attrs weak: HttpOnly=%v Secure=%v SameSite=%v", sess.HttpOnly, sess.Secure, sess.SameSite)
	}
	// authenticated GET / now returns 200
	home := e.req(t, "GET", "/", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if home.StatusCode != http.StatusOK {
		t.Errorf("authenticated GET / = %d, want 200", home.StatusCode)
	}
}

func TestWrongPasswordNoSession(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, post := e.login(t, "127.0.0.1:1", "wrong-password", "")
	if sess != nil {
		t.Error("session issued for wrong password")
	}
	if post.StatusCode != http.StatusOK { // re-render login with error
		t.Errorf("wrong password = %d, want 200 (re-render)", post.StatusCode)
	}
}

func TestUnknownUsernameNoSession(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	form := url.Values{"username": {"intruder"}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	post := e.req(t, "POST", "/login", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf}, form)
	if cookieByName(post, e.srv.cookieName()) != nil {
		t.Error("session issued for unknown username")
	}
}

func TestCSRFMissingTokenRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	form := url.Values{"username": {"operator"}, "password": {testPassword}}
	post := e.req(t, "POST", "/login", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"}, nil, form)
	if post.StatusCode != http.StatusForbidden {
		t.Errorf("POST /login without CSRF = %d, want 403", post.StatusCode)
	}
}

func TestCSRFBadOriginRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	form := url.Values{"username": {"operator"}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	post := e.req(t, "POST", "/login", "127.0.0.1:1",
		map[string]string{"Origin": "https://evil.example"}, []*http.Cookie{csrf}, form)
	if post.StatusCode != http.StatusForbidden {
		t.Errorf("POST /login with bad Origin = %d, want 403", post.StatusCode)
	}
}

func TestCSRFTokenMismatchRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	form := url.Values{"username": {"operator"}, "password": {testPassword}, "csrf_token": {"forged-token"}}
	post := e.req(t, "POST", "/login", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf}, form)
	if post.StatusCode != http.StatusForbidden {
		t.Errorf("CSRF token mismatch = %d, want 403", post.StatusCode)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	// logout needs CSRF too
	get := e.req(t, "GET", "/", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		// CSRF cookie may have been set earlier; re-fetch from a page render
		get = e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
		csrf = cookieByName(get, e.srv.csrfCookieName())
	}
	form := url.Values{"csrf_token": {csrf.Value}}
	e.req(t, "POST", "/logout", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, form)
	// session should now be revoked server-side
	home := e.req(t, "GET", "/", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if home.StatusCode != http.StatusSeeOther {
		t.Errorf("after logout, GET / = %d, want 303 (session revoked)", home.StatusCode)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	for i := 0; i < peerMaxFailures+1; i++ {
		e.login(t, "127.0.0.1:1", "wrong", "")
	}
	// even with the CORRECT password, the peer/user is now locked out
	sess, post := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess != nil {
		t.Error("login succeeded despite lockout")
	}
	body := readBody(post)
	if !strings.Contains(body, "Too many attempts") {
		t.Errorf("expected lockout message, got: %s", body)
	}
}

func TestTOTPRequiredWhenConfigured(t *testing.T) {
	secret, _ := crypto.GenerateTOTPSecret()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, secret)
	// correct password but no TOTP → denied
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess != nil {
		t.Error("login succeeded without required TOTP")
	}
}

// review #4: a TOTP code must be single-use within its window.
func TestTOTPReplayRejected(t *testing.T) {
	secret, _ := crypto.GenerateTOTPSecret()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, secret)
	code, err := crypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sess1, _ := e.login(t, "127.0.0.1:1", testPassword, code)
	if sess1 == nil {
		t.Fatal("first login with a valid TOTP code failed")
	}
	sess2, _ := e.login(t, "127.0.0.1:1", testPassword, code)
	if sess2 != nil {
		t.Error("the same TOTP code was accepted twice (replay)")
	}
}

// review #17: a same-host but http (non-loopback) Origin must not be treated as
// same-origin with the HTTPS admin plane.
func TestOriginSchemeMismatchRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	form := url.Values{"username": {"operator"}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	// Host is example.com (httptest default); Origin host matches but scheme is http.
	post := e.req(t, "POST", "/login", "127.0.0.1:1",
		map[string]string{"Origin": "http://example.com"}, []*http.Cookie{csrf}, form)
	if post.StatusCode != http.StatusForbidden {
		t.Errorf("http-scheme Origin against https admin plane = %d, want 403", post.StatusCode)
	}
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
