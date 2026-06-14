// Package web implements the HTTP control plane: the fail-closed request
// pipeline (plan §5), the auth/session handlers, and the admin UI shell. It
// binds loopback only (plan §3); the managed edge fronts the public ports.
package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/helmsman/helmsman/internal/audit"
	"github.com/helmsman/helmsman/internal/config"
	"github.com/helmsman/helmsman/internal/crypto"
	"github.com/helmsman/helmsman/internal/docker"
	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/envstore"
	"github.com/helmsman/helmsman/internal/monitor"
	"github.com/helmsman/helmsman/internal/ops"
	"github.com/helmsman/helmsman/internal/session"
	"github.com/helmsman/helmsman/internal/store"
)

// maxConcurrentLogStreams caps simultaneous live log streams (each holds a
// socket-proxy connection); excess returns 503.
const maxConcurrentLogStreams = 8

// secState is the slice of config that SIGHUP can hot-reload (plan §5.1:
// allowlist + auth, never keys/bind). It is swapped atomically so the request
// hot path never races a reload.
type secState struct {
	trustProxy     bool
	allowlist      []netip.Prefix
	trustedProxies []netip.Prefix
	username       string
	passwordHash   string
	totpSecret     string
	dummyHash      string
}

// loginVerifyConcurrency caps simultaneous argon2id verifications so a burst of
// concurrent logins can't OOM a tiny box (plan §5.1; review #10).
const loginVerifyConcurrency = 2

// loginBodyLimit bounds the POST /login + logout request body — username +
// password + totp + csrf_token never approach this (review #11).
const loginBodyLimit = 64 << 10

// Deps are the (mostly optional) collaborators a Server uses. Anything nil
// degrades gracefully (e.g. nil mon → "collecting…"; nil runner → write plane
// shown disabled).
type Deps struct {
	DB         *store.DB
	ConfigPath string // for SIGHUP allowlist+auth reload
	Log        *slog.Logger
	Monitor    *monitor.Monitor
	OpsStore   *ops.ConfigStore
	Prober     *ops.Prober
	Runner     *dockerexec.Runner
	Docker     *docker.Client
	EnvStore   *envstore.Store
}

// Server holds everything the request pipeline needs. Construct with New.
type Server struct {
	cfg        *config.Config // immutable parts (bind, cookie, edge, session)
	configPath string
	db         *store.DB
	sessions   *session.Manager
	audit      *audit.Logger
	limiter    *rateLimiter
	templates  *template.Template
	log        *slog.Logger
	verifySem  chan struct{}
	mon        *monitor.Monitor   // read-plane snapshots (may be nil)
	opsStore   *ops.ConfigStore   // ops config (may be nil)
	prober     *ops.Prober        // ops queue actions (may be nil)
	runner     *dockerexec.Runner // write-plane exec (may be nil)
	docker     *docker.Client     // read-plane log streaming (may be nil)
	envStore   *envstore.Store    // encrypted env store (may be nil)
	logStreams chan struct{}      // concurrency cap on live log streams
	sec        atomic.Pointer[secState]
}

// New builds a Server from a validated config and its dependencies.
func New(cfg *config.Config, d Deps) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:        cfg,
		configPath: d.ConfigPath,
		db:         d.DB,
		sessions:   session.New(d.DB, cfg.Session.IdleTimeout.D(), cfg.Session.AbsoluteTimeout.D()),
		audit:      audit.New(d.DB, log),
		limiter:    newRateLimiter(300, time.Minute),
		templates:  tmpl,
		log:        log,
		verifySem:  make(chan struct{}, loginVerifyConcurrency),
		mon:        d.Monitor,
		opsStore:   d.OpsStore,
		prober:     d.Prober,
		runner:     d.Runner,
		docker:     d.Docker,
		envStore:   d.EnvStore,
		logStreams: make(chan struct{}, maxConcurrentLogStreams),
	}
	sec, err := buildSecState(cfg)
	if err != nil {
		return nil, err
	}
	s.sec.Store(sec)
	return s, nil
}

func buildSecState(cfg *config.Config) (*secState, error) {
	// Precompute a dummy argon2id hash with the SAME params as the operator's
	// real hash, so a username miss runs an equal-cost verify (timing parity).
	params, _, _, err := crypto.ParseArgon2(cfg.Auth.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("web: parse password hash: %w", err)
	}
	dummy, err := crypto.HashPassword([]byte("\x00helmsman-dummy"), params)
	if err != nil {
		return nil, fmt.Errorf("web: build dummy hash: %w", err)
	}
	return &secState{
		trustProxy:     cfg.TrustProxy,
		allowlist:      cfg.Allowlist(),
		trustedProxies: cfg.TrustedProxyPrefixes(),
		username:       cfg.Auth.Username,
		passwordHash:   cfg.Auth.PasswordHash,
		totpSecret:     cfg.Auth.TOTPSecret,
		dummyHash:      dummy,
	}, nil
}

func (s *Server) security() *secState { return s.sec.Load() }

// Reload re-reads the config file and hot-swaps the allowlist + auth (plan §5.1).
// On any validation error the current state is kept (fail-closed: a bad edit
// never widens or breaks the running policy).
func (s *Server) Reload(ctx context.Context) error {
	cfg, err := config.Load(s.configPath)
	if err != nil {
		_ = s.audit.Log(ctx, audit.Event{
			Action: "config_reload", Outcome: audit.Error, Level: audit.Security,
			Detail: "rejected invalid config; keeping previous",
		})
		return err
	}
	sec, err := buildSecState(cfg)
	if err != nil {
		return err
	}
	s.sec.Store(sec)
	_ = s.audit.Log(ctx, audit.Event{
		Action: "config_reload", Outcome: audit.OK, Level: audit.Security,
		Detail: "allowlist + auth reloaded",
	})
	return nil
}

// Handler assembles the full middleware chain in pipeline order.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public (auth-exempt) routes.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /login", s.withCSRFToken(s.handleLoginGet))
	// capBody is OUTERMOST so the body is bounded before requireCSRF parses it.
	mux.HandleFunc("POST /login", capBody(loginBodyLimit, s.requireCSRF(s.handleLoginPost)))
	mux.HandleFunc("POST /logout", capBody(loginBodyLimit, s.requireCSRF(s.handleLogout)))

	// Static assets (behind the allowlist, but no auth — the login page needs CSS).
	staticFS, _ := fs.Sub(embeddedAssets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheControl(http.FileServer(http.FS(staticFS)))))

	// Protected routes.
	mux.HandleFunc("GET /{$}", s.requireAuth(s.withCSRFToken(s.handleHome)))
	mux.HandleFunc("GET /partials/overview", s.requireAuth(s.handleOverviewPartial))
	mux.HandleFunc("GET /apps/{project}", s.requireAuth(s.withCSRFToken(s.handleApp)))
	mux.HandleFunc("GET /partials/app/{project}", s.requireAuth(s.withCSRFToken(s.handleAppPartial)))
	// App Ops Interface (M3): config form + server-side-proxied queue actions.
	mux.HandleFunc("GET /apps/{project}/ops-config", s.requireAuth(s.withCSRFToken(s.handleOpsConfigGet)))
	mux.HandleFunc("POST /apps/{project}/ops-config", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleOpsConfigPost))))
	mux.HandleFunc("POST /apps/{project}/queues/{queue}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleQueueAction))))
	// Lifecycle (M4 write plane): whole-project + per-service. Literal sub-routes
	// (ops-config, queues) are more specific and take precedence over {action}.
	mux.HandleFunc("POST /apps/{project}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAppAction))))
	mux.HandleFunc("POST /apps/{project}/services/{service}/{action}", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleServiceAction))))
	mux.HandleFunc("GET /apps/{project}/services/{service}/logs", s.requireAuth(s.handleServiceLogs))
	mux.HandleFunc("GET /apps/{project}/compose", s.requireAuth(s.withCSRFToken(s.handleComposeView)))
	// Env settings (M5): literals + write-only secrets, masked reveal, history.
	mux.HandleFunc("GET /apps/{project}/env", s.requireAuth(s.withCSRFToken(s.handleEnvGet)))
	mux.HandleFunc("POST /apps/{project}/env", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSaveLiterals))))
	mux.HandleFunc("POST /apps/{project}/env/secret", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSetSecret))))
	mux.HandleFunc("POST /apps/{project}/env/secret/remove", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRemoveSecret))))
	mux.HandleFunc("POST /apps/{project}/env/reveal", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvReveal))))
	mux.HandleFunc("POST /apps/{project}/env/rollback", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRollback))))
	mux.HandleFunc("GET /events", s.requireAuth(s.withCSRFToken(s.handleEvents)))

	// Pipeline order: allowlist → headers → rate limit → session loader → router.
	// (auth + CSRF are applied per-route inside the mux.)
	var h http.Handler = mux
	h = s.sessionMiddleware(h)
	h = s.rateLimitMiddleware(h)
	h = s.securityHeadersMiddleware(h)
	h = s.allowlistMiddleware(h)
	return h
}

// Run starts the loopback HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.BindAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// --- cookie helpers (plan §5.3) ---

func (s *Server) cookieName() string { return s.cfg.Cookie.Prefix + "session" }

func (s *Server) cookiePath() string {
	if s.cfg.Cookie.Prefix == "__Secure-" && s.cfg.Cookie.BasePath != "" {
		return s.cfg.Cookie.BasePath
	}
	return "/"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, rawID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    rawID,
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   true, // __Host-/__Secure- prefixes require it; localhost is a secure context
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// auditDeny records an allowlist denial (called from the allowlist middleware).
func (s *Server) auditDeny(r *http.Request, peer, client netip.Addr) {
	_ = s.audit.Log(r.Context(), audit.Event{
		IP: peer.String(), Action: "allowlist_deny", Outcome: audit.Deny, Level: audit.Security,
		Target: r.URL.Path, Detail: "resolved client " + client.String(),
	})
}
