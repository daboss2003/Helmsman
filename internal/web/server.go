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

	"github.com/daboss2003/Helmsman/internal/alertstore"
	"github.com/daboss2003/Helmsman/internal/apitoken"
	"github.com/daboss2003/Helmsman/internal/audit"
	"github.com/daboss2003/Helmsman/internal/backupstore"
	"github.com/daboss2003/Helmsman/internal/cfgstore"
	"github.com/daboss2003/Helmsman/internal/config"
	"github.com/daboss2003/Helmsman/internal/crypto"
	"github.com/daboss2003/Helmsman/internal/docker"
	"github.com/daboss2003/Helmsman/internal/dockerexec"
	"github.com/daboss2003/Helmsman/internal/edge"
	"github.com/daboss2003/Helmsman/internal/envstore"
	"github.com/daboss2003/Helmsman/internal/github"
	"github.com/daboss2003/Helmsman/internal/gitstore"
	"github.com/daboss2003/Helmsman/internal/monitor"
	"github.com/daboss2003/Helmsman/internal/ops"
	"github.com/daboss2003/Helmsman/internal/provstore"
	"github.com/daboss2003/Helmsman/internal/scale"
	"github.com/daboss2003/Helmsman/internal/selfheal"
	"github.com/daboss2003/Helmsman/internal/session"
	"github.com/daboss2003/Helmsman/internal/setupstore"
	"github.com/daboss2003/Helmsman/internal/store"
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
	// tokenCIDRUnion is the precomputed union of every ACTIVE API token's CIDR set.
	// The IP gate checks the unspoofable peer against this BEFORE any bearer is
	// parsed (so a token id is never an enumeration oracle and an unknown bearer
	// never triggers a DB lookup before the peer is admitted). It admits ONLY the
	// /api/v1 surface — never the browser admin plane — and the presented token is
	// still re-bound to its OWN CIDR at auth time (the union is a coarse gate, not
	// the grant). Recomputed on construction + SIGHUP; minting a token therefore
	// requires a reload to widen the gate (fail-closed: stale = narrower).
	tokenCIDRUnion []netip.Prefix
}

// loginVerifyConcurrency caps simultaneous argon2id verifications so a burst of
// concurrent logins can't OOM a tiny box (plan §5.1; review #10).
const loginVerifyConcurrency = 2

// apiVerifyConcurrency caps simultaneous API-token argon2id verifications. It is a
// SEPARATE pool from login so that a flood of junk-bearer API requests (each of which
// now pays a decoy verify for timing parity) can never starve operator logins.
const apiVerifyConcurrency = 2

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
	CfgStore   *cfgstore.Store
	GitStore   *gitstore.Store
	ProvStore  *provstore.Store
	SetupStore *setupstore.Store
	AlertStore *alertstore.Store
	EdgeRoutes *edge.RouteStore
	EdgeRecon  *edge.Reconciler      // nil when the edge isn't owned (external/unavailable)
	EdgeReason string                // why the edge isn't owned (banner), "" when owned
	SelfHeal   *selfheal.Store       // supervisor FSM + expected_down leases (may be nil)
	Scaling    *scale.Store          // auto-scaling policies + state (may be nil)
	DockerSem  *dockerexec.Semaphore // global one-docker-child semaphore (shared with Runner)
	APITokens  *apitoken.Store       // scoped read/deploy API tokens (M19; may be nil → /api/v1 disabled)
	Backups    *backupstore.Store    // encrypted Helmsman-state backups (may be nil)
}

// Server holds everything the request pipeline needs. Construct with New.
type Server struct {
	cfg            *config.Config // immutable parts (bind, cookie, edge, session)
	configPath     string
	db             *store.DB
	sessions       *session.Manager
	audit          *audit.Logger
	limiter        *rateLimiter
	templates      *template.Template
	log            *slog.Logger
	verifySem      chan struct{}
	apiVerifySem   chan struct{}                 // separate argon2 pool for /api/v1 (never starves login)
	apiDummyHash   string                        // decoy argon2id hash (token params) for timing parity
	mon            *monitor.Monitor              // read-plane snapshots (may be nil)
	opsStore       *ops.ConfigStore              // ops config (may be nil)
	prober         *ops.Prober                   // ops queue actions (may be nil)
	runner         *dockerexec.Runner            // write-plane exec (may be nil)
	docker         *docker.Client                // read-plane log streaming (may be nil)
	envStore       *envstore.Store               // encrypted env store (may be nil)
	cfgStore       *cfgstore.Store               // managed config files + cert bindings (may be nil)
	gitStore       *gitstore.Store               // repo-path GitOps (may be nil)
	provStore      *provstore.Store              // provisioned apps (modes 1/2; may be nil)
	setupStore     *setupstore.Store             // setup scripts (Mode 3; may be nil)
	alertStore     *alertstore.Store             // alerting channels/rules/state (may be nil)
	edgeRoutes     *edge.RouteStore              // managed-edge routes (may be nil)
	edgeRecon      *edge.Reconciler              // edge config reconciler (nil when edge unowned)
	edgeReason     string                        // why the edge isn't owned (banner)
	selfHeal       *selfheal.Store               // supervisor FSM + expected_down leases (may be nil)
	scaling        *scale.Store                  // auto-scaling policies + state (may be nil)
	circuitClearer func(project, service string) // supervisor clear-circuit (set post-construction)
	apiTokens      *apitoken.Store               // scoped API tokens (M19; nil → /api/v1 disabled)
	backups        *backupstore.Store            // encrypted Helmsman-state backups (may be nil)
	githubClient   *github.Client                // GitHub connect (M20; nil → feature off)
	dockerSem      *dockerexec.Semaphore         // global one-docker-child semaphore (may be nil)
	setupConfirm   *confirmStore                 // single-use setup confirm tokens
	webhookRL      *rateLimiter                  // per-token webhook rate limit
	webhookSeen    *nonceCache                   // webhook replay (timestamp+nonce) defense
	webhookFlash   *tokenFlash                   // one-time rotated-token hand-off (never in URL)
	gitDeploy      *dockerexec.Semaphore         // single-flight repo deploy (1 at a time)
	logStreams     chan struct{}                 // concurrency cap on live log streams
	sec            atomic.Pointer[secState]
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
		cfg:          cfg,
		configPath:   d.ConfigPath,
		db:           d.DB,
		sessions:     session.New(d.DB, cfg.Session.IdleTimeout.D(), cfg.Session.AbsoluteTimeout.D()),
		audit:        audit.New(d.DB, log),
		limiter:      newRateLimiter(300, time.Minute),
		templates:    tmpl,
		log:          log,
		verifySem:    make(chan struct{}, loginVerifyConcurrency),
		apiVerifySem: make(chan struct{}, apiVerifyConcurrency),
		mon:          d.Monitor,
		opsStore:     d.OpsStore,
		prober:       d.Prober,
		runner:       d.Runner,
		docker:       d.Docker,
		envStore:     d.EnvStore,
		cfgStore:     d.CfgStore,
		gitStore:     d.GitStore,
		provStore:    d.ProvStore,
		setupStore:   d.SetupStore,
		alertStore:   d.AlertStore,
		edgeRoutes:   d.EdgeRoutes,
		edgeRecon:    d.EdgeRecon,
		edgeReason:   d.EdgeReason,
		selfHeal:     d.SelfHeal,
		scaling:      d.Scaling,
		apiTokens:    d.APITokens,
		backups:      d.Backups,
		dockerSem:    d.DockerSem,
		setupConfirm: newConfirmStore(5 * time.Minute),
		webhookRL:    newRateLimiter(30, time.Minute),
		webhookSeen:  newNonceCache(webhookNonceTTL),
		webhookFlash: newTokenFlash(2 * time.Minute),
		gitDeploy:    dockerexec.NewSemaphore(),
		logStreams:   make(chan struct{}, maxConcurrentLogStreams),
	}
	sec, err := buildSecState(cfg)
	if err != nil {
		return nil, err
	}
	sec.tokenCIDRUnion = s.activeTokenUnion(context.Background())
	s.sec.Store(sec)
	// A decoy argon2id hash with the SAME params a real token uses, so the not-found
	// path can pay an equal-cost verify (timing parity — an unknown/expired/revoked id
	// must be latency-indistinguishable from a live one; M19 review).
	apiDummy, err := crypto.HashPassword([]byte("\x00helmsman-api-decoy"), crypto.DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("web: build api decoy hash: %w", err)
	}
	s.apiDummyHash = apiDummy
	// "Connect with GitHub" is on only when the operator configured an OAuth App. The
	// HTTP client has a bounded timeout; outbound egress to GitHub is the operator's
	// systemd egress-allowlist concern.
	if cfg.GitHub.Enabled() {
		s.githubClient = github.New(&http.Client{Timeout: 30 * time.Second}, "", "")
	}
	return s, nil
}

// activeTokenUnion recomputes the union of every active API token's CIDR set. On any
// store error it returns nil (admitting NO token CIDRs) — a read failure must never
// widen the IP gate, only narrow it (fail-closed).
func (s *Server) activeTokenUnion(ctx context.Context) []netip.Prefix {
	if s.apiTokens == nil {
		return nil
	}
	union, err := s.apiTokens.ActiveCIDRUnion(ctx, time.Now())
	if err != nil {
		s.log.Warn("apitoken: CIDR-union recompute failed; admitting no token CIDRs (fail-closed)", "err", err)
		return nil
	}
	return union
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
	sec.tokenCIDRUnion = s.activeTokenUnion(ctx)
	s.sec.Store(sec)
	_ = s.audit.Log(ctx, audit.Event{
		Action: "config_reload", Outcome: audit.OK, Level: audit.Security,
		Detail: "allowlist + auth + token CIDR-union reloaded",
	})
	return nil
}

// Handler assembles the full middleware chain in pipeline order.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public (auth-exempt) routes.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	// Webhook: allowlist-exempt (CI egress) + auth-exempt, but HMAC-gated,
	// replay-protected, per-token rate-limited, and FETCH-ONLY (plan §5.7).
	mux.HandleFunc("POST /webhook/{token}", capBody(1<<20, s.handleWebhook))
	mux.HandleFunc("GET /login", s.withCSRFToken(s.handleLoginGet))
	// capBody is OUTERMOST so the body is bounded before requireCSRF parses it.
	mux.HandleFunc("POST /login", capBody(loginBodyLimit, s.requireCSRF(s.handleLoginPost)))
	mux.HandleFunc("POST /logout", capBody(loginBodyLimit, s.requireCSRF(s.handleLogout)))

	// Static assets (behind the allowlist, but no auth — the login page needs CSS).
	// The operator theme overlay (M7) is a more-specific route that takes
	// precedence over the embedded FileServer; it reads a fixed data-dir file.
	mux.HandleFunc("GET /static/theme.css", s.handleThemeCSS)
	staticFS, _ := fs.Sub(embeddedAssets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheControl(http.FileServer(http.FS(staticFS)))))

	// Protected routes.
	mux.HandleFunc("GET /{$}", s.requireAuth(s.withCSRFToken(s.handleHome)))
	mux.HandleFunc("GET /partials/overview", s.requireAuth(s.handleOverviewPartial))
	mux.HandleFunc("GET /incidents", s.requireAuth(s.withCSRFToken(s.handleIncidents)))
	mux.HandleFunc("GET /apps", s.requireAuth(s.withCSRFToken(s.handleAppsList)))
	// Host metric series for the live dashboard charts (read plane; cookie-authed).
	mux.HandleFunc("GET /partials/metrics.json", s.requireAuth(s.handleMetricsHistory))
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
	mux.HandleFunc("POST /apps/{project}/supervisor/clear", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSupervisorClear))))
	mux.HandleFunc("POST /apps/{project}/scaling", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleScalingSave))))
	mux.HandleFunc("GET /apps/{project}/services/{service}/logs", s.requireAuth(s.handleServiceLogs))
	// Env settings (M5): literals + write-only secrets, masked reveal, history.
	mux.HandleFunc("GET /apps/{project}/env", s.requireAuth(s.withCSRFToken(s.handleEnvGet)))
	mux.HandleFunc("POST /apps/{project}/env", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSaveLiterals))))
	mux.HandleFunc("POST /apps/{project}/env/secret", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEnvSetSecret))))
	mux.HandleFunc("POST /apps/{project}/env/secret/remove", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRemoveSecret))))
	mux.HandleFunc("POST /apps/{project}/env/reveal", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvReveal))))
	mux.HandleFunc("POST /apps/{project}/env/rollback", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEnvRollback))))
	// Managed config files + cert bindings (M5b).
	mux.HandleFunc("GET /apps/{project}/config-files", s.requireAuth(s.withCSRFToken(s.handleConfigFilesGet)))
	mux.HandleFunc("POST /apps/{project}/config-files", capBody(256<<10, s.requireAuth(s.requireCSRF(s.handleConfigFileSave))))
	mux.HandleFunc("POST /apps/{project}/config-files/preview", capBody(256<<10, s.requireAuth(s.requireCSRF(s.handleConfigFilePreview))))
	mux.HandleFunc("POST /apps/{project}/config-files/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleConfigFileDelete))))
	mux.HandleFunc("POST /apps/{project}/cert-bindings", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleCertBindingSave))))
	mux.HandleFunc("POST /apps/{project}/cert-bindings/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleCertBindingDelete))))
	// App provisioning wizard (M8, modes 1 & 2). validate is a dry preview;
	// commit/deploy are §0-gated write-plane actions.
	mux.HandleFunc("GET /apps/new", s.requireAuth(s.withCSRFToken(s.handleProvisionNew)))
	mux.HandleFunc("POST /apps/new/validate", capBody(1<<20, s.requireAuth(s.requireCSRF(s.handleProvisionValidate))))
	mux.HandleFunc("POST /apps/new/commit", capBody(1<<20, s.requireAuth(s.requireCSRF(s.handleProvisionCommit))))
	mux.HandleFunc("POST /apps/{project}/provision-deploy", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleProvisionDeploy))))
	mux.HandleFunc("POST /apps/{project}/provision-delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleProvisionDelete))))
	// Setup-script sandbox (M9, Mode 3 — OFF by default, hard-gated). The run is
	// confirm-token-gated and fail-closed; it never runs from an auto path.
	mux.HandleFunc("GET /apps/{project}/setup", s.requireAuth(s.withCSRFToken(s.handleSetupGet)))
	mux.HandleFunc("POST /apps/{project}/setup/sync", capBody(1<<20, s.requireAuth(s.requireCSRF(s.handleSetupSync))))
	mux.HandleFunc("POST /apps/{project}/setup/run", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSetupRun))))
	mux.HandleFunc("POST /apps/{project}/setup/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleSetupDelete))))
	// Repo-path GitOps (M6).
	mux.HandleFunc("GET /git/new", s.requireAuth(s.withCSRFToken(s.handleGitNew)))
	mux.HandleFunc("POST /git", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitSave))))
	mux.HandleFunc("GET /apps/{project}/git", s.requireAuth(s.withCSRFToken(s.handleGitGet)))
	mux.HandleFunc("POST /apps/{project}/git", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitSave))))
	mux.HandleFunc("POST /apps/{project}/git/fetch", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitFetch))))
	mux.HandleFunc("POST /apps/{project}/git/deploy", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitDeploy))))
	mux.HandleFunc("POST /apps/{project}/git/webhook-rotate", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitWebhookRotate))))
	// Connect with GitHub (M20): OAuth web flow → repo picker → auto deploy-key.
	// The callback is a cross-site navigation back from github.com, so the Strict
	// session cookie isn't sent — it is authenticated by the single-use Lax OAuth
	// state cookie instead (set only by the authenticated+CSRF'd connect action).
	mux.HandleFunc("POST /github/connect", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitHubConnect))))
	mux.HandleFunc("GET /github/callback", s.handleGitHubCallback)
	mux.HandleFunc("GET /github/repos", s.requireAuth(s.handleGitHubRepos))
	mux.HandleFunc("POST /github/connect-repo", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleGitHubConnectRepo))))
	mux.HandleFunc("POST /github/disconnect", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleGitHubDisconnect))))
	// Managed edge (M11): per-app public routes (Caddy/ACME). The whole config is
	// re-rendered + pushed on every change; the operator never edits Caddy.
	mux.HandleFunc("GET /edge", s.requireAuth(s.withCSRFToken(s.handleEdge)))
	mux.HandleFunc("POST /edge/routes", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleEdgeRouteSave))))
	mux.HandleFunc("POST /edge/routes/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleEdgeRouteDelete))))
	// Alerting (M10): channels + rules + open alerts. Read-and-notify only.
	mux.HandleFunc("GET /alerts", s.requireAuth(s.withCSRFToken(s.handleAlerts)))
	mux.HandleFunc("POST /alerts/channels", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleAlertChannelSave))))
	mux.HandleFunc("POST /alerts/channels/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertChannelDelete))))
	mux.HandleFunc("POST /alerts/channels/test", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertChannelTest))))
	mux.HandleFunc("POST /alerts/rules", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleAlertRuleSave))))
	mux.HandleFunc("POST /alerts/rules/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertRuleDelete))))
	mux.HandleFunc("POST /alerts/ack", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertAck))))
	mux.HandleFunc("POST /alerts/silence", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAlertSilence))))
	mux.HandleFunc("GET /events", s.requireAuth(s.withCSRFToken(s.handleEvents)))
	// Operator UI prefs (M7): persisted tile order. UI-only, never Tier-1.
	mux.HandleFunc("POST /settings/tile-order", capBody(64<<10, s.requireAuth(s.requireCSRF(s.handleTileOrder))))
	// API tokens (M19): read-only view + revoke. Minting stays CLI-only by design.
	mux.HandleFunc("GET /settings/api-tokens", s.requireAuth(s.withCSRFToken(s.handleAPITokens)))
	mux.HandleFunc("POST /settings/api-tokens/revoke", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleAPITokenRevoke))))
	// Backups: encrypted Helmsman-state snapshots — view, create, download, delete.
	mux.HandleFunc("GET /settings/backups", s.requireAuth(s.withCSRFToken(s.handleBackups)))
	mux.HandleFunc("GET /settings/backups/download", s.requireAuth(s.handleBackupDownload))
	mux.HandleFunc("POST /settings/backups/create", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleBackupCreate))))
	mux.HandleFunc("POST /settings/backups/delete", capBody(loginBodyLimit, s.requireAuth(s.requireCSRF(s.handleBackupDelete))))

	// Scoped machine API (M19, plan §17.1): bearer-ONLY, cookie-REJECTING,
	// CSRF-EXEMPT (no ambient credential to abuse). requireToken is the sole gate —
	// these routes are deliberately NOT wrapped in requireAuth/requireCSRF. A token
	// can carry only the read scopes + deploy:write:<slug>; nothing here can express
	// a Tier-1 / reveal / setup / mint capability.
	mux.HandleFunc("GET /api/v1/status", s.requireToken(fixedScope("status:read"), s.handleAPIStatus))
	mux.HandleFunc("GET /api/v1/metrics", s.requireToken(fixedScope("metrics:read"), s.handleAPIMetrics))
	mux.HandleFunc("GET /api/v1/events", s.requireToken(fixedScope("events:read"), s.handleAPIEvents))
	mux.HandleFunc("GET /api/v1/audit", s.requireToken(fixedScope("audit:read"), s.handleAPIAudit))
	mux.HandleFunc("POST /api/v1/apps/{project}/deploy", capBody(1<<20, s.requireToken(deployScope, s.handleAPIDeploy)))

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
