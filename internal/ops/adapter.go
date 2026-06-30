package ops

import (
	"context"
	"net/http"
	"strings"

	"github.com/daboss2003/mooring/internal/opsclient"
	"github.com/daboss2003/mooring/internal/secret"
)

// Target is everything an adapter needs to reach an app's ops endpoints. The
// host is pinned by BaseURL; the secret travels server-side only (plan §4.1).
type Target struct {
	BaseURL      string
	SecretHeader string
	Secret       secret.Redacted
	BasePath     string // operator-configured fallback prefix; descriptor may override
}

// Doer is the minimal SSRF-safe client surface adapters use. *opsclient.Client
// satisfies it; tests inject a fake. (All host-pinning/rebind defense lives in
// the concrete client — this interface only decouples for testing.)
type Doer interface {
	Get(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted) (*opsclient.Response, error)
	Post(ctx context.Context, base, relPath, secretHeader string, sec secret.Redacted, body []byte) (*opsclient.Response, error)
}

// Adapter is the §4.4 plugin seam: ops.v1 is built in; others (Prometheus,
// plain /healthz) can register so non-Terminus apps light up RICH panels too.
type Adapter interface {
	Name() string
	// Discover classifies the app (RICH/BASIC) and returns its capabilities.
	Discover(ctx context.Context, c Doer, t Target) Discovery
	// Probe fetches and normalizes the live record for a RICH app.
	Probe(ctx context.Context, c Doer, t Target, d Discovery) Result
}

// Discovery is the outcome of the discovery phase (plan §4.1).
type Discovery struct {
	Mode         Mode
	Version      string
	Capabilities []string
	BasePath     string
	Note         string
}

// --- registry ---

var registry = map[string]Adapter{}

// Register adds an adapter (called from init()).
func Register(a Adapter) { registry[a.Name()] = a }

// Lookup returns a registered adapter, defaulting to ops.v1.
func Lookup(name string) Adapter {
	if a, ok := registry[name]; ok {
		return a
	}
	return registry["ops.v1"]
}

func init() { Register(opsV1{}) }

// --- ops.v1 built-in adapter ---

type opsV1 struct{}

func (opsV1) Name() string { return "ops.v1" }

func (a opsV1) Discover(ctx context.Context, c Doer, t Target) Discovery {
	// 1. Public descriptor at /.well-known/ops (no secret).
	if resp, err := c.Get(ctx, t.BaseURL, "/.well-known/ops", "", secret.Redacted{}); err == nil && resp.Status == http.StatusOK {
		if d, ok := parseDescriptor(resp.Body); ok {
			if majorMatches(d.OpsInterfaceVersion) {
				return Discovery{Mode: RICH, Version: d.OpsInterfaceVersion, Capabilities: d.Capabilities, BasePath: cleanBasePath(d.BasePath)}
			}
			// Present but incompatible MAJOR → BASIC + badge note (plan §4).
			return Discovery{Mode: BASIC, Version: d.OpsInterfaceVersion, Note: "ops interface major-version mismatch"}
		}
	}
	// 2. Authenticated fallback: a Terminus-style /health/live (plan §4.1).
	path := joinPath(cleanBasePath(t.BasePath), "/health/live")
	if resp, err := c.Get(ctx, t.BaseURL, path, t.SecretHeader, t.Secret); err == nil && (resp.Status == 200 || resp.Status == 503) {
		if _, ok := parseHealth(resp.Body, a.Name()); ok {
			return Discovery{Mode: RICH, Version: "1.0", Capabilities: []string{"health"}, BasePath: cleanBasePath(t.BasePath)}
		}
	}
	// 3. Otherwise BASIC.
	return Discovery{Mode: BASIC}
}

func (a opsV1) Probe(ctx context.Context, c Doer, t Target, d Discovery) Result {
	res := Result{
		Mode:            RICH,
		Version:         d.Version,
		Capabilities:    d.Capabilities,
		AlertingCapable: hasCapability(d.Capabilities, "alerting"),
	}
	base := d.BasePath
	if base == "" {
		base = cleanBasePath(t.BasePath)
	}

	// health/live → indicators
	livePath := joinPath(base, "/health/live")
	resp, err := c.Get(ctx, t.BaseURL, livePath, t.SecretHeader, t.Secret)
	if err != nil {
		res.Mode = BASIC
		res.Err = "ops health probe failed"
		return res
	}
	if resp.Status != 200 && resp.Status != 503 {
		res.Mode = BASIC
		res.Err = "ops health endpoint returned an unexpected status"
		return res
	}
	inds, ok := parseHealth(resp.Body, a.Name())
	if !ok {
		res.Mode = BASIC
		res.Err = "ops health response did not match the contract"
		return res
	}
	res.Indicators = inds

	// queues (optional capability)
	if hasCapability(d.Capabilities, "queues") {
		if qr, qerr := c.Get(ctx, t.BaseURL, joinPath(base, "/queues"), t.SecretHeader, t.Secret); qerr == nil && qr.Status == 200 {
			if qs, ok := parseQueues(qr.Body); ok {
				res.Queues = qs
			}
		}
	}
	// metrics (optional capability): open-ended monitor cards (database/cache/routes/
	// system/…). A failure here never downgrades the app — health already succeeded.
	if hasCapability(d.Capabilities, "metrics") {
		if mr, merr := c.Get(ctx, t.BaseURL, joinPath(base, "/metrics"), t.SecretHeader, t.Secret); merr == nil && mr.Status == 200 {
			if gs, ok := parseMetrics(mr.Body); ok {
				res.Metrics = gs
			}
		}
	}
	return res
}

// cleanBasePath normalizes a descriptor/operator base path: empty stays empty;
// otherwise it must be a valid relative prefix (else dropped to empty so a
// hostile descriptor can't smuggle anything — the join is re-validated anyway).
func cleanBasePath(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return ""
	}
	if !opsclient.ValidateRelPath(p) {
		return ""
	}
	return p
}

// joinPath joins a (possibly empty) base prefix and an endpoint into a single
// absolute relative path. The result is validated again by the opsclient.
func joinPath(base, endpoint string) string {
	if base == "" {
		return endpoint
	}
	return base + endpoint
}
