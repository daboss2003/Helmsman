package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// ServiceResolver maps (project, service) → a routable container bridge IP, via the
// read-only socket-proxy. ok=false when no running replica is found. It exists because
// the control plane is a host process that cannot resolve a compose service name (those
// live only on Docker's internal DNS) — so a base_url like http://api:3000 must be
// rewritten to the container's IP before the prober dials it. nil disables the rewrite
// (only literal-IP base_urls work then).
type ServiceResolver func(ctx context.Context, project, service string) (ip string, ok bool)

// Prober runs discovery + probe for one app per call (the monitor drives the
// cadence: sequential + jittered, plan §4). It also persists the snapshot ring
// and performs server-side-proxied queue actions.
type Prober struct {
	store    *ConfigStore
	client   Doer
	db       *store.DB
	resolve  ServiceResolver // rewrites a service-name base_url to a bridge IP; nil = no rewrite
	ringSize int             // retained samples per app
	sparkN   int             // samples returned for the sparkline
}

// NewProber builds a Prober. client is the SSRF-safe outbound client; resolve rewrites a
// service-name base_url to the backing container's bridge IP (nil = literal-IP only).
func NewProber(cs *ConfigStore, client Doer, db *store.DB, resolve ServiceResolver) *Prober {
	return &Prober{store: cs, client: client, db: db, resolve: resolve, ringSize: 100, sparkN: 60}
}

// resolveBase rewrites a service-name base_url to the backing container's bridge IP
// (scoped to project). A literal-IP host, or a nil resolver, is returned unchanged.
// Scheme, port, and path are preserved.
func (p *Prober) resolveBase(ctx context.Context, project, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("bad base_url")
	}
	host := u.Hostname()
	if p.resolve == nil || net.ParseIP(host) != nil {
		return raw, nil // no resolver wired, or already a literal IP
	}
	ip, ok := p.resolve(ctx, project, host)
	if !ok {
		return "", fmt.Errorf("service %q has no running replica (or socket-proxy down)", host)
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(ip, port)
	} else {
		u.Host = ip
	}
	return u.String(), nil
}

// Probe returns the canonical ops Result for a project. ok=false means ops is
// not enabled for this app (it stays BASIC from Docker-derived data).
func (p *Prober) Probe(ctx context.Context, project string) (*Result, bool) {
	cfg, ok, err := p.store.Get(project)
	if err != nil || !ok || !cfg.Enabled || cfg.OpsMode == "basic" {
		return nil, false
	}
	adapter := Lookup(cfg.Adapter)
	base, rerr := p.resolveBase(ctx, project, cfg.BaseURL)
	if rerr != nil {
		// The service name didn't resolve to a live replica — report it as a clear BASIC
		// result (not a cryptic dial error) and record it so the panel shows why.
		res := &Result{Mode: BASIC, Err: "ops endpoint not reachable: " + rerr.Error()}
		p.record(ctx, project, Discovery{Mode: BASIC}, res)
		return res, true
	}
	target := Target{BaseURL: base, SecretHeader: cfg.SecretHeader, Secret: cfg.Secret, BasePath: cfg.BasePath}

	var disc Discovery
	if cfg.OpsMode == "rich" {
		// Operator override: skip descriptor discovery (the app gates its ops
		// endpoints), probe directly (plan §4.1 discovery-precondition caveat).
		disc = Discovery{Mode: RICH, Version: "1.0", Capabilities: []string{"health", "queues", "metrics"}, BasePath: cleanBasePath(cfg.BasePath)}
	} else {
		disc = adapter.Discover(ctx, p.client, target)
	}

	if disc.Mode != RICH {
		res := &Result{Mode: BASIC, Version: disc.Version, Err: disc.Note}
		p.record(ctx, project, disc, res)
		return res, true
	}

	probe := adapter.Probe(ctx, p.client, target, disc)
	res := &probe
	p.record(ctx, project, disc, res)
	if res.Mode == RICH {
		p.appendSnapshot(ctx, project, res.HealthScore())
		res.Snapshot = p.loadSnapshot(ctx, project)
	}
	return res, true
}

// ProbeTarget probes ONE ops Target directly (no DB-backed config, no snapshot ring),
// for per-service ops driven from the canonical mooring.yaml. mode is auto|rich|basic.
// Returns nil when mode is "basic" (ops disabled for the service).
func (p *Prober) ProbeTarget(ctx context.Context, project string, target Target, adapterName, mode string) *Result {
	if mode == "basic" {
		return nil
	}
	// Resolve a compose-service-name base_url to the live bridge IP (the host can't resolve
	// compose names) — same as the scheduled Probe/QueueAction paths. A literal IP or a nil
	// resolver passes through; an unresolvable service is a clear BASIC failure, not a hang.
	base, rerr := p.resolveBase(ctx, project, target.BaseURL)
	if rerr != nil {
		return &Result{Mode: BASIC, Err: "ops endpoint not reachable: " + rerr.Error()}
	}
	target.BaseURL = base

	adapter := Lookup(adapterName)
	var disc Discovery
	if mode == "rich" {
		// Operator override: skip descriptor discovery, probe directly.
		disc = Discovery{Mode: RICH, Version: "1.0", Capabilities: []string{"health", "queues", "metrics"}, BasePath: cleanBasePath(target.BasePath)}
	} else {
		disc = adapter.Discover(ctx, p.client, target)
	}
	if disc.Mode != RICH {
		return &Result{Mode: BASIC, Version: disc.Version, Err: disc.Note}
	}
	res := adapter.Probe(ctx, p.client, target, disc)
	return &res
}

var queueActions = map[string]bool{"pause": true, "resume": true, "retry-failed": true}
var queueNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ErrBadQueueAction / ErrBadQueueName guard the server-side queue proxy.
var (
	ErrBadQueueAction = errors.New("ops: invalid queue action")
	ErrBadQueueName   = errors.New("ops: invalid queue name")
	ErrOpsNotEnabled  = errors.New("ops: not enabled for this app")
	ErrQueueFailed    = errors.New("ops: queue action failed")
)

// QueueAction performs a server-side, secret-bearing POST to an app's queue
// control endpoint (plan §4.2). The secret never reaches the browser.
func (p *Prober) QueueAction(ctx context.Context, project, queue, action string) error {
	if !queueActions[action] {
		return ErrBadQueueAction
	}
	if !queueNameRe.MatchString(queue) {
		return ErrBadQueueName
	}
	cfg, ok, err := p.store.Get(project)
	if err != nil {
		return err
	}
	// "basic" is a full ops kill-switch on BOTH read (Probe) and write
	// (QueueAction) paths, matching the "basic (skip ops)" UI (review #7).
	if !ok || !cfg.Enabled || cfg.OpsMode == "basic" {
		return ErrOpsNotEnabled
	}
	base, rerr := p.resolveBase(ctx, project, cfg.BaseURL)
	if rerr != nil {
		return ErrQueueFailed
	}
	path := joinPath(cleanBasePath(cfg.BasePath), "/queues/"+queue+"/"+action)
	resp, err := p.client.Post(ctx, base, path, cfg.SecretHeader, cfg.Secret, nil)
	if err != nil {
		return ErrQueueFailed
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return ErrQueueFailed
	}
	return nil
}

func (p *Prober) record(ctx context.Context, project string, disc Discovery, res *Result) {
	caps, _ := json.Marshal(disc.Capabilities)
	_, _ = p.db.ExecContext(ctx,
		`UPDATE app_ops SET disc_mode=?, disc_version=?, disc_caps=?, last_probe_at=?, last_error=? WHERE project=?`,
		string(res.Mode), disc.Version, string(caps), time.Now().Unix(), res.Err, project)
}

func (p *Prober) appendSnapshot(ctx context.Context, project string, score float64) {
	_, _ = p.db.ExecContext(ctx, `INSERT INTO ops_snapshot(project, ts, score) VALUES(?, ?, ?)`,
		project, time.Now().Unix(), score)
	// Trim the ring to ringSize newest samples for this project.
	_, _ = p.db.ExecContext(ctx,
		`DELETE FROM ops_snapshot WHERE project=? AND id NOT IN (
		   SELECT id FROM ops_snapshot WHERE project=? ORDER BY ts DESC, id DESC LIMIT ?)`,
		project, project, p.ringSize)
}

func (p *Prober) loadSnapshot(ctx context.Context, project string) []SnapshotPoint {
	rows, err := p.db.QueryContext(ctx,
		`SELECT ts, score FROM ops_snapshot WHERE project=? ORDER BY ts DESC, id DESC LIMIT ?`,
		project, p.sparkN)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var pts []SnapshotPoint
	for rows.Next() {
		var sp SnapshotPoint
		if err := rows.Scan(&sp.At, &sp.Value); err != nil {
			return pts
		}
		pts = append(pts, sp)
	}
	// reverse to ascending time for the sparkline
	for i, j := 0, len(pts)-1; i < j; i, j = i+1, j-1 {
		pts[i], pts[j] = pts[j], pts[i]
	}
	return pts
}
