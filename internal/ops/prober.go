package ops

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/daboss2003/Helmsman/internal/store"
)

// Prober runs discovery + probe for one app per call (the monitor drives the
// cadence: sequential + jittered, plan §4). It also persists the snapshot ring
// and performs server-side-proxied queue actions.
type Prober struct {
	store    *ConfigStore
	client   Doer
	db       *store.DB
	ringSize int // retained samples per app
	sparkN   int // samples returned for the sparkline
}

// NewProber builds a Prober. client is the SSRF-safe outbound client.
func NewProber(cs *ConfigStore, client Doer, db *store.DB) *Prober {
	return &Prober{store: cs, client: client, db: db, ringSize: 100, sparkN: 60}
}

// Probe returns the canonical ops Result for a project. ok=false means ops is
// not enabled for this app (it stays BASIC from Docker-derived data).
func (p *Prober) Probe(ctx context.Context, project string) (*Result, bool) {
	cfg, ok, err := p.store.Get(project)
	if err != nil || !ok || !cfg.Enabled || cfg.OpsMode == "basic" {
		return nil, false
	}
	adapter := Lookup(cfg.Adapter)
	target := Target{BaseURL: cfg.BaseURL, SecretHeader: cfg.SecretHeader, Secret: cfg.Secret, BasePath: cfg.BasePath}

	var disc Discovery
	if cfg.OpsMode == "rich" {
		// Operator override: skip descriptor discovery (the app gates its ops
		// endpoints), probe directly (plan §4.1 discovery-precondition caveat).
		disc = Discovery{Mode: RICH, Version: "1.0", Capabilities: []string{"health", "queues"}, BasePath: cleanBasePath(cfg.BasePath)}
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
	path := joinPath(cleanBasePath(cfg.BasePath), "/queues/"+queue+"/"+action)
	resp, err := p.client.Post(ctx, cfg.BaseURL, path, cfg.SecretHeader, cfg.Secret, nil)
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
