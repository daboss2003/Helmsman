package selfheal

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/helmsman/helmsman/internal/alert"
	"github.com/helmsman/helmsman/internal/alertstore"
	"github.com/helmsman/helmsman/internal/dockerexec"
	"github.com/helmsman/helmsman/internal/monitor"
)

// Actioner executes a remediation rung for one service. The watcher calls it ONLY
// after the four safety gates pass, and while it HOLDS the one-docker-child
// semaphore (acquired non-blocking by the gate).
type Actioner interface {
	Remediate(ctx context.Context, app monitor.App, service string, rung Rung) error
}

// Config configures a Watcher. The function/clock fields are injectable for tests.
type Config struct {
	Store        *Store
	Alerts       *alertstore.Store // nil → pages are logged only (alerting disabled)
	Snap         func() *monitor.Snapshot
	Sem          *dockerexec.Semaphore
	Act          Actioner
	Policy       Policy
	Log          *slog.Logger
	Interval     time.Duration
	FloorBytes   uint64          // memory-headroom floor (0 = gate disabled, e.g. no host metrics)
	WritePlaneOK bool            // the §0 write-plane gate result
	Protected    map[string]bool // project names that are the edge/control plane — never targets
	Now          func() int64    // injectable clock; defaults to time.Now().Unix
}

// Watcher is the bounded self-healing supervisor loop (plan §8.5).
type Watcher struct {
	cfg  Config
	fsms map[Key]FSM // in-memory FSM cache, recovered from the store on boot
}

// New builds a Watcher.
func New(cfg Config) *Watcher {
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Watcher{cfg: cfg, fsms: map[Key]FSM{}}
}

// Run boots (clearing stale expected_down leases fail-closed, then recovering FSM
// state from SQLite) and ticks the supervisor until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	// Fail-closed: a deploy that crashed without releasing its lease must not be able
	// to suppress a crash-loop alert across a restart.
	_ = w.cfg.Store.ClearAllExpectedDown(ctx)
	if all, err := w.cfg.Store.LoadAll(); err == nil {
		w.fsms = all
	}
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Tick runs one supervision pass over the latest snapshot. Exported for tests.
func (w *Watcher) Tick(ctx context.Context) {
	snap := w.cfg.Snap()
	if snap == nil || !snap.DockerOK {
		return // never act on stale/absent data
	}
	now := w.cfg.Now()
	leases, _ := w.cfg.Store.ActiveExpectedDown(now)

	// Headroom: free host memory this tick. If host metrics are unavailable the
	// headroom gate is disabled (floor 0) — the §0 gate + semaphore still apply.
	var headroom uint64
	floor := w.cfg.FloorBytes
	if snap.HostOK && snap.Host.MemTotal >= snap.Host.MemUsed {
		headroom = snap.Host.MemTotal - snap.Host.MemUsed
	} else {
		floor = 0
	}

	seen := map[Key]bool{}
	for _, app := range snap.Apps {
		for _, svc := range app.Services {
			key := Key{App: app.Project, Service: svc.Service}
			seen[key] = true
			obs := Observation{
				Running:      svc.Running(),
				Health:       svc.Health,
				RestartCount: svc.RestartCount,
				OOMKilled:    svc.OOMKilled,
				ExitCode:     svc.ExitCode,
				ExpectedDown: leases[app.Project],
				// WaitingOnEdge is refined once the cert inventory lands (M19); until
				// then it is conservatively false (never suppress a real failure).
				WaitingOnEdge: false,
			}
			w.stepService(ctx, app, svc.Service, key, obs, now, headroom, floor)
		}
	}
	w.prune(ctx, seen, leases, now)
}

// stepService decides and acts for one service.
func (w *Watcher) stepService(ctx context.Context, app monitor.App, service string, key Key, obs Observation, now int64, headroom, floor uint64) {
	prev, ok := w.fsms[key]
	if !ok {
		prev = FSM{Phase: Healthy}
	}
	d := Decide(prev, obs, w.cfg.Policy, now)

	switch d.Act {
	case ActNone:
		w.commit(ctx, key, d.Next, now)
	case ActResolve:
		w.emitInfra(ctx, app, service, "recovered", "resolved")
		w.commit(ctx, key, d.Next, now)
	case ActPage:
		w.emitInfra(ctx, app, service, d.Kind, "firing")
		w.commit(ctx, key, d.Next, now)
	case ActRemediate:
		w.remediate(ctx, app, service, key, d, now, headroom, floor)
	}
}

// remediate applies the four safety gates to a proposed rung and acts accordingly.
func (w *Watcher) remediate(ctx context.Context, app monitor.App, service string, key Key, d Decision, now int64, headroom, floor uint64) {
	gi := GateInput{
		Rung:                 d.Rung,
		WritePlaneOK:         w.cfg.WritePlaneOK,
		RedeployEnabled:      w.cfg.Policy.RedeployEnabled,
		AcquireSemaphore:     w.cfg.Sem.TryAcquire,
		HeadroomBytes:        headroom,
		FloorBytes:           floor,
		IsEdgeOrControlPlane: w.cfg.Protected[app.Project],
	}
	out, reason := Gates(gi)
	switch out {
	case GateProceed:
		// The gate acquired the semaphore; we hold it for exactly this action.
		defer w.cfg.Sem.Release()
		err := w.cfg.Act.Remediate(ctx, app, service, d.Rung)
		// The attempt is consumed whether or not the action succeeded (a failed
		// rung still counts toward the cap → the circuit eventually opens).
		w.commit(ctx, key, CommitRemediation(d.Next, d.Rung, w.cfg.Policy, now), now)
		if err != nil {
			w.cfg.Log.Warn("selfheal: remediation failed", "app", app.Project, "service", service, "rung", d.Rung, "err", err)
		} else {
			w.cfg.Log.Info("selfheal: remediated", "app", app.Project, "service", service, "rung", d.Rung)
		}
	case GateDefer:
		// No attempt consumed; re-checked next tick.
		w.commit(ctx, key, d.Next, now)
		w.cfg.Log.Debug("selfheal: action deferred", "app", app.Project, "service", service, "reason", reason)
	case GatePage:
		// Headroom too low to safely restart: page instead of acting (plan §8.5).
		next := d.Next
		next.Phase = Degraded
		w.emitInfra(ctx, app, service, "low_headroom", "firing")
		w.commit(ctx, key, next, now)
	case GateSkip:
		// Edge/control plane is never a remediation target — leave it untouched.
	}
}

// prune drops FSM state for services that no longer exist (and whose app isn't
// mid-deploy under a lease), so the table doesn't grow unbounded.
func (w *Watcher) prune(ctx context.Context, seen map[Key]bool, leases map[string]bool, now int64) {
	for key := range w.fsms {
		if seen[key] || leases[key.App] {
			continue
		}
		delete(w.fsms, key)
		_ = w.cfg.Store.Delete(ctx, key)
	}
}

func (w *Watcher) commit(ctx context.Context, key Key, f FSM, now int64) {
	w.fsms[key] = f
	_ = w.cfg.Store.Save(ctx, key, f, now)
}

// kindLevel maps a can't-fix taxonomy kind to its alert level. low_headroom is a
// WARNING (quiet-hours-suppressible); the give-up kinds are CRITICAL (always page).
func kindLevel(kind string) string {
	if kind == "low_headroom" {
		return alert.LevelWarning
	}
	return alert.LevelCritical
}

// emitInfra enqueues a Helmsman-originated infra alert (origin=helmsman_infra,
// rule_id=0, never deferred). Names are CR/LF/NUL-stripped before they reach any
// channel (the email channel also builds MIME-safe, never placing a name in a
// header). A nil alert store (alerting disabled) logs the page instead.
func (w *Watcher) emitInfra(ctx context.Context, app monitor.App, service, kind, transition string) {
	target := sanitizeName(app.Project) + "/" + sanitizeName(service)
	if w.cfg.Alerts == nil {
		w.cfg.Log.Warn("selfheal: infra alert (no channels configured)", "kind", kind, "target", target, "transition", transition)
		return
	}
	summary := infraSummary(kind, transition, target)
	o := alert.Outbox{
		RuleID:     0, // infra sentinel
		Target:     target,
		Kind:       kind,
		Level:      kindLevel(kind),
		Transition: transition,
		Summary:    summary,
		DedupeKey:  "selfheal:" + target, // one open supervisor alert per service
	}
	if err := w.cfg.Alerts.EnqueueInfra(ctx, o); err != nil {
		w.cfg.Log.Warn("selfheal: enqueue infra alert failed", "err", err)
	}
}

// infraSummary builds the bounded, fixed-section body (plan §8.4) — no log dump.
func infraSummary(kind, transition, target string) string {
	if transition == "resolved" {
		return "Service " + target + " recovered and is healthy again."
	}
	switch kind {
	case "oom_killed_repeated":
		return "Service " + target + " is being OOM/at-limit killed repeatedly. Helmsman is NOT restarting it (a restart would not help on a memory-starved box). Reduce its memory use or raise the host's RAM."
	case "low_headroom":
		return "Service " + target + " needs a restart but host memory headroom is below the safety floor. Helmsman is holding off to avoid an OOM. Free memory or raise the floor."
	case "crashloop_capped":
		return "Service " + target + " is crash-looping and Helmsman's restart/recreate attempts did not recover it. Manual investigation needed."
	case "unhealthy_capped":
		return "Service " + target + " is up but failing its healthcheck and did not recover after restart/recreate. Manual investigation needed."
	default:
		return "Service " + target + " could not be self-healed (" + kind + ")."
	}
}

// sanitizeName strips CR/LF/NUL (defence in depth against header/log injection via
// an attacker-influenced project/service name) and bounds the length.
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// runnerActioner is the production Actioner: it runs the rung's `docker compose`
// action through the write-plane runner WITHOUT re-acquiring the semaphore (the
// watcher's gate already holds it).
type runnerActioner struct {
	runner *dockerexec.Runner
	jobFor func(app monitor.App, service string, action []string) dockerexec.Job
}

// NewRunnerActioner builds the production Actioner. jobFor lets the caller supply
// the env-file / config-file details for an app (reusing the write-plane builder).
func NewRunnerActioner(runner *dockerexec.Runner, jobFor func(app monitor.App, service string, action []string) dockerexec.Job) Actioner {
	return runnerActioner{runner: runner, jobFor: jobFor}
}

// rungAction maps a rung to its static `docker compose` argv (no shell, ever).
var rungAction = map[Rung][]string{
	RungRestart:  {"restart"},
	RungRecreate: {"up", "-d", "--force-recreate"},
	RungRedeploy: {"up", "-d", "--force-recreate"},
}

func (a runnerActioner) Remediate(ctx context.Context, app monitor.App, service string, rung Rung) error {
	action := rungAction[rung]
	job := a.jobFor(app, service, action)
	return a.runner.RunHeld(ctx, job, nil)
}
