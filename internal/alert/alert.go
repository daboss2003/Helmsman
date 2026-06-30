// Package alert is Mooring's read-and-notify alert engine (plan §8): ONE
// evaluator that reads the poller's snapshot (zero network I/O, zero docker
// writes, side-effect-free) and drives a per-(rule,target) state machine, and a
// SEPARATE rate-limited notifier that drains an outbox. It defers to an app that
// already alerts — with a down-only safety net so a dark app still pages on
// liveness.
package alert

import (
	"fmt"
	"sort"
	"strings"

	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
)

// Phase is the per-(rule,target) state-machine phase.
type Phase string

const (
	PhaseOK       Phase = "ok"
	PhasePending  Phase = "pending"  // condition true, sustain window not yet elapsed
	PhaseFiring   Phase = "firing"   // sustained → alert is open
	PhaseResolved Phase = "resolved" // condition cleared, clear window not yet elapsed
)

// Levels.
const (
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// Kinds (the read-detectable v1 set; the §8.4 infra taxonomy extends this engine).
const (
	KindContainerDown = "container_down"
	KindHostCPU       = "host_cpu"
	KindHostMem       = "host_mem"
	KindHostDisk      = "host_disk"
	KindDepDown       = "dep_down"
	KindRestartStorm  = "restart_storm"
)

var validKind = map[string]bool{
	KindContainerDown: true, KindHostCPU: true, KindHostMem: true,
	KindHostDisk: true, KindDepDown: true, KindRestartStorm: true,
}

// ValidKind reports whether kind is known.
func ValidKind(kind string) bool { return validKind[kind] }

// isLiveness reports whether a kind is part of the down-only safety net (covered
// even when a self-managed app is unreachable — plan §8).
func isLiveness(kind string) bool { return kind == KindContainerDown }

// Rule is one alert rule (operator-defined).
type Rule struct {
	ID                   int64
	Name                 string
	Kind                 string
	Scope                string // "" = all apps; else a project slug
	Threshold            float64
	ForSeconds           int
	Level                string
	DeferWhenSelfManaged bool
	ChannelID            int64 // 0 = all enabled channels
	Enabled              bool
}

// State is the persisted per-(rule,target) state.
type State struct {
	RuleID        int64
	Target        string
	Phase         Phase
	Since         int64
	Level         string
	Detail        string
	Acked         bool
	SilencedUntil int64
}

func (s State) key() stateKey { return stateKey{s.RuleID, s.Target} }

type stateKey struct {
	rule   int64
	target string
}

// Outbox is one notification handoff the evaluator appends (it never sends).
type Outbox struct {
	RuleID     int64
	Target     string
	Kind       string
	Level      string
	Transition string // firing | resolved
	Summary    string
	DedupeKey  string
}

// targetEval is one rule applied to one concrete target this tick.
type targetEval struct {
	target string
	met    bool
	detail string
	skip   bool // deferred to the app's own alerting
}

// Evaluate runs every enabled rule against the snapshot and the prior state,
// returning the new states and any outbox notifications to enqueue. It is PURE
// (no I/O); the caller persists + signals the notifier. now is unix seconds.
func Evaluate(now int64, rules []Rule, snap *monitor.Snapshot, prior []State) ([]State, []Outbox) {
	priorByKey := map[stateKey]State{}
	for _, s := range prior {
		priorByKey[s.key()] = s
	}
	var outStates []State
	var outbox []Outbox

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, te := range evalRuleTargets(rule, snap) {
			k := stateKey{rule.ID, te.target}
			if te.skip {
				// Deferred to the app's own alerting now: close any open alert by
				// resolving it to ok (SaveStates prunes ok rows) so it can't stick
				// firing forever once a rule starts deferring.
				if prev, ok := priorByKey[k]; ok {
					prev.Phase = PhaseOK
					outStates = append(outStates, prev)
					delete(priorByKey, k)
				}
				continue
			}
			prev, hadPrev := priorByKey[k]
			ns, ob := step(now, rule, te, prev, hadPrev)
			outStates = append(outStates, ns)
			delete(priorByKey, k)
			if ob != nil {
				outbox = append(outbox, *ob)
			}
		}
	}
	// States for targets not evaluated this tick (e.g. a transient snapshot gap)
	// are carried forward unchanged so a restart/flap doesn't lose an open alert.
	for _, s := range priorByKey {
		outStates = append(outStates, s)
	}
	return outStates, outbox
}

// step advances one (rule,target) state machine by one tick.
func step(now int64, rule Rule, te targetEval, prev State, hadPrev bool) (State, *Outbox) {
	ns := State{RuleID: rule.ID, Target: te.target, Level: rule.Level, Detail: te.detail}
	if hadPrev {
		ns.Acked = prev.Acked
		ns.SilencedUntil = prev.SilencedUntil
	}
	phase := PhaseOK
	since := now
	if hadPrev {
		phase = prev.Phase
		since = prev.Since
	}

	clearWindow := int64(rule.ForSeconds)
	if te.met {
		switch phase {
		case PhaseOK, PhaseResolved:
			phase, since = PhasePending, now
		case PhasePending:
			if now-since >= int64(rule.ForSeconds) {
				phase, since = PhaseFiring, now
				ns.Phase, ns.Since = phase, since
				return ns, &Outbox{RuleID: rule.ID, Target: te.target, Kind: rule.Kind, Level: rule.Level,
					Transition: "firing", Summary: te.detail, DedupeKey: dedupeKey(rule, te.target)}
			}
		case PhaseFiring:
			// stays firing
		}
	} else {
		switch phase {
		case PhasePending:
			phase, since = PhaseOK, now // never sustained — anti-flap, no page
		case PhaseFiring:
			phase, since = PhaseResolved, now
			ns.Phase, ns.Since = phase, since
			ns.Acked = false
			return ns, &Outbox{RuleID: rule.ID, Target: te.target, Kind: rule.Kind, Level: rule.Level,
				Transition: "resolved", Summary: "recovered", DedupeKey: dedupeKey(rule, te.target)}
		case PhaseResolved:
			if now-since >= clearWindow {
				phase, since = PhaseOK, now
				ns.Acked = false
			}
		case PhaseOK:
			// stays ok
		}
	}
	ns.Phase, ns.Since = phase, since
	return ns, nil
}

func dedupeKey(rule Rule, target string) string {
	return fmt.Sprintf("%d:%s:%s", rule.ID, rule.Kind, target)
}

// evalRuleTargets enumerates the concrete targets for a rule against the snapshot,
// applying the defer / down-only-safety-net logic per app (plan §8).
func evalRuleTargets(rule Rule, snap *monitor.Snapshot) []targetEval {
	if snap == nil {
		return nil
	}
	switch rule.Kind {
	case KindHostCPU, KindHostMem, KindHostDisk:
		if !snap.HostOK {
			return nil
		}
		val, label := hostMetric(rule.Kind, snap)
		return []targetEval{{
			target: "host", met: val > rule.Threshold,
			detail: fmt.Sprintf("host %s %.1f%% > %.1f%%", label, val, rule.Threshold),
		}}
	case KindContainerDown:
		var out []targetEval
		for _, app := range appsInScope(rule, snap) {
			for _, svc := range app.Services {
				te := targetEval{target: app.Project + "/" + svc.Service,
					met: !svc.Running(), detail: app.Project + "/" + svc.Service + " is " + svc.State}
				te.skip = deferTarget(rule, app)
				out = append(out, te)
			}
		}
		return out
	case KindRestartStorm:
		var out []targetEval
		for _, app := range appsInScope(rule, snap) {
			for _, svc := range app.Services {
				te := targetEval{target: app.Project + "/" + svc.Service,
					met:    float64(svc.RestartCount) >= rule.Threshold,
					detail: fmt.Sprintf("%s/%s restarted %d times", app.Project, svc.Service, svc.RestartCount)}
				te.skip = deferTarget(rule, app)
				out = append(out, te)
			}
		}
		return out
	case KindDepDown:
		var out []targetEval
		for _, app := range appsInScope(rule, snap) {
			if app.Ops == nil || app.Ops.Mode != ops.RICH {
				continue
			}
			for _, ind := range app.Ops.Indicators {
				te := targetEval{target: app.Project + "/" + ind.Name,
					met:    strings.EqualFold(ind.Status, "down"),
					detail: fmt.Sprintf("%s dependency %s is %s", app.Project, ind.Name, ind.Status)}
				te.skip = deferTarget(rule, app)
				out = append(out, te)
			}
		}
		return out
	}
	return nil
}

// deferTarget implements the defer + down-only safety net for an app target:
//   - self-managed + reachable: defer (skip) rules marked defer_when_self_managed.
//   - self-managed + UNREACHABLE: skip non-liveness rules, but still COVER liveness
//     (so "the app went dark" still pages).
//   - not self-managed: cover everything.
func deferTarget(rule Rule, app monitor.App) bool {
	selfManaged := app.Ops != nil && app.Ops.AlertingCapable
	if !selfManaged {
		return false
	}
	reachable := app.Ops != nil && app.Ops.Mode == ops.RICH && app.Ops.Err == ""
	if reachable {
		return rule.DeferWhenSelfManaged
	}
	// Unreachable self-managed app: cover only the narrow liveness subset.
	return !isLiveness(rule.Kind)
}

func appsInScope(rule Rule, snap *monitor.Snapshot) []monitor.App {
	if rule.Scope == "" {
		return snap.Apps
	}
	for _, a := range snap.Apps {
		if a.Project == rule.Scope {
			return []monitor.App{a}
		}
	}
	return nil
}

func hostMetric(kind string, snap *monitor.Snapshot) (float64, string) {
	switch kind {
	case KindHostCPU:
		return snap.Host.CPUPercent, "cpu"
	case KindHostMem:
		return pct(snap.Host.MemUsed, snap.Host.MemTotal), "memory"
	case KindHostDisk:
		return pct(snap.Host.DiskUsed, snap.Host.DiskTotal), "disk"
	}
	return 0, ""
}

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// SortStates orders states deterministically (rule, then target).
func SortStates(s []State) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].RuleID != s[j].RuleID {
			return s[i].RuleID < s[j].RuleID
		}
		return s[i].Target < s[j].Target
	})
}
