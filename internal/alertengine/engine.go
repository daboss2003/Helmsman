// Package alertengine runs the alert engine's goroutines (plan §8): ONE evaluator
// (reads the poller's snapshot, drives the state machine, enqueues the outbox —
// never sends), a SEPARATE globally-rate-limited notifier (drains the outbox, so a
// hung SMTP/bot can't stall evaluation or spam the box), and an externalized
// dead-man's-switch heartbeat. Read-and-notify only: zero docker writes.
package alertengine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/monitor"
)

// Config tunes the engine (from config.AlertingConfig).
type Config struct {
	EvalInterval      time.Duration
	NotifyMinInterval time.Duration
	QuietStartHour    int // -1 disables
	QuietEndHour      int
	DeadMansURL       string
	DeadMansInterval  time.Duration
	AdminURL          string // for the "open in dashboard" link in notifications
}

const maxNotifyAttempts = 3

// Engine owns the evaluator + notifier + heartbeat.
type Engine struct {
	store  *alertstore.Store
	snapFn func() *monitor.Snapshot
	cfg    Config
	log    *slog.Logger
	wake   chan struct{} // evaluator signals the notifier
}

// New builds an Engine. snapFn returns the latest poller snapshot (may be nil).
func New(store *alertstore.Store, snapFn func() *monitor.Snapshot, cfg Config, log *slog.Logger) *Engine {
	return &Engine{store: store, snapFn: snapFn, cfg: cfg, log: log, wake: make(chan struct{}, 1)}
}

// RunEvaluator ticks the evaluator until ctx is cancelled.
func (e *Engine) RunEvaluator(ctx context.Context) {
	t := time.NewTicker(e.cfg.EvalInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.evalOnce(ctx)
		}
	}
}

func (e *Engine) evalOnce(ctx context.Context) {
	rules, err := e.store.ListRules()
	if err != nil {
		e.log.Warn("alert: load rules failed", "err", err)
		return
	}
	if len(rules) == 0 {
		return
	}
	prior, err := e.store.LoadStates()
	if err != nil {
		e.log.Warn("alert: load states failed", "err", err)
		return
	}
	now := time.Now().Unix()
	states, outbox := alert.Evaluate(now, rules, e.snapFn(), prior)
	if err := e.store.SaveStates(ctx, states); err != nil {
		e.log.Warn("alert: save states failed", "err", err)
	}
	if len(outbox) > 0 {
		if err := e.store.EnqueueOutbox(ctx, outbox); err != nil {
			e.log.Warn("alert: enqueue failed", "err", err)
			return
		}
		e.signal()
	}
}

func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// RunNotifier drains the outbox, globally rate-limited, until ctx is cancelled.
func (e *Engine) RunNotifier(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.wake:
		}
		e.drain(ctx)
		e.store.PruneOutbox(ctx, time.Now().Add(-7*24*time.Hour).Unix())
	}
}

func (e *Engine) drain(ctx context.Context) {
	pending, err := e.store.PendingOutbox(100)
	if err != nil {
		return
	}
	now := time.Now()
	for _, row := range pending {
		if ctx.Err() != nil {
			return
		}
		// Quiet hours suppress WARNING; CRITICAL always pages (plan §8).
		if row.Level != alert.LevelCritical && e.inQuietHours(now) {
			e.store.MarkSent(ctx, row.ID, true, maxNotifyAttempts)
			continue
		}
		// Mooring-originated infra alert (plan §8.4): rule_id=0, NEVER deferred to an
		// app and not tied to a rule/silence — route straight to ALL channels.
		if row.RuleID == 0 {
			channels, err := e.store.AllChannels()
			if err != nil || len(channels) == 0 {
				e.store.MarkSent(ctx, row.ID, false, maxNotifyAttempts)
				continue
			}
			e.store.MarkSent(ctx, row.ID, e.sendAll(ctx, channels, e.render(row), row.Kind), maxNotifyAttempts)
			continue
		}
		// Silenced (operator) → drop.
		if e.store.IsSilenced(row.RuleID, row.Target, now.Unix()) {
			e.store.MarkSent(ctx, row.ID, true, maxNotifyAttempts)
			continue
		}
		rule, ok := e.store.RuleByID(row.RuleID)
		if !ok {
			e.store.MarkSent(ctx, row.ID, true, maxNotifyAttempts)
			continue
		}
		channels, err := e.store.ChannelsForRule(rule.ChannelID)
		if err != nil || len(channels) == 0 {
			e.store.MarkSent(ctx, row.ID, false, maxNotifyAttempts)
			continue
		}
		e.store.MarkSent(ctx, row.ID, e.sendAll(ctx, channels, e.render(row), row.Kind), maxNotifyAttempts)
	}
}

// sendAll delivers n to every channel, rate-limited between sends so a slow channel
// can't spam-cannon the box. Returns whether every send succeeded.
func (e *Engine) sendAll(ctx context.Context, channels []alert.Channel, n alert.Notification, kind string) bool {
	allOK := true
	for _, ch := range channels {
		sctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := ch.Send(sctx, n); err != nil {
			allOK = false
			e.log.Warn("alert: channel send failed", "kind", kind, "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return allOK
		case <-time.After(e.cfg.NotifyMinInterval):
		}
	}
	return allOK
}

func (e *Engine) render(row alertstore.OutboxRow) alert.Notification {
	verb := "FIRING"
	if row.Transition == "resolved" {
		verb = "RESOLVED"
	}
	title := fmt.Sprintf("[%s] %s — %s (%s)", up(row.Level), verb, row.Kind, row.Target)
	body := row.Summary
	if e.cfg.AdminURL != "" {
		body += "\n\n" + e.cfg.AdminURL
	}
	return alert.Notification{Title: title, Body: body, Level: row.Level}
}

// inQuietHours reports whether now falls in the configured quiet window.
func (e *Engine) inQuietHours(now time.Time) bool {
	s, end := e.cfg.QuietStartHour, e.cfg.QuietEndHour
	if s < 0 || end < 0 {
		return false
	}
	h := now.Hour()
	if s <= end {
		return h >= s && h < end
	}
	return h >= s || h < end // window wraps midnight
}

// RunHeartbeat pings an external cron-monitor so a dead dashboard is detected by
// something OTHER than itself (plan §8 dead-man's-switch). SSRF-guarded outbound.
func (e *Engine) RunHeartbeat(ctx context.Context) {
	if e.cfg.DeadMansURL == "" {
		return
	}
	t := time.NewTicker(e.cfg.DeadMansInterval)
	defer t.Stop()
	e.ping(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.ping(ctx)
		}
	}
}

func (e *Engine) ping(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, e.cfg.DeadMansURL, nil)
	if err != nil {
		return
	}
	resp, err := heartbeatClient().Do(req)
	if err != nil {
		e.log.Warn("alert: dead-man heartbeat failed")
		return
	}
	resp.Body.Close()
}

// heartbeatClient blocks loopback/link-local dial targets (SSRF posture).
func heartbeatClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	d.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, perr := netip.ParseAddr(host)
		if perr != nil {
			return fmt.Errorf("alert: heartbeat: unresolved")
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("alert: heartbeat refusing loopback/link-local")
		}
		return nil
	}
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true},
	}
}

func up(s string) string { return string(bytes.ToUpper([]byte(s))) }
