// Package audit appends to the append-only events table (plan §5.8). It never
// records secret values — callers pass already-redacted detail strings.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/helmsman/helmsman/internal/store"
)

// Level distinguishes routine actions from security-relevant ones.
type Level string

const (
	Info     Level = "info"
	Security Level = "security"
)

// Outcome of an audited action.
type Outcome string

const (
	OK    Outcome = "ok"
	Deny  Outcome = "deny"
	Error Outcome = "error"
)

// Event is one audit record.
type Event struct {
	Actor   string
	IP      string
	Action  string
	Target  string
	Outcome Outcome
	Level   Level
	Detail  string
}

// Logger writes audit events.
type Logger struct {
	db  *store.DB
	log *slog.Logger // may be nil
}

// New returns a Logger backed by db. log (may be nil) receives a line whenever an
// audit write FAILS, so a dropped security event is never invisible (review #12).
func New(db *store.DB, log *slog.Logger) *Logger { return &Logger{db: db, log: log} }

// Log appends an event. A DB failure is returned AND logged (if a logger is set):
// it is non-fatal to the request path (the request still fails closed on its own
// merits), but the dropped event must not vanish silently.
func (l *Logger) Log(ctx context.Context, e Event) error {
	if e.Level == "" {
		e.Level = Info
	}
	if e.Outcome == "" {
		e.Outcome = OK
	}
	_, err := l.db.ExecContext(ctx,
		`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(), e.Actor, e.IP, e.Action, e.Target,
		string(e.Outcome), string(e.Level), e.Detail,
	)
	if err != nil && l.log != nil {
		l.log.Error("audit write failed",
			"action", e.Action, "outcome", string(e.Outcome),
			"actor", e.Actor, "ip", e.IP, "err", err)
	}
	return err
}
