package selfheal

import (
	"context"

	"github.com/daboss2003/Helmsman/internal/store"
)

// Store persists the per-(app,service) FSM and the expected_down leases. Alert and
// FSM state are recovered from SQLite on restart so a bounce neither re-fires
// remediation nor loses an open circuit.
type Store struct{ db *store.DB }

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Key identifies one supervised service.
type Key struct{ App, Service string }

// LoadAll returns every persisted FSM, keyed by (app,service).
func (s *Store) LoadAll() (map[Key]FSM, error) {
	rows, err := s.db.Query(`SELECT app, service, phase, unhealthy_streak, healthy_streak, attempts,
		last_rung, backoff_until, window_start, oom_strikes, degraded_since, open FROM supervisor_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Key]FSM{}
	for rows.Next() {
		var k Key
		var f FSM
		var lastRung string
		var open int
		if err := rows.Scan(&k.App, &k.Service, &f.Phase, &f.UnhealthyStreak, &f.HealthyStreak,
			&f.Attempts, &lastRung, &f.BackoffUntil, &f.WindowStart, &f.OOMStrikes, &f.DegradedSince, &open); err != nil {
			return nil, err
		}
		f.LastRung = Rung(lastRung)
		f.Open = open == 1
		out[k] = f
	}
	return out, rows.Err()
}

// Save upserts one FSM.
func (s *Store) Save(ctx context.Context, k Key, f FSM, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO supervisor_state
		(app, service, phase, unhealthy_streak, healthy_streak, attempts, last_rung, backoff_until, window_start, oom_strikes, degraded_since, open, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(app, service) DO UPDATE SET
			phase=excluded.phase, unhealthy_streak=excluded.unhealthy_streak, healthy_streak=excluded.healthy_streak,
			attempts=excluded.attempts, last_rung=excluded.last_rung, backoff_until=excluded.backoff_until,
			window_start=excluded.window_start, oom_strikes=excluded.oom_strikes, degraded_since=excluded.degraded_since,
			open=excluded.open, updated_at=excluded.updated_at`,
		k.App, k.Service, string(f.Phase), f.UnhealthyStreak, f.HealthyStreak, f.Attempts, string(f.LastRung),
		f.BackoffUntil, f.WindowStart, f.OOMStrikes, f.DegradedSince, b2i(f.Open), now)
	return err
}

// Delete drops an FSM (a service that no longer exists in any app).
func (s *Store) Delete(ctx context.Context, k Key) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM supervisor_state WHERE app=? AND service=?`, k.App, k.Service)
	return err
}

// ClearCircuit resets a latched CIRCUIT_OPEN service to HEALTHY so the supervisor
// will act on it again (the operator's "I fixed the underlying problem" button).
func (s *Store) ClearCircuit(ctx context.Context, k Key, now int64) error {
	return s.Save(ctx, k, FSM{Phase: Healthy}, now)
}

// --- expected_down leases ---

// AcquireExpectedDown opens/extends a bounded lease for an app (the write plane
// holds it while it intentionally touches the app). until is the auto-expiry.
func (s *Store) AcquireExpectedDown(ctx context.Context, app string, until int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO expected_down(app, until, reason) VALUES(?,?,?)
		 ON CONFLICT(app) DO UPDATE SET until=excluded.until, reason=excluded.reason`,
		app, until, "write-plane action")
	return err
}

// ReleaseExpectedDown clears an app's lease (the action finished).
func (s *Store) ReleaseExpectedDown(ctx context.Context, app string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM expected_down WHERE app=?`, app)
	return err
}

// ActiveExpectedDown returns the set of apps with a non-expired lease.
func (s *Store) ActiveExpectedDown(now int64) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT app FROM expected_down WHERE until > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var app string
		if err := rows.Scan(&app); err != nil {
			return nil, err
		}
		out[app] = true
	}
	return out, rows.Err()
}

// ClearAllExpectedDown wipes every lease — called fail-closed on boot, so a deploy
// that crashed without releasing its lease can't suppress a crash-loop alert forever.
func (s *Store) ClearAllExpectedDown(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM expected_down`)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
