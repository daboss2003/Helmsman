-- M13 self-healing supervisor (plan §8.5). The per-(app,service) FSM is persisted
-- so a restart neither re-fires remediation nor loses an open circuit (state is
-- recovered from SQLite). expected_down is a BOUNDED lease the write plane holds
-- while it intentionally touches an app, so a deploy isn't mistaken for a crash
-- loop; it is cleared fail-closed on boot (a crashed deploy must never leave a
-- crash-looping service silently un-paged) and auto-expires via `until`.
CREATE TABLE supervisor_state (
    app              TEXT    NOT NULL,
    service          TEXT    NOT NULL,
    phase            TEXT    NOT NULL,
    unhealthy_streak INTEGER NOT NULL DEFAULT 0,
    healthy_streak   INTEGER NOT NULL DEFAULT 0,
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_rung        TEXT    NOT NULL DEFAULT '',
    backoff_until    INTEGER NOT NULL DEFAULT 0,
    window_start     INTEGER NOT NULL DEFAULT 0,
    oom_strikes      INTEGER NOT NULL DEFAULT 0,
    degraded_since   INTEGER NOT NULL DEFAULT 0,
    open             INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (app, service)
);

CREATE TABLE expected_down (
    app    TEXT    PRIMARY KEY,
    until  INTEGER NOT NULL,            -- unix sec; the lease is inactive once now >= until
    reason TEXT    NOT NULL DEFAULT ''
);
