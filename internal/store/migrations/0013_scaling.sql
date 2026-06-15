-- M14 opt-in auto-scaling (plan §8A). scaling_policy is the per-(app,service)
-- operator opt-in + thresholds (OFF unless a row exists with enabled=1).
-- scaling_state is the controller's desired-replica count + hysteresis timers,
-- recovered from SQLite on restart so a bounce neither re-ramps nor loses the
-- cooldown. per_replica_mem/cpu are the REQUIRED reservations the host-capacity
-- guard reserves against (a missing/implausible one refuses growth).
CREATE TABLE scaling_policy (
    app             TEXT    NOT NULL,
    service         TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 0,
    min_replicas    INTEGER NOT NULL DEFAULT 1,
    max_replicas    INTEGER NOT NULL DEFAULT 1,
    up_cpu_pct      REAL    NOT NULL DEFAULT 80,
    up_mem_pct      REAL    NOT NULL DEFAULT 80,
    down_cpu_pct    REAL    NOT NULL DEFAULT 40,
    down_mem_pct    REAL    NOT NULL DEFAULT 40,
    breach_for_secs INTEGER NOT NULL DEFAULT 60,
    cooldown_up     INTEGER NOT NULL DEFAULT 60,
    cooldown_down   INTEGER NOT NULL DEFAULT 300,
    per_replica_mem INTEGER NOT NULL DEFAULT 0,   -- bytes (required for scaling)
    per_replica_cpu INTEGER NOT NULL DEFAULT 0,   -- milli-cpu (required for scaling)
    PRIMARY KEY (app, service)
);

CREATE TABLE scaling_state (
    app          TEXT    NOT NULL,
    service      TEXT    NOT NULL,
    replicas     INTEGER NOT NULL DEFAULT 1,   -- desired count the controller drives toward
    breach_since INTEGER NOT NULL DEFAULT 0,
    last_change  INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (app, service)
);
