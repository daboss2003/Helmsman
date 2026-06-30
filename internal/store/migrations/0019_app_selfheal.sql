-- Per-app self-healing policy (plan §8.5). The supervisor ships a conservative
-- built-in default (selfheal.DefaultPolicy); a row here tunes the ladder for ONE
-- app (its services). Written from mooring.yaml's spec.self_healing at deploy —
-- yaml is the source of truth (there is no separate dashboard editor). An app with
-- no row uses the built-in default.
CREATE TABLE app_selfheal (
    project           TEXT    PRIMARY KEY,
    sustain_ticks     INTEGER NOT NULL,
    attempt_cap       INTEGER NOT NULL,
    stabilize_ticks   INTEGER NOT NULL,
    oom_strike_cap    INTEGER NOT NULL,
    window_seconds    INTEGER NOT NULL,
    backoff_base_secs INTEGER NOT NULL,
    backoff_max_secs  INTEGER NOT NULL,
    redeploy_enabled  INTEGER NOT NULL DEFAULT 0,
    updated_at        INTEGER NOT NULL
);
