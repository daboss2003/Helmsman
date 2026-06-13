-- M1 security spine schema (plan §9). Later milestones add apps, app_routes,
-- edge_config_versions, env_blobs, alerts, etc. via subsequent migrations.

-- Server-side opaque sessions. We store only the SHA-256 hash of the session id
-- (plan §5.3); the raw id lives only in the operator's cookie.
CREATE TABLE sessions (
    id_hash        BLOB PRIMARY KEY,          -- sha256(raw session id)
    username       TEXT NOT NULL,
    created_at     INTEGER NOT NULL,          -- unix seconds (wall clock)
    last_seen_at   INTEGER NOT NULL,          -- unix seconds; idle timeout anchor
    absolute_exp   INTEGER NOT NULL,          -- unix seconds; absolute timeout
    created_mono   INTEGER NOT NULL DEFAULT 0,-- monotonic anchor (plan §5.9), ns
    peer_ip        TEXT NOT NULL DEFAULT '',
    user_agent     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_absolute_exp ON sessions(absolute_exp);

-- Login throttling keyed on (real peer, username) plus a global per-username
-- counter so XFF rotation can't bypass the lockout (plan §5.2).
CREATE TABLE login_attempts (
    scope          TEXT NOT NULL,             -- 'peer_user' or 'user'
    key            TEXT NOT NULL,             -- e.g. "1.2.3.4|operator" or "operator"
    failures       INTEGER NOT NULL DEFAULT 0,
    first_failure  INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, key)
);

-- Append-only audit log. A monotonic seq (plan §5.9) keeps ordering stable even
-- if the wall clock is nudged. Never stores secret values.
CREATE TABLE events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,              -- unix seconds (wall clock, display)
    actor      TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    outcome    TEXT NOT NULL DEFAULT '',      -- 'ok' | 'deny' | 'error'
    level      TEXT NOT NULL DEFAULT 'info',  -- 'info' | 'security'
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX events_ts ON events(ts);

-- Free-form key/value settings (operator UI prefs only; never Tier-1).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
