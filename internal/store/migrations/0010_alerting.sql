-- M10 alerting (plan §8): a read-and-notify engine — ZERO docker writes. The
-- evaluator reads the poller's snapshot and drives a per-(rule,target) state
-- machine; a SEPARATE rate-limited notifier drains the outbox. Channel configs are
-- AES-256-GCM encrypted under the master key (never plaintext at rest).

CREATE TABLE alert_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,                 -- webhook|smtp|telegram|slack|discord|ntfy
    config_enc  BLOB NOT NULL,                 -- AES-256-GCM(JSON channel config)
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE alert_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,               -- container_down|host_cpu|host_mem|host_disk|dep_down|restart_storm
    scope         TEXT NOT NULL DEFAULT '',    -- '' = all apps, else a project slug
    threshold     REAL NOT NULL DEFAULT 0,     -- % for host_*, count for restart_storm
    for_seconds   INTEGER NOT NULL DEFAULT 60, -- sustain window (anti-flap)
    level         TEXT NOT NULL DEFAULT 'warning', -- warning|critical
    defer_when_self_managed INTEGER NOT NULL DEFAULT 1,
    channel_id    INTEGER,                     -- NULL = all enabled channels
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL DEFAULT 0
);

-- Live per-(rule,target) state, recovered on restart (a bounce never re-fires or
-- loses an open alert).
CREATE TABLE alert_state (
    rule_id   INTEGER NOT NULL,
    target    TEXT NOT NULL,                   -- e.g. "host" or "shop/web"
    phase     TEXT NOT NULL DEFAULT 'ok',      -- ok|pending|firing|resolved
    since     INTEGER NOT NULL DEFAULT 0,      -- unix secs the current phase began
    level     TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT '',
    acked     INTEGER NOT NULL DEFAULT 0,
    silenced_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, target)
);

-- The handoff between evaluator (writer) and notifier (drainer). The evaluator
-- NEVER sends; it only appends here and signals the notifier.
CREATE TABLE alert_outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL,
    target      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    level       TEXT NOT NULL,
    transition  TEXT NOT NULL,                 -- firing|resolved
    summary     TEXT NOT NULL DEFAULT '',
    dedupe_key  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL DEFAULT 0,
    sent_at     INTEGER NOT NULL DEFAULT 0,    -- 0 = pending
    attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alert_outbox_pending ON alert_outbox(sent_at, id);
