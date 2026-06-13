-- M3 App Ops Interface (plan §4, §9). Per-app ops coordinates (the shared secret
-- is stored AES-256-GCM, never in the clear) plus the snapshot ring.

CREATE TABLE app_ops (
    project       TEXT PRIMARY KEY,
    enabled       INTEGER NOT NULL DEFAULT 0,
    base_url      TEXT NOT NULL DEFAULT '',  -- operator-configured, pinned origin
    secret_header TEXT NOT NULL DEFAULT '',
    secret_enc    BLOB,                      -- AES-256-GCM(shared secret); NULL = none
    ops_mode      TEXT NOT NULL DEFAULT 'auto', -- auto | rich | basic
    base_path     TEXT NOT NULL DEFAULT '',
    adapter       TEXT NOT NULL DEFAULT 'ops.v1',
    updated_at    INTEGER NOT NULL DEFAULT 0,
    -- cached discovery state (refreshed each probe)
    disc_mode     TEXT NOT NULL DEFAULT '',
    disc_version  TEXT NOT NULL DEFAULT '',
    disc_caps     TEXT NOT NULL DEFAULT '',  -- JSON array
    last_probe_at INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT ''
);

-- Per-app health-score ring for the sparkline (plan §4.3, §9 ops_snapshot).
CREATE TABLE ops_snapshot (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    score   REAL NOT NULL DEFAULT 0  -- 0..1 fraction of dependencies up
);
CREATE INDEX ops_snapshot_proj_ts ON ops_snapshot(project, ts);
