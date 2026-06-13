-- M2 read plane (plan §9): the app registry (discovered from compose-project
-- labels for now; provisioning in M8 adds the rest) and the metrics rings.

-- An "app" is one Docker Compose project (plan §3). In M2 rows are discovered
-- from container labels; later milestones add provision_mode/git/def fields.
CREATE TABLE apps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project      TEXT NOT NULL UNIQUE,      -- com.docker.compose.project
    display_name TEXT NOT NULL DEFAULT '',
    discovered   INTEGER NOT NULL DEFAULT 1,-- 1 = seen via Docker, not yet provisioned
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL
);

-- Per-container metric samples (BASIC mode, plan §4.3). Bounded by retention
-- (full retention/VACUUM is §16/M18; M2 prunes by age).
CREATE TABLE container_metrics (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    project       TEXT NOT NULL,
    service       TEXT NOT NULL DEFAULT '',
    container_id  TEXT NOT NULL DEFAULT '',
    state         TEXT NOT NULL DEFAULT '', -- running|exited|created|...
    health        TEXT NOT NULL DEFAULT '', -- healthy|unhealthy|starting|none
    cpu_pct       REAL NOT NULL DEFAULT 0,
    mem_bytes     INTEGER NOT NULL DEFAULT 0,
    mem_limit     INTEGER NOT NULL DEFAULT 0,
    restart_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX container_metrics_ts ON container_metrics(ts);
CREATE INDEX container_metrics_proj_ts ON container_metrics(project, ts);

-- Host RAM/disk/CPU samples (plan §4 read plane).
CREATE TABLE host_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    cpu_pct     REAL NOT NULL DEFAULT 0,
    load1       REAL NOT NULL DEFAULT 0,
    mem_total   INTEGER NOT NULL DEFAULT 0,
    mem_used    INTEGER NOT NULL DEFAULT 0,
    disk_total  INTEGER NOT NULL DEFAULT 0,
    disk_used   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX host_metrics_ts ON host_metrics(ts);
