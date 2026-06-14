-- M9 setup-script sandbox (plan §7/§9, Mode 3 — OFF by default, hard-gated).
-- One script set per app (encrypted at rest — a bootstrap script may embed
-- sensitive logic), plus a run ledger keyed by the FULL script_set_checksum so
-- on_first_deploy is idempotent and a confirmation is void on any byte change.
CREATE TABLE setup_scripts (
    slug        TEXT PRIMARY KEY,
    script_enc  BLOB NOT NULL,                     -- AES-256-GCM(script bytes)
    trigger     TEXT NOT NULL DEFAULT 'never',     -- never|on_demand|on_first_deploy|before_each_deploy
    produces    TEXT NOT NULL DEFAULT '',          -- newline-joined env:NAME / file:relpath
    pinned_sha  TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE setup_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT NOT NULL,
    checksum    TEXT NOT NULL,                      -- full script_set_checksum
    outcome     TEXT NOT NULL DEFAULT '',           -- ok | error | blocked
    exit_code   INTEGER NOT NULL DEFAULT 0,
    actor       TEXT NOT NULL DEFAULT '',
    started_at  INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX setup_runs_lookup ON setup_runs(slug, checksum);
