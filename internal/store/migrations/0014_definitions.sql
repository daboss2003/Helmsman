-- M15 mooring.yaml definition file (plan §7.7). definition_versions is the history
-- of successfully-applied CANONICAL definitions per app; the latest row is the live
-- canonical (last applied = source of truth). Each row is HMAC-protected so a DB
-- tamper can't become a loaded definition: every read RE-PARSES + RE-VALIDATES the
-- stored YAML through the full pipeline (never a verbatim replay), and rollback
-- re-derives the same way.
CREATE TABLE definition_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    slug       TEXT    NOT NULL,
    yaml       TEXT    NOT NULL,           -- canonical YAML (re-validated on every read)
    hmac       BLOB    NOT NULL,           -- HMAC-SHA256(yaml) under a key derived from the encryption key
    note       TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX definition_versions_slug ON definition_versions(slug, id);
