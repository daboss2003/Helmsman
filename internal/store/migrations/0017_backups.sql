-- Backups catalog: each row is one encrypted snapshot of Mooring's own state (the
-- SQLite DB, taken consistently via VACUUM INTO, then AES-256-GCM-encrypted with the
-- master key). This is the "recover Mooring onto a fresh box" backup — it captures
-- every app's config, secrets (already encrypted), definitions, edge routes, etc.
-- The archive file lives under <data_dir>/backups/<id>.mbk; only the catalog row and
-- the encrypted file are kept (no plaintext snapshot is ever retained).
CREATE TABLE backups (
    id         TEXT PRIMARY KEY,             -- 24 hex chars
    created_at INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,   -- size of the encrypted archive
    file       TEXT NOT NULL,                -- filename under the backups dir
    sha256     TEXT NOT NULL DEFAULT '',     -- hex sha-256 of the encrypted archive
    kind       TEXT NOT NULL DEFAULT 'mooring-state',
    note       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_backups_created ON backups(created_at DESC);
