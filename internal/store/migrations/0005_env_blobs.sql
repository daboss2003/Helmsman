-- M5 env store (plan §5.5, §9). Per-app environment, AES-256-GCM at rest, with
-- an immutable version history (auditable + rollback). The current env is the
-- highest version. Values (incl. secret-flagged ones) live only inside blob_enc.
CREATE TABLE env_blobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project    TEXT NOT NULL,
    version    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    blob_enc   BLOB NOT NULL,              -- AES-256-GCM(JSON [{k,v,s}])
    UNIQUE(project, version)
);
CREATE INDEX env_blobs_project ON env_blobs(project, version DESC);
