-- M20 "Connect with GitHub": the single operator-level GitHub OAuth connection.
-- One row (id=1). The access token is stored ENCRYPTED (AES-256-GCM, like every other
-- secret at rest) and is used ONLY to list repos + install per-repo read-only deploy
-- keys; day-to-day fetching uses those repo-scoped deploy keys, never this token.
CREATE TABLE github_connection (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    login      TEXT NOT NULL DEFAULT '',
    token_enc  BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
