-- M6 repo-path GitOps (plan §7.6, §9). One row per repo-backed app. Credentials
-- + the webhook HMAC secret are AES-256-GCM at rest; the webhook token is stored
-- only as a SHA-256 hash (the high-entropy token itself is never persisted/logged).
CREATE TABLE app_git (
    project          TEXT PRIMARY KEY,
    repo_url         TEXT NOT NULL,
    git_ref          TEXT NOT NULL DEFAULT 'refs/heads/main',
    compose_path     TEXT NOT NULL DEFAULT 'docker-compose.yml',
    dockerfile_path  TEXT NOT NULL DEFAULT '',
    auto_deploy      INTEGER NOT NULL DEFAULT 0,   -- default OFF (plan §7.6)
    build_policy     TEXT NOT NULL DEFAULT 'never', -- never | on_missing (on-box build, ≥1GB)
    cred_kind        TEXT NOT NULL DEFAULT '',      -- '' | token | ssh
    cred_enc         BLOB,                          -- AES-256-GCM(PAT or ssh key)
    known_hosts_enc  BLOB,                          -- AES-256-GCM(pinned known_hosts, ssh)
    deployed_commit  TEXT NOT NULL DEFAULT '',
    staged_commit    TEXT NOT NULL DEFAULT '',
    update_state     TEXT NOT NULL DEFAULT 'up_to_date',
    commits_behind   INTEGER NOT NULL DEFAULT 0,
    last_fetch_at    INTEGER NOT NULL DEFAULT 0,
    last_fetch_error TEXT NOT NULL DEFAULT '',      -- classified, never raw git stderr
    webhook_token_hash BLOB,                        -- sha256(token)
    webhook_secret_enc BLOB,                        -- AES-256-GCM(HMAC key)
    updated_at       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX app_git_webhook ON app_git(webhook_token_hash);
