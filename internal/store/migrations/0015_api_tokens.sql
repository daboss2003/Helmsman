-- M19 scoped API tokens (plan §17.1): a new front DOOR, never a new trust PATH.
-- A token is strictly LESS privileged than a browser session — its scope grammar
-- (see internal/apitoken) has no symbol for any Tier-1 capability, reveal-secret,
-- raw-Caddy, setup-run, or mint-another-token. Tokens are minted ONLY over the
-- CLI/SSH; the web never mints. Only the argon2id hash is stored (never plaintext),
-- the id scopes the verify to exactly one row, and every token carries a MANDATORY
-- expiry + a non-empty CIDR set (a token is an auth factor, not an allowlist bypass).
CREATE TABLE api_tokens (
    id          TEXT PRIMARY KEY,            -- 24 hex chars; selects exactly one row
    hash        TEXT NOT NULL,               -- argon2id-encoded secret (never plaintext)
    scopes      TEXT NOT NULL,               -- space-separated validated scope set
    cidrs       TEXT NOT NULL,               -- space-separated non-empty CIDR set
    label       TEXT NOT NULL DEFAULT '',    -- operator note (informational)
    created_at  INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL,            -- mandatory; active requires expires_at > now
    revoked     INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_api_tokens_active ON api_tokens(revoked, expires_at);
