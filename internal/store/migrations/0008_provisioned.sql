-- M8 app provisioning (plan §7). One row per Helmsman-provisioned app. Helmsman
-- GENERATES and owns the compose from the typed spec (helmsman.yaml under the
-- hood) — there is no raw-compose paste. The run dir lives outside DataDir
-- (Helmsman-owned, sibling tree) and holds the generated compose; env values live
-- in the encrypted env store, NEVER here, so this row + spec are non-secret.
CREATE TABLE app_provisioned (
    slug         TEXT PRIMARY KEY,
    source       TEXT NOT NULL,                       -- 'generated' | 'inline'
    compose_path TEXT NOT NULL DEFAULT 'docker-compose.yml',
    spec_json    TEXT NOT NULL DEFAULT '',            -- Mode-1 typed spec (source of truth; '' for inline)
    created_at   INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);
