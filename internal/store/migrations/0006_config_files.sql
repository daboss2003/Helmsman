-- M5b managed config files + cert bindings (plan §7.4/§7.5, §9).

-- A managed config file: a structured template Helmsman renders host-side. The
-- template is stored encrypted (AES-256-GCM). secret_bearing forces 0600.
CREATE TABLE app_config_files (
    project        TEXT NOT NULL,
    name           TEXT NOT NULL,             -- operator label, unique per app
    rel_path       TEXT NOT NULL,             -- output path, confined under run_dir
    template_enc   BLOB NOT NULL,             -- AES-256-GCM(template bytes)
    bindings_json  TEXT NOT NULL DEFAULT '[]',-- [{Key,Source}] — names + source kinds
    secret_bearing INTEGER NOT NULL DEFAULT 0,
    mode_octal     INTEGER NOT NULL DEFAULT 416, -- 0640; 0600 (384) when secret-bearing
    rendered_sha256 TEXT NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project, name)
);

-- A cert binding wires an edge-issued cert (for a hostname on this app's routes)
-- to a per-consumer synced 0600 path under the run_dir. required=1 blocks the
-- consumer's `up` until the synced cert files exist (the cert-wait ordering gate).
-- The actual ACME issuance + cert-sync is the managed edge (M11); this is the
-- schema + the deploy-time gate.
CREATE TABLE app_cert_bindings (
    project      TEXT NOT NULL,
    binding_name TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    sync_dir_rel TEXT NOT NULL,               -- dir (under run_dir) the certs sync to
    required     INTEGER NOT NULL DEFAULT 1,
    updated_at   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project, binding_name)
);
