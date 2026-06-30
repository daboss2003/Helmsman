-- Per-app mooring file path. A repo can hold SEVERAL mooring files —
-- mooring.yaml plus variants like mooring.staging.yaml / mooring.prod.yaml —
-- and EACH becomes its own deployed app instance (its own app_git row, its own
-- slug taken from that file's metadata.slug). This column records WHICH file in
-- the repo drives this particular app; the deploy reads the definition from it
-- (loadRepoDefinition). Existing rows + the common single-app case default to the
-- plain mooring.yaml, so this is a no-op for everyone who has only one.
ALTER TABLE app_git ADD COLUMN mooring_file_path TEXT NOT NULL DEFAULT 'mooring.yaml';
