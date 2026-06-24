-- Per-route TLS issuer selection. A route can opt into a named private CA (defined in
-- config.yaml edge.cas) instead of the default edge.acme_ca. '' = the default issuer,
-- so existing routes are unaffected.
ALTER TABLE app_routes ADD COLUMN tls_ca TEXT NOT NULL DEFAULT '';
