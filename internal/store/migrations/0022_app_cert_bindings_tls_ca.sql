-- Per-cert-binding TLS issuer selection. A cert binding can opt into a named private CA
-- (defined in config.yaml edge.cas) instead of the default edge.acme_ca. '' = default,
-- so existing bindings are unaffected.
ALTER TABLE app_cert_bindings ADD COLUMN tls_ca TEXT NOT NULL DEFAULT '';
