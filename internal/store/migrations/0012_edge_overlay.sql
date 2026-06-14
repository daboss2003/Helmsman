-- M11b: the Layer-2 operator overlay (plan §6.2). Each save is a new version row;
-- the ACTIVE overlay is the latest row. The overlay text is NEVER loaded verbatim
-- — every apply re-parses + re-lints it as untrusted (RenderComposite/ParseOverlay)
-- and re-derives the composite from typed structs. The HMAC is defence-in-depth:
-- a DB tamper that leaves the linter satisfied is still caught (the row's MAC won't
-- verify) and the overlay is dropped fail-closed with a level=security audit.
CREATE TABLE edge_overlay (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    overlay    TEXT    NOT NULL,            -- raw operator JSON (re-validated on every apply)
    hmac       BLOB    NOT NULL,            -- HMAC-SHA256(overlay) under a key derived from the encryption key
    note       TEXT    NOT NULL DEFAULT '', -- operator note / provenance
    created_at INTEGER NOT NULL
);
