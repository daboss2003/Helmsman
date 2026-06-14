-- M11 managed edge (plan §6): the operator's desired edge routes (Layer 1). The
-- edge config is NEVER stored as text — Helmsman holds this declarative set and
-- renders the WHOLE Caddy JSON document from typed structs every apply (SBD-7).
-- A route's upstream is an allowlisted app endpoint; control-plane ports are
-- rejected at struct-validate AND render time AND (on Linux) refused at dial.
CREATE TABLE app_routes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id           TEXT NOT NULL DEFAULT '',     -- owning project (informational)
    hostname         TEXT NOT NULL,                -- public vhost, e.g. app.example.com
    upstream         TEXT NOT NULL,                -- host:port of the app container endpoint
    upstream_scheme  TEXT NOT NULL DEFAULT 'http', -- http | https
    path_prefix      TEXT NOT NULL DEFAULT '',     -- optional path scoping
    redirect_http    INTEGER NOT NULL DEFAULT 1,   -- HTTP→HTTPS redirect
    hsts             INTEGER NOT NULL DEFAULT 1,   -- HSTS (only emitted once a cert exists)
    security_headers INTEGER NOT NULL DEFAULT 1,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(hostname, path_prefix)
);
