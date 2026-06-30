-- L4 (TCP/UDP) load-balancer routes: the operator's desired stream listeners
-- (the L4 analog of app_routes). Like the edge, the nginx-stream config is NEVER
-- stored as text — Mooring holds this declarative set and renders the whole config
-- from typed structs each apply. A listener (listen+protocol) is globally unique so
-- two apps can never fight over the same public port; the upstream is an allowlisted
-- internal service:port, control-plane ports rejected at validate + render time.
CREATE TABLE app_l4_routes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     TEXT    NOT NULL,                -- owning project
    listen     INTEGER NOT NULL,               -- the host port the L4 LB binds
    protocol   TEXT    NOT NULL,               -- tcp | udp
    service    TEXT    NOT NULL,               -- selector → the service whose replicas receive traffic
    port       INTEGER NOT NULL,               -- the service's internal container port
    lb         TEXT    NOT NULL DEFAULT '',    -- '' (round_robin) | least_conn | hash_client_ip
    created_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE(listen, protocol)
);
