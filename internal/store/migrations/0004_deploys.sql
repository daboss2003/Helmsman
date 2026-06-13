-- M4 write plane: a record of every lifecycle/deploy action (plan §9 deploys).
CREATE TABLE deploys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    service     TEXT NOT NULL DEFAULT '',   -- '' = whole project
    action      TEXT NOT NULL,              -- start|stop|restart|redeploy
    source      TEXT NOT NULL DEFAULT 'manual', -- manual|auto_deploy|rollback|initial
    actor       TEXT NOT NULL DEFAULT '',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL DEFAULT 0,
    exit_code   INTEGER NOT NULL DEFAULT -1,
    outcome     TEXT NOT NULL DEFAULT ''    -- ok|error|disabled
);
CREATE INDEX deploys_project ON deploys(project, started_at);
