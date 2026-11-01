-- Postgres audit schema (SPEC.md §15). Column names and types match the
-- admin API's alembic migration 001 so both services share one table; every
-- statement is idempotent so either side may create it first.
CREATE TABLE IF NOT EXISTS audit_events (
    id                  TEXT    PRIMARY KEY,
    org_id              TEXT,
    request_id          TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    caller_id           TEXT,
    caller_team         TEXT,
    environment         TEXT,
    decision            TEXT    NOT NULL,
    effective_action    TEXT    NOT NULL,
    enforcement_mode    TEXT    NOT NULL DEFAULT 'enforce',
    violated_rules      TEXT,
    finding_types       TEXT,
    model               TEXT,
    provider            TEXT,
    tool_name           TEXT,
    request_type        TEXT,
    governance_depth    INTEGER DEFAULT 0,
    prompt_tokens       INTEGER,
    completion_tokens   INTEGER,
    estimated_cost_usd  REAL,
    duration_ms         REAL,
    detection_ms        REAL,
    policy_ms           REAL,
    was_normalized      INTEGER DEFAULT 0,
    manifest_warnings   INTEGER DEFAULT 0,
    trace_id            TEXT,
    policy_engine       TEXT,
    created_at          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ae_org_time ON audit_events(org_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_decision ON audit_events(decision, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_trace    ON audit_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_ae_created  ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS kill_switch_log (
    id              TEXT    PRIMARY KEY,
    scope           TEXT    NOT NULL,
    scope_value     TEXT,
    action          TEXT    NOT NULL,
    activated_by    TEXT    NOT NULL,
    reason          TEXT,
    timestamp       TEXT    NOT NULL
);

-- Durable kill-switch state (SPEC.md §9 D11): one signed, versioned document.
CREATE TABLE IF NOT EXISTS kill_switch_state (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version BIGINT  NOT NULL,
    signed  TEXT    NOT NULL
);
