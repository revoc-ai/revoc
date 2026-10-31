"""Initial schema — all tables from REVOC SPEC.md Section 15.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-06-06
"""

from __future__ import annotations

from alembic import op

# revision identifiers used by Alembic
revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id          TEXT    PRIMARY KEY,
            name        TEXT    NOT NULL,
            plan        TEXT    NOT NULL DEFAULT 'free',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_bundles (
            id              TEXT    PRIMARY KEY,
            org_id          TEXT    NOT NULL,
            name            TEXT    NOT NULL,
            environment     TEXT    NOT NULL DEFAULT 'production',
            version         TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'draft',
            yaml_content    TEXT    NOT NULL,
            rego_content    TEXT,
            compiled_at     TEXT,
            activated_at    TEXT,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            created_by      TEXT    NOT NULL,
            UNIQUE(org_id, name, version, environment)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_audit_log (
            id                  TEXT    PRIMARY KEY,
            policy_bundle_id    TEXT    NOT NULL,
            action              TEXT    NOT NULL,
            actor               TEXT    NOT NULL,
            yaml_hash_before    TEXT,
            yaml_hash_after     TEXT,
            timestamp           TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    op.execute(
        """
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
            created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ae_org_time  ON audit_events(org_id, timestamp DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ae_decision  ON audit_events(decision, timestamp DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ae_trace     ON audit_events(trace_id)"
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS kill_switch_log (
            id              TEXT    PRIMARY KEY,
            scope           TEXT    NOT NULL,
            scope_value     TEXT,
            action          TEXT    NOT NULL,
            activated_by    TEXT    NOT NULL,
            reason          TEXT,
            timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id              TEXT    PRIMARY KEY,
            org_id          TEXT    NOT NULL,
            username        TEXT    NOT NULL UNIQUE,
            email           TEXT    NOT NULL UNIQUE,
            hashed_pw       TEXT    NOT NULL,
            role            TEXT    NOT NULL DEFAULT 'viewer',
            is_superuser    INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id              TEXT    PRIMARY KEY,
            org_id          TEXT    NOT NULL,
            user_id         TEXT    NOT NULL,
            name            TEXT    NOT NULL,
            key_hash        TEXT    NOT NULL UNIQUE,
            caller_id       TEXT    NOT NULL,
            policy_profile  TEXT,
            expires_at      TEXT,
            last_used       TEXT,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        )
        """
    )


def downgrade() -> None:
    # Drop in reverse dependency order
    op.execute("DROP TABLE IF EXISTS api_keys")
    op.execute("DROP TABLE IF EXISTS users")
    op.execute("DROP INDEX IF EXISTS idx_ae_trace")
    op.execute("DROP INDEX IF EXISTS idx_ae_decision")
    op.execute("DROP INDEX IF EXISTS idx_ae_org_time")
    op.execute("DROP TABLE IF EXISTS audit_events")
    op.execute("DROP TABLE IF EXISTS kill_switch_log")
    op.execute("DROP TABLE IF EXISTS policy_audit_log")
    op.execute("DROP TABLE IF EXISTS policy_bundles")
    op.execute("DROP TABLE IF EXISTS organizations")
