"""tests/test_services.py — direct service-layer tests for coverage.

Tests PolicyBundleService and ReportService without going through the HTTP
layer, which has consistently failed to reach those code paths.
"""

from __future__ import annotations

import json
import pathlib
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.bundle_service as _bsvc_mod
from app.core.exceptions import PolicyNotFoundError
from app.models.audit import AuditEvent
from app.models.policy import PolicyBundle
from app.schemas.audit import AuditStatsResponse
from app.schemas.reports import ComplianceReportResponse
from app.services.bundle_service import PolicyBundleService
from app.services.report_service import ReportService

# ── shared test data ──────────────────────────────────────────────────────────

_YAML = (
    "apiVersion: revoc.io/v1\n"
    "kind: PolicyManifest\n"
    "metadata:\n"
    "  name: svc-test\n"
    "  org_id: svc-org\n"
    "spec:\n"
    "  profile: internal-dev\n"
)

_REGO = "package revoc.governance.custom\n# svc-test\n"


def _make_bundle(version: str, org_id: str = "svc-org") -> PolicyBundle:
    return PolicyBundle(
        org_id=org_id,
        name="svc-test",
        environment="production",
        version=version,
        yaml_content=_YAML,
        rego_content=_REGO,
        created_by="ci",
        status="draft",
    )


# ── PolicyBundleService ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bundle_service_activate_sets_active(
    db_session: AsyncSession,
) -> None:
    """PolicyBundleService.activate() should mark the bundle active and write to disk."""
    svc = PolicyBundleService()
    b = _make_bundle("1.0.0")
    db_session.add(b)
    await db_session.flush()

    result = await svc.activate(db_session, b.id, actor="ci")

    assert result.status == "active"
    assert result.activated_at is not None


@pytest.mark.asyncio
async def test_bundle_service_activate_archives_previous_active(
    db_session: AsyncSession,
) -> None:
    """Activating a new bundle should archive the previously active one."""
    svc = PolicyBundleService()

    b1 = _make_bundle("2.0.0")
    b2 = _make_bundle("2.1.0")
    db_session.add(b1)
    db_session.add(b2)
    await db_session.flush()

    await svc.activate(db_session, b1.id, actor="ci")
    # b1 is now active; activating b2 should archive b1
    await svc.activate(db_session, b2.id, actor="ci")

    await db_session.refresh(b1)
    assert b1.status == "archived"


@pytest.mark.asyncio
async def test_bundle_service_rollback_reactivates_archived(
    db_session: AsyncSession,
) -> None:
    """PolicyBundleService.rollback() should re-activate the last archived bundle."""
    svc = PolicyBundleService()

    b1 = _make_bundle("3.0.0")
    b2 = _make_bundle("3.1.0")
    db_session.add(b1)
    db_session.add(b2)
    await db_session.flush()

    await svc.activate(db_session, b1.id, actor="ci")  # b1 active
    await svc.activate(db_session, b2.id, actor="ci")  # b2 active, b1 archived

    rolled = await svc.rollback(db_session, b2.id, actor="ci")

    assert rolled.id == b1.id
    assert rolled.status == "active"


@pytest.mark.asyncio
async def test_bundle_service_write_to_disk(
    db_session: AsyncSession,
) -> None:
    """write_to_disk() should create YAML and Rego files under POLICY_DIR."""
    svc = PolicyBundleService()
    b = _make_bundle("4.0.0")
    db_session.add(b)
    await db_session.flush()

    # POLICY_DIR is patched to tmp_path by the autouse override_policy_dir fixture.
    policy_dir = _bsvc_mod.POLICY_DIR
    await svc.write_to_disk(b, policy_dir)

    base = pathlib.Path(policy_dir) / b.org_id / b.name
    assert (base / "policy.yaml").exists()
    assert (base / "policy.rego").exists()


# ── ReportService ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_service_generate_with_events(
    db_session: AsyncSession,
) -> None:
    """ReportService.generate() should aggregate counts from audit events."""
    svc = ReportService()

    ev = AuditEvent(
        request_id="rpt-svc-001",
        timestamp="2026-06-06T12:00:00",
        org_id="rpt-org",
        caller_id="rpt-caller",
        decision="block",
        effective_action="block",
        enforcement_mode="enforce",
        violated_rules=json.dumps(["sec_ddl_mutation_v1", "sec_prompt_injection_v1"]),
    )
    db_session.add(ev)
    await db_session.flush()

    report = await svc.generate(
        db_session,
        "rpt-org",
        datetime(2026, 6, 6, 0, 0, 0, tzinfo=UTC),
        datetime(2026, 6, 6, 23, 59, 59, tzinfo=UTC),
    )

    assert report.org_id == "rpt-org"
    assert report.summary.total >= 1
    assert report.summary.blocked >= 1
    assert len(report.summary.top_rules) >= 1


@pytest.mark.asyncio
async def test_report_service_generate_empty_org(
    db_session: AsyncSession,
) -> None:
    """generate() with no matching events should return zeroed summary."""
    svc = ReportService()
    report = await svc.generate(
        db_session,
        "org-that-does-not-exist",
        datetime(2020, 1, 1, tzinfo=UTC),
        datetime(2020, 1, 2, tzinfo=UTC),
    )
    assert report.summary.total == 0
    assert report.summary.blocked == 0


def test_report_service_to_csv_structure() -> None:
    """to_csv() should produce bytes containing the required header row."""
    svc = ReportService()
    report = ComplianceReportResponse(
        org_id="csv-org",
        start_time=datetime(2026, 6, 6, tzinfo=UTC),
        end_time=datetime(2026, 6, 6, 23, 59, 59, tzinfo=UTC),
        summary=AuditStatsResponse(
            total=5, blocked=3, redacted=1, allowed=1,
            top_rules=[{"rule_id": "sec_ddl_mutation_v1", "count": 3}],
            top_callers=[{"caller_id": "svc-a", "count": 5}],
        ),
        generated_at=datetime(2026, 6, 6, 12, tzinfo=UTC),
    )
    csv_bytes = svc.to_csv(report)

    assert b"REVOC Compliance Report" in csv_bytes
    assert b"csv-org" in csv_bytes
    assert b"sec_ddl_mutation_v1" in csv_bytes
    assert b"svc-a" in csv_bytes


# ── error-path coverage ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bundle_service_activate_not_found(
    db_session: AsyncSession,
) -> None:
    """activate() with a missing bundle_id raises PolicyNotFoundError (line 45)."""

    svc = PolicyBundleService()
    with pytest.raises(PolicyNotFoundError):
        await svc.activate(db_session, "does-not-exist", actor="ci")


@pytest.mark.asyncio
async def test_bundle_service_rollback_bundle_not_found(
    db_session: AsyncSession,
) -> None:
    """rollback() with a missing bundle_id raises PolicyNotFoundError (line 88)."""

    svc = PolicyBundleService()
    with pytest.raises(PolicyNotFoundError):
        await svc.rollback(db_session, "does-not-exist", actor="ci")


@pytest.mark.asyncio
async def test_bundle_service_rollback_no_prior_archived(
    db_session: AsyncSession,
) -> None:
    """rollback() when no archived bundle exists raises PolicyNotFoundError (line 103)."""

    svc = PolicyBundleService()
    b = _make_bundle("5.0.0")
    db_session.add(b)
    await db_session.flush()

    # Only one bundle, never archived — nothing to roll back to
    await svc.activate(db_session, b.id, actor="ci")
    with pytest.raises(PolicyNotFoundError):
        await svc.rollback(db_session, b.id, actor="ci")


@pytest.mark.asyncio
async def test_report_service_invalid_json_in_violated_rules(
    db_session: AsyncSession,
) -> None:
    """generate() silently skips violated_rules that aren't valid JSON (lines 52-53)."""
    svc = ReportService()

    ev = AuditEvent(
        request_id="rpt-badjson-001",
        timestamp="2026-06-06T14:00:00",
        org_id="rpt-badjson-org",
        caller_id="caller-x",
        decision="block",
        effective_action="block",
        enforcement_mode="enforce",
        violated_rules="not-valid-json",
    )
    db_session.add(ev)
    await db_session.flush()

    report = await svc.generate(
        db_session,
        "rpt-badjson-org",
        datetime(2026, 6, 6, 0, 0, 0, tzinfo=UTC),
        datetime(2026, 6, 6, 23, 59, 59, tzinfo=UTC),
    )
    assert report.summary.total >= 1
    assert report.summary.top_rules == []
