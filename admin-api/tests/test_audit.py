"""tests/test_audit.py — 4 audit router tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# ── helpers ───────────────────────────────────────────────────────────────────

_INGEST_EVENT = {
    "request_id": "req-001",
    "timestamp": "2026-06-06T10:00:00+00:00",
    "org_id": "test-org",
    "caller_id": "service-a",
    "decision": "block",
    "effective_action": "block",
    "enforcement_mode": "enforce",
    "violated_rules": ["sec_ddl_mutation_v1"],
    "trace_id": "trace-abc-001",
}

_SHADOW_EVENT = {
    "request_id": "req-shadow-001",
    "timestamp": "2026-06-06T11:00:00+00:00",
    "org_id": "test-org",
    "caller_id": "service-b",
    "decision": "block",
    "effective_action": "audit",
    "enforcement_mode": "shadow",
    "violated_rules": ["sec_prompt_injection_v1"],
    "trace_id": "trace-shadow-001",
}


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_creates_events(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """POST /audit/ingest should accept a batch and return inserted count."""
    resp = await async_client.post(
        "/api/v1/audit/ingest",
        json=[_INGEST_EVENT],
        headers=internal_key_headers,
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["inserted"] == 1

    # Verify the event is retrievable
    list_resp = await async_client.get(
        "/api/v1/audit?org_id=test-org", headers=auth_headers
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1
    ids = [e["request_id"] for e in data["items"]]
    assert "req-001" in ids


@pytest.mark.asyncio
async def test_list_with_filter(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /audit?decision=block should return only block decisions."""
    # Ingest a 'allow' event to ensure filtering works
    allow_event = {**_INGEST_EVENT, "request_id": "req-allow-001", "decision": "allow",
                   "effective_action": "allow", "trace_id": "trace-allow-001"}
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[allow_event, _INGEST_EVENT],
        headers=internal_key_headers,
    )

    resp = await async_client.get(
        "/api/v1/audit?decision=block", headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["decision"] == "block"


@pytest.mark.asyncio
async def test_shadow_report_shows_would_be_blocks(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /audit/shadow should count shadow-mode block decisions."""
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[_SHADOW_EVENT],
        headers=internal_key_headers,
    )

    resp = await async_client.get("/api/v1/audit/shadow", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_shadow_would_block" in data
    assert data["total_shadow_would_block"] >= 1


@pytest.mark.asyncio
async def test_csv_export_valid(
    async_client: AsyncClient,
    internal_key_headers: dict[str, str],
    auth_headers: dict[str, str],
) -> None:
    """GET /reports/csv should return a CSV file with correct content-type."""
    await async_client.post(
        "/api/v1/audit/ingest",
        json=[_INGEST_EVENT],
        headers=internal_key_headers,
    )

    resp = await async_client.get(
        "/api/v1/reports/csv"
        "?org_id=test-org"
        "&start_time=2026-06-06T00:00:00"
        "&end_time=2026-06-06T23:59:59",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "REVOC Compliance Report" in resp.text
