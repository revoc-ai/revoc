"""Malformed-request and oversized-body resilience tests.

Verifies that the proxy handles adversarial HTTP payloads gracefully — returning
the correct 4xx status rather than 500 or panic — without leaking internal error
details.  None of these requests should reach the upstream LLM stub.

SPEC.md §7.1 RevocError:
  - BodyTooLarge → 413
  - RequestParse  → 400
"""

from __future__ import annotations

import json

import pytest

from .conftest import PROXY_BASE, wiremock_count

pytestmark = pytest.mark.asyncio


# ── Body-size enforcement ──────────────────────────────────────────────────────


async def test_oversized_request_body_returns_413(proxy_client, wiremock_llm):
    """A request body exceeding max_request_body_bytes (10 MiB per SPEC.md §13)
    must be rejected with HTTP 413 before any parsing or governance takes place.

    Sending 11 MiB of arbitrary bytes ensures the size check fires even without
    a valid JSON structure.  The upstream stub must receive zero requests.
    """
    oversized = b"A" * (11 * 1024 * 1024)  # 11 MiB — exceeds 10 MiB limit
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413, (
        f"Expected 413 for oversized body, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


# ── Malformed JSON ─────────────────────────────────────────────────────────────


async def test_malformed_json_returns_400(proxy_client, wiremock_llm):
    """A body with Content-Type: application/json that is not valid JSON must
    return HTTP 400 (RevocError::RequestParse).

    The upstream stub must receive zero requests.
    """
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=b"{not valid json !!!",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for malformed JSON, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_truncated_json_returns_400(proxy_client, wiremock_llm):
    """A syntactically truncated JSON body (no closing brace) must return 400."""
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for truncated JSON, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_binary_body_with_json_content_type_returns_400(proxy_client, wiremock_llm):
    """A binary (non-UTF-8) payload with Content-Type: application/json must
    return 400 — the body is not decodable as UTF-8 JSON.
    """
    # 10 KiB of bytes that are intentionally invalid UTF-8 sequences
    binary_payload = bytes([0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82]) * 1_700
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=binary_payload,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for binary body, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_empty_body_returns_400(proxy_client, wiremock_llm):
    """An empty body with Content-Type: application/json is not valid JSON
    and must return 400 — not 200 or 500.
    """
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=b"",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for empty body, got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_deeply_nested_json_returns_400(proxy_client, wiremock_llm):
    """A JSON payload nested beyond serde_json's default recursion limit (128)
    must return 400.  This prevents stack-overflow-style "JSON bomb" attacks
    where a tiny payload causes O(depth) stack frames during parsing.

    200 levels of nesting exceeds serde_json's recursion guard and must be
    rejected at parse time, before any governance evaluation.
    """
    # Build {"a": {"a": {"a": ... "x" ...}}} 200 levels deep
    inner: str = '"x"'
    for _ in range(200):
        inner = f'{{"a": {inner}}}'

    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=inner.encode(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, (
        f"Expected 400 for deeply nested JSON (200 levels), "
        f"got {resp.status_code}: {resp.text[:200]}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


# ── Error response format ──────────────────────────────────────────────────────


async def test_malformed_json_error_response_is_revoc_format(proxy_client):
    """A 400 from a malformed-JSON body must include a valid REVOC error JSON
    body — not an empty response or a plain-text error — so clients can handle
    it programmatically.

    The error object must have at minimum: error.code and error.message.
    """
    resp = await proxy_client.post(
        "/v1/chat/completions",
        content=b"this is not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    try:
        body = resp.json()
    except Exception:
        pytest.fail(f"400 response body is not valid JSON: {resp.text[:200]}")

    assert "error" in body, f"Expected 'error' key in response body, got: {body}"
    err = body["error"]
    assert "code" in err, f"Expected 'code' in error object, got: {err}"
    assert "message" in err, f"Expected 'message' in error object, got: {err}"
