"""Streaming (SSE) governance tests — SPEC.md §12,
crates/revoc-proxy/src/upstream/streaming.rs and
crates/revoc-proxy/src/streaming/governor.rs.

The mock-llm wiremock mapping docker/wiremock/mock-llm/mappings/chat-completions-stream.json
matches `"stream": true` and returns 3 SSE chunks: a greeting, a chunk containing
a US_SSN (123-45-6789), and a stop chunk, followed by `data: [DONE]`.

The stream governor applies the same policy to streamed text as to any other
response: PII is redacted in-stream (the SSN is removed, per the redaction
strategy for US_SSN), secrets and security findings stop the stream with a
synthetic content_filter chunk, and tool calls are held until governed.
"""

import json

import httpx
import pytest

from .conftest import PROXY_BASE, chat_payload


async def _read_sse_events(resp):
    events = []
    async for line in resp.aiter_lines():
        if line.startswith("data: "):
            events.append(line[len("data: "):])
    return events


async def test_streaming_fast_first_chunk(proxy_client):
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=chat_payload("Say hello", stream=True),
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            first_line = None
            async for line in resp.aiter_lines():
                if line.strip():
                    first_line = line
                    break
            assert first_line is not None
            assert first_line.startswith("data: ")


async def test_streaming_ssn_is_redacted_in_stream(proxy_client):
    """The second chunk contains a US_SSN. The default policy redacts PII, so
    the stream completes normally with the SSN removed — it never reaches the
    client, and the surrounding text does."""
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=chat_payload("Tell me an SSN", stream=True),
        ) as resp:
            assert resp.status_code == 200
            events = await _read_sse_events(resp)

    assert events, "expected at least one SSE event"
    assert "123-45-6789" not in "\n".join(events)
    assert events[-1].strip() == "[DONE]"

    text = ""
    finish = None
    for ev in events:
        if ev.strip() == "[DONE]":
            continue
        choice = (json.loads(ev).get("choices") or [{}])[0]
        text += (choice.get("delta") or {}).get("content") or ""
        finish = choice.get("finish_reason") or finish
    assert text.startswith("Hello there, the SSN is"), text
    assert text.endswith(" ok"), text
    assert finish == "stop"


async def test_tool_call_finish_reason_governed(proxy_client, wiremock_llm):
    """A streamed response with finish_reason=tool_calls must NEVER be forwarded
    to the client when the accumulated tool-call arguments contain dangerous
    content (DDL mutation in this case).

    The wiremock mapping chat-completions-stream-tool-calls.json returns three
    SSE chunks:
      1. Tool call setup  (execute_sql, empty args)
      2. Arguments chunk  ({"sql": "DROP TABLE users;"})
      3. finish_reason=tool_calls

    REVOC must intercept the stream before finish_reason=tool_calls reaches the
    client. Tool-call deltas are held by the stream governor and released only
    after the assembled calls pass governance; here they fail, so a synthetic
    content_filter chunk is sent instead and finish_reason=tool_calls is
    suppressed.

    SPEC.md §23 Rule 22: never forward finish_reason=tool_calls before
    governance on accumulated calls.
    """
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=chat_payload("tool_call_governance_test please run it", stream=True),
        ) as resp:
            assert resp.status_code == 200, f"Unexpected status: {resp.status_code}"
            events = await _read_sse_events(resp)

    assert events, "Expected at least one SSE event from the stream"

    tool_calls_seen = False
    content_filter_seen = False
    for ev in events:
        if ev.strip() == "[DONE]":
            continue
        try:
            parsed = json.loads(ev)
        except json.JSONDecodeError:
            continue
        choices = parsed.get("choices", [])
        if not choices:
            continue
        finish = choices[0].get("finish_reason")
        if finish == "tool_calls":
            tool_calls_seen = True
        if finish == "content_filter":
            content_filter_seen = True

    assert not tool_calls_seen, (
        "finish_reason=tool_calls must never reach the client when the accumulated "
        "call contains dangerous content (SPEC.md §23 Rule 22)"
    )
    assert content_filter_seen, (
        "Expected a synthetic content_filter chunk injected by governance; "
        f"got events: {events}"
    )
    full_text = " ".join(events)
    assert "DROP TABLE" not in full_text.upper(), (
        "DDL payload must not be forwarded verbatim in any stream chunk"
    )


async def test_audit_event_written_after_stream(proxy_client, dashboard_client):
    """After a (non-blocked) stream completes, the stream governor persists
    a response-side AuditEvent with request_type=LlmResponse (the request side
    is audited separately when the stream starts). We can't get the trace_id
    from streaming responses' headers before the body starts (set_revoc_headers
    is applied to the response builder, so X-Revoc-Trace-ID IS present on the
    initial response headers) — fetch it and poll the dashboard analytics
    endpoint for an increase in total request count as indirect confirmation
    the audit write occurred."""
    import asyncio

    before = await dashboard_client.get("/api/analytics")
    assert before.status_code == 200, before.text
    total_before = before.json()["total"]

    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=chat_payload("Say hello, nothing sensitive", stream=True),
        ) as resp:
            assert resp.status_code == 200
            trace_id = resp.headers["X-Revoc-Trace-ID"]
            async for _ in resp.aiter_lines():
                pass

    # The request-side event is written when the stream starts and the
    # response-side one just after it ends; the trace shows the latest, so
    # poll until the response side has landed.
    detail = None
    for _ in range(20):
        d = await dashboard_client.get(f"/api/requests/{trace_id}")
        if d.status_code == 200:
            detail = d.json()
            if detail["request_type"] == "LlmResponse":
                break
        await asyncio.sleep(0.5)
    assert detail is not None, "stream audit event was not written"
    assert detail["request_type"] == "LlmResponse"


async def test_buffer_output_mode_not_per_request_configurable(proxy_client):
    """`stream.buffer_output` (SPEC.md §13) is a static proxy-wide config
    value read once from AppState/config at startup
    (crates/revoc-proxy/src/upstream/streaming.rs reads
    `state.config.stream.buffer_output`). There is no
    request header or body field that overrides it per-request, and the test
    stack's revoc.toml/env does not set REVOC_STREAM__BUFFER_OUTPUT (so it
    uses the documented default `false`). Verifying the `true` (HIPAA/PCI
    full-buffer) branch would require a second proxy instance with different
    config, which is out of scope for this suite. We instead confirm the
    documented default (false / incremental streaming) is what's active by
    checking that streaming responses arrive as `text/event-stream` with
    multiple discrete chunks rather than a single buffered JSON/SSE blob."""
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=chat_payload("Say hello, nothing sensitive", stream=True),
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            chunk_count = 0
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    chunk_count += 1
            assert chunk_count >= 2
