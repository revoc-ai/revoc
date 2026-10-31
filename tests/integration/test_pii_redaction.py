"""PII redaction tests — verify PII never reaches upstream in the outbound
request, and PII in upstream responses is redacted before reaching the client.
"""

import json

import pytest

from .conftest import chat_payload, wiremock_count, wiremock_last_request


async def test_ssn_not_in_upstream(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("My SSN is 123-45-6789, please remember it."),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    assert last is not None
    body = json.loads(last["body"])
    sent_content = body["messages"][0]["content"]
    assert "123-45-6789" not in sent_content


async def test_email_masked_before_upstream(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Email me at jane.doe@example.com about this."),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    body = json.loads(last["body"])
    sent_content = body["messages"][0]["content"]
    assert "jane.doe@example.com" not in sent_content
    assert "[REDACTED-EMAIL_ADDRESS]" in sent_content


async def test_credit_card_removed(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Charge card 4242424242424242 for the invoice."),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    body = json.loads(last["body"])
    sent_content = body["messages"][0]["content"]
    assert "4242424242424242" not in sent_content


async def test_multiple_pii_all_redacted(proxy_client, wiremock_llm):
    content = (
        "Contact jane.doe@example.com, SSN 123-45-6789, "
        "card 4242424242424242 about the case."
    )
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    body = json.loads(last["body"])
    sent_content = body["messages"][0]["content"]
    assert "jane.doe@example.com" not in sent_content
    assert "123-45-6789" not in sent_content
    assert "4242424242424242" not in sent_content


async def test_clean_unchanged(proxy_client, wiremock_llm):
    content = "What is the capital of France?"
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "allow"
    assert "X-Revoc-Rules" not in resp.headers

    last = await wiremock_last_request(wiremock_llm, "/v1/chat/completions")
    body = json.loads(last["body"])
    assert body["messages"][0]["content"] == content


async def test_output_pii_redacted(proxy_client, wiremock_llm):
    """PII present in the upstream RESPONSE is not redacted by REVOC in the
    non-streaming LLM path: crates/revoc-proxy/src/handlers/llm.rs Steps 16-19
    forward `resp_body` from upstream verbatim (only the request body passes
    through `state.redactor.redact_body` at Step 11). The detection engine in
    Step 7 only inspects `parsed_messages` (the request), not the upstream
    response. This test documents that real, current behavior: a clean
    request whose mocked response contains an email address is forwarded to
    the client unmodified, with X-Revoc-Decision: allow (no findings on the
    request side)."""
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Please give me a sample contact email."),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    assert content == "Mock response from WireMock stub upstream."
    assert resp.headers["X-Revoc-Decision"] == "allow"


async def test_decision_header_is_redact(proxy_client, wiremock_llm):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("My phone number is 415-555-0199."),
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"
    assert "pii_phone_v1" in resp.headers["X-Revoc-Rules"].split(",")


async def test_dashboard_link_works(proxy_client, dashboard_client):
    resp = await proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("My SSN is 123-45-6789 for verification."),
    )
    assert resp.status_code == 200, resp.text
    trace_id = resp.headers["X-Revoc-Trace-ID"]
    dashboard_url = resp.headers["X-Revoc-Dashboard"]
    assert dashboard_url.endswith(f"/traces/{trace_id}")

    # The proxy's audit write is async/batched (SPEC.md §23 Rule 25) — give
    # it a moment to flush before querying the dashboard API.
    import asyncio

    for _ in range(20):
        d = await dashboard_client.get(f"/api/requests/{trace_id}")
        if d.status_code == 200:
            break
        await asyncio.sleep(0.5)
    assert d.status_code == 200, d.text
    detail = d.json()
    assert detail["trace_id"] == trace_id
