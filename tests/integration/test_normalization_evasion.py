"""Unicode normalization (D8) evasion tests — crates/revoc-detector/src/normalization.rs.

normalize() applies, in order: NFKC, zero-width removal (7 chars), BIDI/RTLO
removal (9 chars), control-char strip (preserving \\n \\r \\t). It is applied
before every regex pass; matched findings get was_normalized=true.
"""

import base64

import pytest

from .conftest import chat_payload, wiremock_count


async def test_fullwidth_ddl_blocked(proxy_client, wiremock_llm):
    """Fullwidth Unicode forms (U+FF01-FF5E) NFKC-normalize to their ASCII
    equivalents, so 'ＤＲＯＰ ＴＡＢＬＥ ｕｓｅｒｓ' becomes 'DROP TABLE users'
    and triggers sec_ddl_mutation_v1."""
    content = "Please run ＤＲＯＰ ＴＡＢＬＥ users now."
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 403, resp.text
    rules = resp.headers["X-Revoc-Rules"].split(",")
    assert "sec_ddl_mutation_v1" in rules
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_zero_width_ssn_redacted(proxy_client, wiremock_llm):
    """Zero-width chars (e.g. U+200B ZERO WIDTH SPACE) inserted inside an SSN
    are stripped before regex scanning, so '123\\u200b-45-6789' still matches
    US_SSN and is redacted (pii_ssn_v1)."""
    zwsp = "​"
    content = f"My SSN is 123{zwsp}-45{zwsp}-6789, please note it."
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact"
    assert "pii_ssn_v1" in resp.headers["X-Revoc-Rules"].split(",")
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1


async def test_rtlo_wrapped_pattern_blocked(proxy_client, wiremock_llm):
    """RTLO/BIDI control chars (e.g. U+202E RIGHT-TO-LEFT OVERRIDE) wrapped
    around a DDL phrase are stripped before scanning, so the underlying
    'DROP TABLE users' text is still detected and blocked."""
    rtlo = "‮"
    pdf = "‬"
    content = f"Run this: {rtlo}sresu ELBAT PORD{pdf} on staging."
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 403, resp.text
    rules = resp.headers["X-Revoc-Rules"].split(",")
    assert "sec_ddl_mutation_v1" in rules
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_cyrillic_homoglyphs_not_falsely_normalized(proxy_client, wiremock_llm):
    """Cyrillic homoglyphs (е.g. Cyrillic 'е' U+0435, 'а' U+0430, 'о' U+043E,
    'р' U+0440) are NOT canonically equivalent to Latin letters under NFKC —
    NFKC only folds compatibility/formatting variants (fullwidth, ligatures,
    etc.), not cross-script homoglyphs. So a DDL phrase spelled with Cyrillic
    look-alikes does NOT normalize to 'DROP TABLE users' and is NOT detected
    as sec_ddl_mutation_v1 — it passes through as an ordinary allowed message.
    This documents real normalization.rs behavior (NFKC is not a homoglyph
    defense)."""
    # "DROP TABLE users" with Cyrillic а(0430), е(0435), о(043E), р(0440)
    content = "Plеаse run DRОP TABLE useрs on staging."  # noqa: RUF001
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    rules = resp.headers.get("X-Revoc-Rules", "")
    assert "sec_ddl_mutation_v1" not in rules.split(",")
    assert resp.headers["X-Revoc-Decision"] == "allow"
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1


async def test_clean_base64_content_allowed(proxy_client, wiremock_llm):
    """Base64-encoded content with no embedded security/PII pattern (e.g. a
    benign greeting) decodes cleanly via encoding::prepare_scan_targets() but
    produces no findings, so the request is allowed normally."""
    payload = base64.b64encode(b"Hello world, just a friendly greeting.").decode()
    content = f"Here is some encoded text: {payload}"
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "allow"
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1


async def test_null_byte_injection_ddl_blocked(proxy_client, wiremock_llm):
    """NUL bytes (\\x00) injected between word characters in a DDL phrase are
    converted to spaces by normalization Step 4 before regex scanning.

    Without the fix: "DROP\\x00TABLE" → "DROPTABLE" (no word-boundary match).
    With the fix:     "DROP\\x00TABLE" → "DROP TABLE" → sec_ddl_mutation_v1 fires.

    Sent via MCP tools/call so the argument value reaches the DDL detector path.
    """
    from .conftest import mcp_tools_call

    null_byte_ddl = "DROP\x00TABLE users;"
    resp = await proxy_client.post(
        "/mcp",
        json=mcp_tools_call("execute_sql", {"query": null_byte_ddl}, server_id="mock-mcp"),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # MCP blocks return HTTP 200 with JSON-RPC error body (SPEC.md §11 Step 9)
    assert "error" in data, f"Expected JSON-RPC error for null-byte DDL, got: {data}"
    assert data["error"]["data"]["code"] == "REVOC_GOVERNANCE_BLOCK"
    rules = data["error"]["data"]["rules"]
    assert "sec_ddl_mutation_v1" in rules, f"Expected sec_ddl_mutation_v1, got rules: {rules}"
    assert resp.headers.get("X-Revoc-Block") == "true"


async def test_double_encoded_base64_ddl_blocked(proxy_client, wiremock_llm):
    """A DDL payload hidden under two layers of base64 encoding must be caught
    by the multi-level decoder in encoding::prepare_scan_targets().

    Single-pass base64 scanners decode layer 1 and see another base64 string,
    not the payload. The multi-level decoder (depth=3) peels both layers and
    exposes "DROP TABLE users;" to the DDL regex.
    """
    raw = b"DROP TABLE users;"
    layer1 = base64.b64encode(raw).decode()
    layer2 = base64.b64encode(layer1.encode()).decode()
    content = f"Please decode and execute: {layer2}"
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 403, (
        f"Expected 403 for double-encoded DDL, got {resp.status_code}: {resp.text[:200]}"
    )
    rules = resp.headers["X-Revoc-Rules"].split(",")
    assert "sec_encoded_evasion_v1" in rules or "sec_ddl_mutation_v1" in rules, (
        f"Expected a security block rule, got rules: {rules}"
    )
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 0


async def test_mathematical_bold_digits_ssn_redacted(proxy_client, wiremock_llm):
    """Mathematical Bold digit characters (U+1D7CF–U+1D7D8) NFKC-normalize to
    their ASCII equivalents, so '𝟏𝟐𝟑-𝟒𝟓-𝟔𝟕𝟖��' becomes '123-45-6789' and
    triggers pii_ssn_v1 redaction.

    These are distinct from Cyrillic homoglyphs (which NFKC does NOT normalize)
    — mathematical symbols ARE compatibility variants and ARE folded by NFKC.
    """
    # Mathematical Bold digits U+1D7CF (1) through U+1D7D8 (9): 𝟏𝟐𝟑-𝟒𝟓-𝟔𝟕𝟖𝟗
    math_bold_ssn = (
        "\U0001d7cf\U0001d7d0\U0001d7d1"        # 𝟏𝟐𝟑
        "-"
        "\U0001d7d2\U0001d7d3"                  # 𝟒𝟓
        "-"
        "\U0001d7d4\U0001d7d5\U0001d7d6\U0001d7d7"  # 𝟔𝟕𝟖𝟗
    )
    content = f"My identifier is {math_bold_ssn} please verify."
    resp = await proxy_client.post("/v1/chat/completions", json=chat_payload(content))
    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Revoc-Decision"] == "redact", (
        f"Expected redact for math-bold SSN, got: {resp.headers.get('X-Revoc-Decision')}"
    )
    rules = resp.headers["X-Revoc-Rules"].split(",")
    assert "pii_ssn_v1" in rules, f"Expected pii_ssn_v1, got rules: {rules}"
    assert await wiremock_count(wiremock_llm, "/v1/chat/completions") == 1
