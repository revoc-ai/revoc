# Threat Model

REVOC defends against threats that arise specifically from AI agent deployments.
This page catalogues the threat categories, how REVOC detects them, and their limits.

## Threat Categories

### T1 — PII Leakage to LLM

**Scenario:** Application code passes user records directly into LLM prompts.
Customer SSNs, emails, and phone numbers reach a third-party AI provider.

**REVOC defense:** Detection pipeline runs on every request before it reaches the
upstream. PII entities are redacted (removed or masked) before forwarding.

**Limit:** REVOC detects known PII patterns. Novel PII formats not covered by the
11 entity types require custom rules or the ONNX enricher.

---

### T2 — Secret Exposure in Prompts

**Scenario:** A developer includes an API key or private key in a prompt for
debugging. The secret reaches the LLM and is potentially stored in training data.

**REVOC defense:** Secret rules (Security tier) detect all major secret formats
and block the request before it reaches the upstream.

**Limit:** Custom or internal secret formats not matching known patterns require
a custom `GENERIC_API_KEY` rule extension.

---

### T3 — Prompt Injection

**Scenario:** User-supplied content in an RAG pipeline contains instructions
designed to override the model's system prompt: "Ignore previous instructions..."

**REVOC defense:** `sec_prompt_injection_v1` and `sec_sysextract_v1` detect known
injection phrases and block the request.

**Limit:** Novel injection techniques that do not use known phrases may evade detection.
The ONNX enricher and HTTP plugin system allow extending detection coverage.

---

### T4 — Unicode Evasion

**Scenario:** An attacker uses fullwidth Unicode characters, zero-width characters,
or RTLO overrides to make `ＤＲＯＰTable` appear as `DROPTable` on screen while
evading regex detection.

**REVOC defense:** Four-step NFKC normalization runs on every field before any
regex pattern. Evasion attempts are flagged with `was_normalized: true`.

**Limit:** Normalization is applied to text content fields. Binary formats and
custom encoding schemes require explicit plugin support.

---

### T5 — Encoding-Based Evasion

**Scenario:** Attack content is base64-encoded or URL-encoded before being embedded
in a prompt, expecting the model to decode it while the regex scanner misses it.

**REVOC defense:** `encoding::prepare_scan_targets()` decodes base64 and URL-encoded
tokens and runs the full detection pipeline on decoded content. `was_encoded: true`
is set on findings from decoded content. `sec_encoded_evasion_v1` explicitly blocks
security-tier patterns found only in encoded form.

---

### T6 — MCP Tool Abuse

**Scenario:** An AI agent calls an MCP tool with a SQL query containing `DROP TABLE`,
or calls an HTTP tool with an internal IP address to probe the internal network.

**REVOC defense:** MCP tool arguments are inspected by the full detection pipeline
before the MCP server receives the call. Blocked calls never reach the MCP server.

---

### T7 — Tool Manifest Poisoning

**Scenario:** A compromised or malicious MCP server returns a `tools/list` manifest
containing prompt injection in tool descriptions, or tools with parameter names
like `admin_password` designed to extract credentials from the model.

**REVOC defense:** Manifest analysis runs on every `tools/list` response before
it reaches the AI client. Dangerous parameter names and suspicious descriptions
are flagged. With `auto_disable_dangerous_tools = true`, dangerous tools are
removed from the manifest entirely.

---

### T8 — Session-Level Data Exfiltration

**Scenario:** An AI agent reads hundreds of database rows containing customer PII
over multiple tool calls, then attempts to send the data to an external HTTP endpoint.
No single request looks suspicious.

**REVOC defense:** Session tracking aggregates `total_rows_read`, `pii_entities_seen`,
and `external_send_attempted` across requests. When all three thresholds are met,
`session_data_exfil_v1` blocks the next request.

---

### T9 — Infinite Agent Recursion

**Scenario:** An orchestration framework has an agent that calls another agent
that calls another agent... The loop burns API budget and exhausts rate limits.

**REVOC defense:** `X-Revoc-Depth` tracks nesting depth. When depth reaches 10,
the request is blocked immediately with `REVOC_GOVERNANCE_DEPTH_EXCEEDED`.

---

## Out-of-Scope Threats

REVOC is an application-layer governance proxy. It does not defend against:

- Network-layer attacks (DDoS, TCP SYN floods) — use a WAF or CDN
- Compromise of the REVOC proxy process itself — use standard OS hardening
- Side-channel attacks on the inference provider
- Prompt attacks that don't match known injection signatures
- Data exfiltration via the upstream LLM's response (partial — bidirectional governance
  catches PII in responses but cannot detect all semantic exfiltration)
