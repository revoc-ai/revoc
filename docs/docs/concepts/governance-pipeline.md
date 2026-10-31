# Governance Pipeline

Every request and response passes through the same five-stage detection pipeline
before reaching the policy engine. The pipeline is deterministic and synchronous
within an async task — stages run in fixed order.

## The Five Detection Stages

```
Raw text field
  ↓ [1] normalization::normalize()
        NFKC + zero-width removal + RTLO/BIDI removal + control char removal
        Sets: was_modified flag

  ↓ [2] encoding::prepare_scan_targets()
        Attempt base64 decode of each token
        Attempt URL-decode of each token
        Sets: was_encoded flag on findings from decoded content

  ↓ [3] regex_detector::detect()
        PII patterns (11 entities)
        Secret patterns (10 types)
        Security patterns (8 threats)
        Financial patterns (4 entities)
        Runs on: normalized text + decoded variants

  ↓ [4] onnx_detector::detect()          [optional, onnx_enabled=true]
        BERT NER: PER / ORG / LOC / MISC
        Span-level named entity recognition

  ↓ [5] http_plugin::detect()            [optional, if plugins configured]
        Community plugin HTTP callbacks

  ↓ deduplication::deduplicate()
        Merge overlapping spans, keep higher confidence
        Remove duplicate entity type + position pairs

Vec<Finding>
```

## Stage 1 — Normalization

Applied to every text field before any pattern matching. See
[Unicode Normalization](normalization.md) for the full specification.

The `was_normalized` flag on each finding indicates whether the normalized form
differed from the raw input — evidence of a Unicode evasion attempt.

## Stage 2 — Encoding Detection

After normalization, each token is tested for common encoding layers:

**Base64 decoding:** Each whitespace-delimited token ≥ 20 characters is tested
as base64. If decoding succeeds and the result is valid UTF-8 or matches known
binary patterns (PEM headers, etc.), the decoded content is also scanned.

**URL decoding:** `%XX` sequences are decoded and the result is scanned separately.

Findings from decoded content carry `was_encoded: true`. The security rule
`sec_encoded_evasion_v1` fires when a security-tier pattern is found only in
decoded content — explicit evidence of encoding-based evasion.

## Stage 3 — Regex Detection

The main detection stage. Patterns are pre-compiled at startup and applied
using `regex` (linear-time) and `fancy-regex` (for lookbehind patterns).

All patterns run on:
1. The normalized text
2. The base64-decoded variant (if any)
3. The URL-decoded variant (if any)

Findings from variants set `was_encoded: true`.

## Stage 4 — ONNX NER (optional)

Disabled by default. When enabled, the BERT NER model runs on the normalized
text using `ort` (ONNX Runtime). Adds person name and location detection.

Throughput drops from > 100K req/s to ~8K req/s (GPU) with ONNX enabled.
Enable only when your workload requires name/location detection beyond regex coverage.

## Stage 5 — HTTP Plugin (optional)

External detection plugins are called via HTTP POST with the normalized text.
Plugins return findings in the REVOC finding JSON format. Response timeout: 2s.
A plugin timeout results in an empty finding list — the pipeline continues.

## Deduplication

After all stages, overlapping findings are merged:

- Two findings for the same span (same `start`, `end`, `field`) → keep the one
  with higher `confidence`
- Two findings of different types overlapping at the same position → keep both
  (e.g., an EMAIL_ADDRESS inside a URL that also matches GENERIC_API_KEY)

## Policy Input Construction

After deduplication, the `Vec<Finding>` is assembled into a `PolicyInput`:

```rust
PolicyInput {
    request_id,
    request_type,    // LlmRequest | LlmResponse | McpToolCall | McpToolResult | ...
    caller,          // CallerContext from auth middleware
    findings,        // deduped Vec<Finding>
    model,           // from request body
    provider,        // from upstream router
    messages,        // parsed chat messages
    tool_call,       // if MCP tools/call
    token_usage,     // from response (output governance)
    session_state,   // from Redis/memory
    governance_depth,
    timestamp,
}
```

This is passed to `PolicyEngine::evaluate()`, which returns a `PolicyDecision`.

## Timing

The pipeline has an 8-second timeout on the detection stage. If the detection
engine (including any ONNX or HTTP plugin calls) exceeds 8 seconds, the request
is handled according to `fail_open`:

- `fail_open = false` (default): request is blocked
- `fail_open = true`: not supported in production — setting is ignored and treated as false

All timing is reported in `X-Revoc-Timing: detection=Xms,policy=Xms,...`.
