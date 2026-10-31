# Quickstart

This guide walks you from zero to a fully governed AI application in under five minutes.
Every command is exact and runnable.

## Prerequisites

- Docker 24+ installed and running
- An OpenAI API key (or use mock mode without one)
- Python 3.12+ (for Steps 2–7)

---

## Step 1 — Start REVOC

```bash
docker run -d \
  -p 8080:8080 \
  -p 3000:3000 \
  -p 8081:8081 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc \
  ghcr.io/revoc-ai/revoc:latest
```

Wait for the proxy to be ready:

```bash
curl -s http://localhost:8080/health
```

Expected output:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_secs": 3,
  "policy_engine": "native",
  "kill_switch_active": false
}
```

!!! note "No OpenAI key? Use mock mode."
    ```bash
    docker run -d \
      -p 8080:8080 -p 3000:3000 -p 8081:8081 \
      -e REVOC_UPSTREAM__MOCK_MODE=true \
      -e REVOC_AUTH__MODE=none \
      --name revoc \
      ghcr.io/revoc-ai/revoc:latest
    ```
    Mock mode returns `"Mock response. Governance pipeline ran."` for every request.
    The full detection and policy pipeline still runs — ideal for development.

---

## Step 2 — Govern Your First API Call

```python
from openai import OpenAI

# The only change: add base_url
client = OpenAI(
    api_key="sk-your-key-here",
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What is 2 + 2?"}],
)
print(response.choices[0].message.content)
# Output: 4
# Response headers include: X-Revoc-Decision: allow, X-Revoc-Dashboard: http://localhost:3000/traces/<id>
```

---

## Step 3 — Trigger PII Detection

```bash
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "My SSN is 123-45-6789. Help me with my account."
      }
    ]
  }' | python3 -m json.tool
```

Expected response (PII redacted, request still fulfilled):

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "I can help with your account. For security, please avoid sharing sensitive information in chat."
      }
    }
  ]
}
```

Response headers set by REVOC:

```
X-Revoc-Decision: redact
X-Revoc-Rules: pii_ssn_v1
X-Revoc-Dashboard: http://localhost:3000/traces/01932abc-...
X-Revoc-Timing: detection=2ms,policy=0ms,redaction=1ms,upstream=312ms,total=315ms
```

---

## Step 4 — Open the Dashboard

Navigate to [http://localhost:3000](http://localhost:3000) in your browser.

The live feed shows every request in real time with:

- Decision badge (allow / redact / block / audit)
- Violated rules
- Detection timing breakdown
- Caller context
- Link to full trace detail

---

## Step 5 — View a Trace

Click any row in the live feed, or navigate directly using the `X-Revoc-Dashboard` header value:

```
http://localhost:3000/traces/01932abc-1234-7abc-...
```

The trace detail page shows:

- Raw request (with PII fields shown as entity type + position, never value)
- All findings with confidence scores
- Policy decision and applicable rules
- Redacted output diff
- Full timing breakdown
- Audit event JSON

---

## Step 6 — Add a HIPAA Compliance Profile

Create `hipaa-policy.yaml`:

```yaml
name: hipaa-baseline
version: "1.0"
environment: production
profile: hipaa

rules:
  - rule_id: pii_mrn_v1
    action: remove
    enforcement_mode: enforce

  - rule_id: pii_dob_v1
    action: remove
    enforcement_mode: enforce

  - rule_id: pii_ssn_v1
    action: remove
    enforcement_mode: enforce

  - rule_id: pii_phone_v1
    action: remove
    enforcement_mode: enforce

  - rule_id: token_quota_v1
    action: block
    parameters:
      max_tokens_per_hour: 500000
      enforcement_mode: enforce
```

Apply it via the admin API:

```bash
curl -s -X POST http://localhost:8081/internal/policies \
  -H "Content-Type: application/yaml" \
  -H "X-Admin-Key: dev-admin-key" \
  --data-binary @hipaa-policy.yaml | python3 -m json.tool
```

Expected response:

```json
{
  "status": "activated",
  "policy_id": "01932abc-...",
  "rules_loaded": 5,
  "effective_at": "2026-01-15T10:30:00Z"
}
```

---

## Step 7 — Test MCP Governance

REVOC governs MCP tool calls bidirectionally. Test with a simulated tools/call:

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-1",
    "method": "tools/call",
    "params": {
      "name": "execute_sql",
      "arguments": {
        "query": "DROP TABLE users"
      }
    }
  }' | python3 -m json.tool
```

Expected response (HTTP 200 with JSON-RPC error, upstream never receives the request):

```json
{
  "jsonrpc": "2.0",
  "id": "test-1",
  "error": {
    "code": -32603,
    "message": "Request blocked by governance policy.",
    "data": {
      "code": "REVOC_GOVERNANCE_BLOCK",
      "rules": ["sec_ddl_mutation_v1"],
      "trace_id": "01932abc-...",
      "dashboard_url": "http://localhost:3000/traces/01932abc-..."
    }
  }
}
```

The DDL mutation was caught before reaching your database tool.

---

## Next Steps

- [Default Rules](../default-rules/overview.md) — all 30 active rules explained
- [Shadow Mode](../shadow-mode/overview.md) — observe without blocking for 30 days
- [Emergency Kill-Switch](../operations/emergency-kill-switch.md) — stop all traffic in 50ms
- [Framework Integrations](../framework-integrations/langchain.md) — LangChain, LlamaIndex, AutoGen, CrewAI
