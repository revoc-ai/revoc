# Troubleshooting

Solutions for the most common issues when getting started with REVOC.

---

## 401 Unauthorized on every request

**Symptom:** All requests return `{"error": {"code": "REVOC_AUTH_FAILED", ...}}` with HTTP 401.

**Cause:** Default auth mode is `apikey`. No keys are configured so all requests are rejected.

**Fix (development):** Disable auth:
```bash
docker run ... -e REVOC_AUTH__MODE=none ghcr.io/revoc-ai/revoc:beta
```

**Fix (production):** Set API keys:
```bash
# Generate a key first
revoc-proxy generate-key --label myapp
# Then pass the printed Key value:
docker run ... -e REVOC_API_KEYS=revoc_k_yourkeyhere ghcr.io/revoc-ai/revoc:beta
```

Your callers add `Authorization: Bearer revoc_k_yourkeyhere` to every request.

---

## Port already in use

**Symptom:** `docker: Error response: port is already allocated.`

**Fix:** Stop any existing container or change the host port:
```bash
docker rm -f revoc
# or use a different port:
docker run ... -p 18080:8080 ...
```

---

## Proxy returns 400 Request Parse Error on valid JSON

**Symptom:** `REVOC_REQUEST_PARSE_ERROR` on a request that looks correct.

**Cause 1:** BOM (byte-order mark) prepended to the body. Happens when JSON is written
with Windows tools that add UTF-16 BOM. Use UTF-8 without BOM.

**Cause 2:** Content-Type header missing. Always send `Content-Type: application/json`.

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

---

## Dashboard shows no traces

**Symptom:** Dashboard at `:3000` loads but the live feed is empty.

**Cause 1:** Port 3000 not published. Make sure `-p 3000:3000` is in your `docker run` command.

**Cause 2:** Browser SSE connection dropped. Hard-refresh the page (`Ctrl+Shift+R`).

**Cause 3:** Requests are going directly to OpenAI, not through the proxy. Confirm:
```bash
curl -s http://localhost:8080/health   # should return {"status": "ok", ...}
```

---

## All requests blocked — kill-switch active

**Symptom:** All requests return `REVOC_KILL_SWITCH_ACTIVE` with HTTP 503.

**Fix:** Check and deactivate the kill-switch:
```bash
curl -s http://localhost:8081/internal/emergency/kill-switch/status \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY"

curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/deactivate \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scope": "global"}'
```

---

## 503 Governance Depth Exceeded

**Symptom:** `REVOC_GOVERNANCE_DEPTH_EXCEEDED` with HTTP 503.

**Cause:** An AI agent is calling REVOC recursively more than 10 levels deep. This is
the infinite-loop guard (SPEC.md §3 Principle 6).

**Fix:** Check your agent implementation for circular tool-call chains. Each hop
increments the `X-Revoc-Depth` header. The limit is 10.

---

## Upstream errors (401/429/500 from OpenAI)

**Symptom:** Responses contain OpenAI error messages, not REVOC errors.

**Behavior:** This is correct. REVOC forwards upstream 4xx/5xx verbatim and adds only
`X-Revoc-Trace-ID` to the response. Check your `OPENAI_API_KEY` and quota.

---

## Container starts but `/ready` returns 503

**Symptom:** `/health` returns 200 but `/ready` returns 503 for up to 30 seconds.

**Cause:** Database migrations are running. This is normal on first startup.

**Fix:** Wait 10–30 seconds, then retry. Use `/ready` (not `/health`) as the
liveness probe in Docker Compose or Kubernetes.

---

## `cargo build` fails on Windows with linking errors

The REVOC proxy is built for Linux containers. Build via Docker:

```bash
docker build -t revoc-local -f crates/revoc-proxy/Dockerfile .
```

For native Windows development, use WSL2 with the Rust toolchain installed inside it.

---

## Still stuck?

- Open an issue: [github.com/revoc-ai/revoc/issues](https://github.com/revoc-ai/revoc/issues)
- Check the [proxy logs](../observability/audit-log.md): `docker logs revoc --tail 50`
