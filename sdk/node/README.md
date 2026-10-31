# @revoc-io/sdk

Zero-code-change governance SDK for [REVOC](https://revoc.io) — a drop-in
subclass of the official `openai` Node.js client that routes traffic through
the REVOC proxy and translates governance decisions into typed errors.

## Install

```bash
npm install @revoc-io/sdk
```

## Usage

```typescript
import { RevocOpenAI, RevocGovernanceError } from "@revoc-io/sdk";

const client = new RevocOpenAI({ apiKey: "sk-...", revocBaseUrl: "http://revoc:8080" });

try {
  const resp = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hello" }],
  });
} catch (err) {
  if (err instanceof RevocGovernanceError) {
    console.log(`Blocked by ${err.blockedBy}: ${err.message}`);
    console.log(`See ${err.dashboardUrl}`);
  } else {
    throw err;
  }
}
```

## Zero-code-change activation

```bash
export REVOC_BASE_URL=http://revoc:8080
```

`RevocOpenAI` automatically reads `REVOC_BASE_URL` when `revocBaseUrl` is not
passed explicitly — no source changes required.

## Governance API

```typescript
const stats = await client.governance.getAuditStats(
  new Date(Date.now() - 24 * 60 * 60 * 1000),
  new Date()
);
console.log(stats);
```

## Errors

| Class | Thrown when |
|---|---|
| `RevocGovernanceError` | A policy rule blocked the request |
| `RevocKillSwitchError` | The emergency kill-switch is active |
| `RevocDepthExceededError` | Governance depth reached the maximum (10) |
| `RevocRateLimitError` | The caller exceeded their rate limit |
| `RevocMcpError` | An MCP `tools/call` was blocked before reaching the server |

## License

Apache 2.0
