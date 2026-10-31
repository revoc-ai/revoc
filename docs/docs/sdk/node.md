# Node.js SDK

The `@revoc-io/sdk` Node.js package provides governed OpenAI client wrappers,
MCP tool call helpers, and TypeScript types for governance decisions.

## Installation

```bash
npm install @revoc-io/sdk
# or
pnpm add @revoc-io/sdk
```

## Governed OpenAI Client

```typescript
import { RevocOpenAI } from "@revoc-io/sdk";

const client = new RevocOpenAI({
  apiKey: "sk-your-key",
  revocBaseUrl: "http://localhost:8080",
});

const response = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Hello" }],
});

console.log(response.choices[0].message.content);
```

Governance error responses are raised as typed exceptions:

```typescript
import { RevocOpenAI, RevocGovernanceError } from "@revoc-io/sdk";

try {
  const response = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "My SSN is 123-45-6789" }],
  });
} catch (e) {
  if (e instanceof RevocGovernanceError) {
    console.log(e.decision);     // "block"
    console.log(e.rules);        // ["pii_ssn_v1"]
    console.log(e.dashboardUrl); // http://localhost:3000/traces/...
  }
}
```

## Without the SDK

Any OpenAI-compatible client works by setting `baseURL`:

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "sk-your-key",
  baseURL: "http://localhost:8080",
});

const response = await client.chat.completions.create({ ... });
// Governance headers are in response.headers
```

## Governed MCP Tool Calls

```typescript
import { governedToolCall, RevocMcpError } from "@revoc-io/sdk";

// Sends a tools/call through REVOC and raises RevocMcpError if blocked
try {
  const result = await governedToolCall({
    revocUrl: "http://localhost:8080",
    serverId: "database-mcp",
    callerId: "my-agent",
    toolName: "execute_sql",
    arguments: { query: "SELECT count(*) FROM users" },
  });
  console.log(result);
} catch (e) {
  if (e instanceof RevocMcpError) {
    console.log(e.rules);       // ["sec_ddl_mutation_v1"]
    console.log(e.dashboardUrl); // http://localhost:3000/traces/...
  }
}
```

## Available Exceptions

| Exception | Raised when |
|---|---|
| `RevocGovernanceError` | Request blocked by a governance rule |
| `RevocKillSwitchError` | Emergency kill-switch is active |
| `RevocDepthExceededError` | Governance depth limit (10) exceeded |
| `RevocRateLimitError` | Rate limit exceeded for this caller |
| `RevocMcpError` | MCP tool call blocked by governance |

## TypeScript Types

```typescript
import type {
  RevocGovernanceError,
  RevocKillSwitchError,
  RevocDepthExceededError,
  RevocRateLimitError,
} from "@revoc-io/sdk";
```

## Environment Variable Configuration

```bash
export REVOC_BASE_URL=http://localhost:8080
```

```typescript
import { RevocOpenAI } from "@revoc-io/sdk";

// Reads REVOC_BASE_URL from process.env automatically
const client = new RevocOpenAI({ apiKey: process.env.OPENAI_API_KEY! });
```

## Source

Node.js SDK source: `sdk/node/src/`
