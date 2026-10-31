# Python SDK

The `revoc-sdk` Python package provides governed OpenAI client wrappers, MCP client
helpers, and utilities for reading governance decisions from responses.

## Installation

```bash
pip install revoc-sdk
```

## Governed OpenAI Client

```python
from revoc_sdk import RevocOpenAI

# Drop-in replacement for openai.OpenAI
client = RevocOpenAI(
    api_key="sk-your-key",
    revoc_base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
print(response.choices[0].message.content)
```

Governance error responses are raised as typed exceptions:

```python
from revoc_sdk import RevocOpenAI, RevocGovernanceError, RevocKillSwitchError

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "My SSN is 123-45-6789"}],
    )
except RevocGovernanceError as e:
    print(e.decision)      # "block"
    print(e.rules)         # ["pii_ssn_v1"]
    print(e.dashboard_url) # http://localhost:3000/traces/...
```

## Async Client

```python
from revoc_sdk import RevocAsyncOpenAI

client = RevocAsyncOpenAI(
    api_key="sk-your-key",
    revoc_base_url="http://localhost:8080",
)

response = await client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

## Without the SDK

The SDK is optional. Any OpenAI-compatible client works by setting `base_url`:

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-your-key",
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
# All 30 governance rules apply. Headers are in response.headers.
decision = response.headers.get("x-revoc-decision")
dashboard = response.headers.get("x-revoc-dashboard")
```

## Governed MCP Tool Calls

```python
from revoc_sdk import RevocMcpClient, RevocMcpError

mcp = RevocMcpClient(
    revoc_url="http://localhost:8080",
    server_id="database-mcp",
    caller_id="my-agent",
)

# tools/list — manifest analysis runs automatically
tools = await mcp.tools_list()
print(mcp.last_manifest_warnings)  # 0 if no dangerous tools detected

# tools/call — governance runs before and after
try:
    result = await mcp.tools_call(
        name="execute_sql",
        arguments={"query": "SELECT count(*) FROM users"},
    )
except RevocMcpError as e:
    print(e.rules)         # ["sec_ddl_mutation_v1"]
    print(e.dashboard_url) # http://localhost:3000/traces/...
```

## Available Exceptions

| Exception | Raised when |
|---|---|
| `RevocGovernanceError` | Request blocked by a governance rule |
| `RevocKillSwitchError` | Emergency kill-switch is active |
| `RevocDepthExceededError` | Governance depth limit (10) exceeded |
| `RevocRateLimitError` | Rate limit exceeded for this caller |
| `RevocMcpError` | MCP tool call blocked by governance |

## Environment Variable Configuration

```bash
export REVOC_BASE_URL=http://localhost:8080
export REVOC_CALLER_ID=my-service
export REVOC_ORG_ID=org-acme
```

```python
from revoc_sdk import RevocOpenAI

# Reads REVOC_BASE_URL from environment automatically
client = RevocOpenAI(api_key="sk-your-key")
```

## Patch Mode (Zero Code Changes)

```python
from revoc_sdk import patch, unpatch
from openai import OpenAI

# Monkey-patches openai.OpenAI so all existing code is governed
patch(revoc_base_url="http://localhost:8080")

client = OpenAI(api_key="sk-your-key")  # now routed through REVOC

unpatch()  # restore original behaviour
```

## Source

Python SDK source: `sdk/python/revoc_sdk/`
