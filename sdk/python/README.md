# revoc-sdk

Zero-code-change governance SDK for [REVOC](https://revoc.io) — drop-in
subclasses of the official `openai` Python client that route traffic through
the REVOC proxy and translate governance decisions into typed exceptions.

## Install

```bash
pip install revoc-sdk
```

## Usage

```python
from revoc_sdk import RevocOpenAI, RevocGovernanceError

client = RevocOpenAI(api_key="sk-...", revoc_base_url="http://revoc:8080")

try:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello"}],
    )
except RevocGovernanceError as exc:
    print(f"Blocked by {exc.blocked_by}: {exc.reason}")
    print(f"See {exc.dashboard_url}")
```

## Zero-code-change activation

```bash
export REVOC_BASE_URL=http://revoc:8080
```

```python
import revoc_sdk
revoc_sdk.patch()  # patches openai.OpenAI / openai.AsyncOpenAI

from openai import OpenAI
client = OpenAI(api_key="sk-...")  # transparently routed through REVOC
```

## Governance API

```python
import asyncio
from datetime import datetime, timedelta, timezone

async def main():
    stats = await client.governance.get_audit_stats(
        start_time=datetime.now(timezone.utc) - timedelta(days=1),
        end_time=datetime.now(timezone.utc),
    )
    print(stats)

asyncio.run(main())
```

## Exceptions

| Exception | Raised when |
|---|---|
| `RevocGovernanceError` | A policy rule blocked the request |
| `RevocKillSwitchError` | The emergency kill-switch is active |
| `RevocDepthExceededError` | Governance depth reached the maximum (10) |
| `RevocRateLimitError` | The caller exceeded their rate limit |
| `RevocMcpError` | An MCP `tools/call` was blocked before reaching the server |

## License

Apache 2.0
