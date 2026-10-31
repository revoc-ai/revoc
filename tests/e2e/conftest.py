"""Shared fixtures for REVOC end-to-end tests.

E2E tests run against the single-container stack launched by the Makefile
target `make up` (docker/docker-compose.yml).  Unlike the integration test
stack (docker-compose.test.yml), this stack uses the real application
configuration with mock_mode=true so no real LLM API calls are made.

The stack must be running before this suite is invoked:

    docker run -d --name revoc-e2e \\
        -p 8080:8080 -p 3000:3000 -p 8081:8081 \\
        -e REVOC_AUTH__MODE=none \\
        -e REVOC_UPSTREAM__MOCK_MODE=true \\
        -e REVOC_DASHBOARD__AUTH_MODE=none \\
        -e REVOC_POLICY__DECISION_CACHE_TTL_SECS=0 \\
        ghcr.io/revoc-ai/revoc:latest

    pytest tests/e2e/ -v

The REVOC_E2E_BASE env var overrides the default http://localhost:8080 base URL,
allowing tests to run against a remote stack (CI, staging, etc.).
"""

import os
import time

import httpx
import pytest

PROXY_BASE = os.getenv("REVOC_E2E_BASE", "http://localhost:8080")
DASHBOARD_BASE = os.getenv("REVOC_E2E_DASHBOARD_BASE", "http://localhost:3000")
INTERNAL_BASE = os.getenv("REVOC_E2E_INTERNAL_BASE", "http://localhost:8081")
ADMIN_KEY = os.getenv("REVOC_E2E_ADMIN_KEY", "dev-admin-key")


def _wait_for(url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code < 500:
                return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        time.sleep(1.0)
    raise RuntimeError(f"Stack not ready at {url} after {timeout}s: {last_err}")


@pytest.fixture(scope="session", autouse=True)
def require_stack():
    """Verify the stack is reachable; fail fast with a clear message if not."""
    try:
        _wait_for(f"{PROXY_BASE}/health", timeout=30.0)
    except RuntimeError as exc:
        pytest.skip(f"E2E stack not reachable — {exc}. Start it before running tests/e2e/.")


@pytest.fixture
async def proxy():
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def dashboard():
    async with httpx.AsyncClient(base_url=DASHBOARD_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def internal():
    async with httpx.AsyncClient(base_url=INTERNAL_BASE, timeout=30.0) as client:
        yield client


def chat(content: str, model: str = "gpt-4o-mini", stream: bool = False) -> dict:
    return {
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }


def mcp_call(tool: str, args: dict, call_id: str = "1") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
