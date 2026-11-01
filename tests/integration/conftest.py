"""Shared fixtures for REVOC integration tests.

These tests drive the real stack defined in `docker/docker-compose.test.yml`:
  - revoc-proxy        on :8080 (proxy), :3000 (dashboard), :9090 (metrics), :8081 (internal)
  - revoc-proxy-shadow on :8082  — global enforcement_mode=shadow
  - revoc-proxy-jwt    on :8083  — auth.mode=jwt (HS256, secret=test-jwt-secret-for-integration-tests)
  - revoc-proxy-opa    on :8084  — policy.engine=sidecar delegating to OPA on :8191
  - mock-llm (WireMock) on :8089
  - mock-mcp (WireMock) on :8090
  - opa                on :8191

Ground truth notes (verified against source, see crates/revoc-proxy/src/middleware/auth.rs):
  - REVOC_AUTH__MODE=none -> every request gets CallerContext { org_id: "dev",
    caller_id: "dev", environment: <server.environment>, enforcement_mode: Enforce, ... }.
  - revoc-proxy-shadow uses REVOC_POLICY__ENFORCEMENT_MODE=shadow so every apikey-/none-
    derived CallerContext gets EnforcementMode::Shadow (line 91-95 of auth.rs).
  - revoc-proxy-jwt uses REVOC_AUTH__MODE=jwt + REVOC_JWT_SECRET. Claims: sub=caller_id,
    org=org_id. make_jwt_token() in this module creates signed test tokens.
  - revoc-proxy-opa uses REVOC_POLICY__ENGINE=sidecar, forwarding PolicyInput JSON to
    OPA at POST /v1/data/revoc/governance/main/decision.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import pathlib
import subprocess
import time as _time

import httpx
import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker" / "docker-compose.test.yml"

PROXY_BASE = "http://localhost:8080"
DASHBOARD_BASE = "http://localhost:3000"
INTERNAL_BASE = "http://localhost:8081"
WIREMOCK_LLM_BASE = "http://localhost:8089"
WIREMOCK_MCP_BASE = "http://localhost:8090"

# Additional proxy instances for post-launch feature tests
SHADOW_PROXY_BASE = "http://localhost:8082"
JWT_PROXY_BASE = "http://localhost:8083"
OPA_PROXY_BASE = "http://localhost:8084"
OPA_BASE = "http://localhost:8191"

# JWT secret must match REVOC_JWT_SECRET in the revoc-proxy-jwt compose service
JWT_SECRET = "test-jwt-secret-for-integration-tests"

ADMIN_KEY = "dev-admin-key-local-only"


def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _wait_for(url: str, timeout: float = 90.0) -> None:
    deadline = _time.monotonic() + timeout
    last_err = None
    while _time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code < 500:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
        _time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for {url}: {last_err}")


def make_jwt_token(
    sub: str = "test-user",
    org: str = "test-org",
    secret: str = JWT_SECRET,
    expires_in: int = 3600,
) -> str:
    """Create a minimal HS256 JWT signed with `secret`.

    The REVOC JWT middleware (auth.rs::authenticate_jwt) uses jsonwebtoken's
    default Validation which requires `exp` claim. We produce:
      header: {"alg":"HS256","typ":"JWT"}
      payload: {"sub": sub, "org": org, "exp": now+expires_in}

    Signed with HMAC-SHA256 using `secret` as the key. No external library
    needed — we implement the minimal RFC 7519 encoding directly.
    """
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(_time.time())
    claims = {"sub": sub, "org": org, "exp": now + expires_in}
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


@pytest.fixture(scope="session", autouse=True)
def docker_stack():
    """Bring up the full test stack once for the whole session."""
    # Remove any stale standalone e2e container that may hold the same ports.
    subprocess.run(
        ["docker", "rm", "-f", "revoc-e2e"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    # Tear down any previous compose state so port bindings are released.
    _compose("down", "-v", "--remove-orphans")

    up = _compose("up", "-d", "--build")
    if up.returncode != 0:
        raise RuntimeError(f"docker compose up failed:\nSTDOUT:\n{up.stdout}\nSTDERR:\n{up.stderr}")

    try:
        _wait_for(f"{PROXY_BASE}/health", timeout=180.0)
        _wait_for(f"{WIREMOCK_LLM_BASE}/__admin/health", timeout=60.0)
        _wait_for(f"{WIREMOCK_MCP_BASE}/__admin/health", timeout=60.0)
        _wait_for(f"{SHADOW_PROXY_BASE}/health", timeout=120.0)
        _wait_for(f"{JWT_PROXY_BASE}/health", timeout=120.0)
        _wait_for(f"{OPA_BASE}/health", timeout=60.0)
        _wait_for(f"{OPA_PROXY_BASE}/health", timeout=120.0)
        yield
    finally:
        _compose("down", "-v")


@pytest.fixture
async def proxy_client():
    async with httpx.AsyncClient(base_url=PROXY_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def dashboard_client():
    async with httpx.AsyncClient(base_url=DASHBOARD_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def internal_client():
    async with httpx.AsyncClient(
        base_url=INTERNAL_BASE, timeout=30.0, headers={"X-Admin-Key": ADMIN_KEY}
    ) as client:
        yield client


@pytest.fixture
async def wiremock_llm():
    async with httpx.AsyncClient(base_url=WIREMOCK_LLM_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def wiremock_mcp():
    async with httpx.AsyncClient(base_url=WIREMOCK_MCP_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def shadow_proxy_client():
    """Client for the shadow-mode proxy (port 8082, enforcement_mode=shadow)."""
    async with httpx.AsyncClient(base_url=SHADOW_PROXY_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def jwt_proxy_client():
    """Client for the JWT-auth proxy (port 8083, auth.mode=jwt).

    Requests must include `Authorization: Bearer <token>` with a valid HS256
    JWT signed by JWT_SECRET. Use make_jwt_token() to create test tokens.
    """
    async with httpx.AsyncClient(base_url=JWT_PROXY_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture
async def opa_proxy_client():
    """Client for the OPA-sidecar proxy (port 8084, policy.engine=sidecar)."""
    async with httpx.AsyncClient(base_url=OPA_PROXY_BASE, timeout=30.0) as client:
        yield client


@pytest.fixture(autouse=True)
async def _reset_wiremock_journals():
    """Reset WireMock request journals before each test for reliable call counts."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.delete(f"{WIREMOCK_LLM_BASE}/__admin/requests")
        await client.delete(f"{WIREMOCK_MCP_BASE}/__admin/requests")
    yield


# ── Helpers ──────────────────────────────────────────────────────────────────


def chat_payload(content, model="gpt-4o-mini", stream=False, extra=None):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }
    if extra:
        body.update(extra)
    return body


def mcp_tools_call(tool_name, arguments, call_id="1", server_id=None):
    params = {"name": tool_name, "arguments": arguments}
    if server_id:
        params["server_id"] = server_id
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": params,
    }


def mcp_tools_list(call_id="1"):
    return {"jsonrpc": "2.0", "id": call_id, "method": "tools/list", "params": {}}


async def wiremock_count(client: httpx.AsyncClient, url_path: str) -> int:
    resp = await client.post("/__admin/requests/count", json={"method": "POST", "urlPath": url_path})
    resp.raise_for_status()
    return resp.json()["count"]


async def wiremock_last_request(client: httpx.AsyncClient, url_path: str):
    resp = await client.post("/__admin/requests/find", json={"method": "POST", "urlPath": url_path})
    resp.raise_for_status()
    reqs = resp.json().get("requests", [])
    return reqs[-1] if reqs else None
