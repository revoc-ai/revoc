"""JWT authentication tests — SPEC.md §13 auth.mode=jwt.

The `revoc-proxy-jwt` service uses REVOC_AUTH__MODE=jwt and
REVOC_JWT_SECRET=test-jwt-secret-for-integration-tests.

authenticate_jwt() in auth.rs:
  - Extracts the Bearer token from the Authorization header.
  - Decodes it with jsonwebtoken using HS256 + the configured secret.
  - Validation::default() enforces: signature, exp claim not expired, nbf if present.
  - On success: CallerContext { caller_id=sub, org_id=org (or "unknown"), ... }.
  - On failure: returns None → middleware returns 401.

make_jwt_token() in conftest.py produces RFC 7519 HS256 tokens without any
external dependency.
"""

import pytest

from .conftest import JWT_SECRET, chat_payload, make_jwt_token

pytestmark = pytest.mark.asyncio


async def test_valid_jwt_allows_request(jwt_proxy_client, wiremock_llm):
    """A request with a valid, non-expired JWT must be authenticated and
    forwarded to upstream (200 response from the mock LLM).
    """
    token = make_jwt_token(sub="alice", org="acme")
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Hello from JWT-authenticated caller"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, (
        f"Expected 200 for valid JWT, got {resp.status_code}: {resp.text[:200]}"
    )


async def test_missing_token_returns_401(jwt_proxy_client, wiremock_llm):
    """A request with no Authorization header must be rejected with 401.
    The upstream must not receive any requests.
    """
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("No token here"),
    )
    assert resp.status_code == 401, (
        f"Expected 401 for missing token, got {resp.status_code}: {resp.text[:200]}"
    )
    count_resp = await wiremock_llm.post(
        "/__admin/requests/count",
        json={"method": "POST", "urlPath": "/v1/chat/completions"},
    )
    assert count_resp.json()["count"] == 0, "Upstream must not be reached with missing token"


async def test_wrong_secret_returns_401(jwt_proxy_client, wiremock_llm):
    """A JWT signed with the wrong secret must be rejected with 401.
    jsonwebtoken's signature verification will fail and authenticate_jwt returns None.
    """
    token = make_jwt_token(sub="attacker", org="evil", secret="wrong-secret-totally-different")
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Tampered token"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401, (
        f"Expected 401 for wrong-secret JWT, got {resp.status_code}: {resp.text[:200]}"
    )
    count_resp = await wiremock_llm.post(
        "/__admin/requests/count",
        json={"method": "POST", "urlPath": "/v1/chat/completions"},
    )
    assert count_resp.json()["count"] == 0


async def test_expired_token_returns_401(jwt_proxy_client, wiremock_llm):
    """A JWT whose exp claim is in the past must be rejected with 401.
    jsonwebtoken has a default leeway of 60 seconds, so we use -3600 (1 hour
    expired) to ensure the token is well beyond any leeway tolerance.
    """
    token = make_jwt_token(sub="bob", org="acme", expires_in=-3600)
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Expired token"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401, (
        f"Expected 401 for expired JWT, got {resp.status_code}: {resp.text[:200]}"
    )
    count_resp = await wiremock_llm.post(
        "/__admin/requests/count",
        json={"method": "POST", "urlPath": "/v1/chat/completions"},
    )
    assert count_resp.json()["count"] == 0


async def test_jwt_caller_id_in_trace_headers(jwt_proxy_client):
    """A valid JWT's `sub` claim becomes the caller_id recorded in audit
    events and reflected in response headers. X-Revoc-Trace-ID must be
    present on every authenticated response.
    """
    token = make_jwt_token(sub="carol", org="acme")
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Authenticated hello"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert "X-Revoc-Trace-ID" in resp.headers, "Trace ID must be present on JWT-authenticated responses"
    assert "X-Revoc-Dashboard" in resp.headers, "Dashboard URL must be present (SPEC.md Principle 11)"
    assert "X-Revoc-Timing" in resp.headers, "Timing header must be present (SPEC.md Principle 12)"


async def test_malformed_bearer_token_returns_401(jwt_proxy_client):
    """A Bearer value that is not a parseable JWT (not three base64url segments
    separated by dots) must be rejected with 401 — not 500.
    """
    resp = await jwt_proxy_client.post(
        "/v1/chat/completions",
        json=chat_payload("Malformed token"),
        headers={"Authorization": "Bearer this.is.not.a.valid.jwt.at.all"},
    )
    assert resp.status_code == 401, (
        f"Expected 401 for malformed Bearer token, got {resp.status_code}: {resp.text[:200]}"
    )
