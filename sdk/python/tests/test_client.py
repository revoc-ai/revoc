"""tests/test_client.py — RevocOpenAI / RevocAsyncOpenAI behavior."""

from __future__ import annotations

import httpx
import pytest
from openai import AsyncOpenAI, OpenAI

from revoc_sdk import (
    RevocAsyncOpenAI,
    RevocDepthExceededError,
    RevocGovernanceError,
    RevocKillSwitchError,
    RevocOpenAI,
    patch,
)
from revoc_sdk.client import _async_response_hook, _response_hook

_REVOC_URL = "http://revoc.local:8080"


def test_base_url_set_from_arg() -> None:
    client = RevocOpenAI(api_key="sk-test", revoc_base_url=_REVOC_URL)
    assert str(client.base_url).rstrip("/") == _REVOC_URL


def test_base_url_from_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVOC_BASE_URL", _REVOC_URL)
    client = RevocOpenAI(api_key="sk-test")
    assert str(client.base_url).rstrip("/") == _REVOC_URL


def test_is_instance_of_openai() -> None:
    client = RevocOpenAI(api_key="sk-test", revoc_base_url=_REVOC_URL)
    assert isinstance(client, OpenAI)


def test_async_client_is_instance_of_async_openai() -> None:
    client = RevocAsyncOpenAI(api_key="sk-test", revoc_base_url=_REVOC_URL)
    assert isinstance(client, AsyncOpenAI)


def _build_response(status_code: int, payload: dict[str, object]) -> httpx.Response:
    request = httpx.Request("POST", "http://revoc.local:8080/v1/chat/completions")
    return httpx.Response(status_code, json=payload, request=request)


def test_governance_block_raises_error() -> None:
    payload = {
        "error": {
            "code": "REVOC_GOVERNANCE_BLOCK",
            "message": "Prompt injection detected",
            "blocked_by": "sec_prompt_injection_v1",
            "rules": ["sec_prompt_injection_v1"],
            "trace_id": "01911f6e-0000-7000-8000-000000000000",
            "dashboard_url": "http://localhost:3000/traces/01911f6e",
            "documentation_url": "https://revoc.io/docs/policies/sec_prompt_injection_v1",
        }
    }
    response = _build_response(403, payload)
    with pytest.raises(RevocGovernanceError) as exc_info:
        _response_hook(response)
    err = exc_info.value
    assert err.blocked_by == "sec_prompt_injection_v1"
    assert err.rules == ["sec_prompt_injection_v1"]
    assert err.trace_id == "01911f6e-0000-7000-8000-000000000000"


def test_kill_switch_raises_kill_switch_error() -> None:
    payload = {
        "error": {
            "code": "REVOC_KILL_SWITCH_ACTIVE",
            "message": "All AI traffic suspended by emergency stop.",
            "trace_id": "trace-123",
            "dashboard_url": "http://localhost:3000/emergency",
        }
    }
    response = _build_response(503, payload)
    with pytest.raises(RevocKillSwitchError):
        _response_hook(response)


def test_depth_raises_depth_error() -> None:
    payload = {
        "error": {
            "code": "REVOC_GOVERNANCE_DEPTH_EXCEEDED",
            "message": "Governance depth limit (10/10) reached. Possible infinite agent loop.",
            "trace_id": "trace-456",
            "dashboard_url": "http://localhost:3000/traces/trace-456",
        }
    }
    response = _build_response(503, payload)
    with pytest.raises(RevocDepthExceededError) as exc_info:
        _response_hook(response)
    assert exc_info.value.depth == 10
    assert exc_info.value.max_depth == 10


def test_error_str_contains_dashboard_url() -> None:
    err = RevocGovernanceError(
        reason="Blocked: secret detected",
        decision="block",
        blocked_by="secret_block_v1",
        rules=["secret_block_v1"],
        trace_id="trace-789",
        dashboard_url="http://localhost:3000/traces/trace-789",
    )
    text = str(err)
    assert "http://localhost:3000/traces/trace-789" in text
    assert "secret_block_v1" in text


def test_patch_injects_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVOC_BASE_URL", _REVOC_URL)
    patch()
    client = OpenAI(api_key="sk-test")
    assert str(client.base_url).rstrip("/") == _REVOC_URL


@pytest.mark.asyncio
async def test_async_response_hook_raises_governance_error() -> None:
    payload = {
        "error": {
            "code": "REVOC_GOVERNANCE_BLOCK",
            "message": "Blocked",
            "blocked_by": "secret_block_v1",
            "rules": ["secret_block_v1"],
            "trace_id": "trace-async",
            "dashboard_url": "http://localhost:3000/traces/trace-async",
        }
    }
    response = _build_response(403, payload)
    with pytest.raises(RevocGovernanceError):
        await _async_response_hook(response)


def test_non_revoc_error_passes_through() -> None:
    """Upstream provider errors (forwarded verbatim) must not raise REVOC exceptions."""
    payload = {"error": {"message": "invalid_api_key", "type": "invalid_request_error"}}
    response = _build_response(401, payload)
    _response_hook(response)  # should not raise
