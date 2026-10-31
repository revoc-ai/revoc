"""revoc_sdk.client — drop-in OpenAI client subclasses routed through REVOC.

Usage (zero-code-change beyond the constructor):

    from revoc_sdk import RevocOpenAI
    client = RevocOpenAI(api_key="sk-...")          # reads REVOC_BASE_URL
    client = RevocOpenAI(api_key="sk-...", revoc_base_url="http://revoc:8080")

Both subclasses transparently translate REVOC governance error responses
(`RevocErrorResponse`, see SPEC.md Section 7.5) into typed Python
exceptions so callers can branch on governance outcomes instead of parsing
raw HTTP error bodies.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from openai import AsyncOpenAI, OpenAI

from revoc_sdk.exceptions import (
    RevocDepthExceededError,
    RevocGovernanceError,
    RevocKillSwitchError,
    RevocRateLimitError,
)
from revoc_sdk.governance import GovernanceClient


def _response_hook(response: httpx.Response) -> None:
    """httpx event hook: parse REVOC error bodies and raise typed exceptions.

    Only fires on 4xx/5xx responses, and only acts when the body matches the
    `RevocErrorResponse` shape (`{"error": {"code": "REVOC_...", ...}}`).
    Upstream provider errors are passed through untouched (Rule 8: forward
    verbatim, never wrap).
    """
    if response.status_code < 400:
        return
    try:
        response.read()
        payload = response.json()
    except Exception:  # noqa: BLE001 — malformed/non-JSON bodies pass through
        return
    if not isinstance(payload, dict):
        return
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    code = error.get("code", "")
    if not isinstance(code, str) or not code.startswith("REVOC_"):
        return
    if code == "REVOC_RATE_LIMIT_EXCEEDED":
        retry_after = 0
        try:
            retry_after = int(response.headers.get("retry-after", "0"))
        except ValueError:
            retry_after = 0
        raise RevocRateLimitError(retry_after_secs=retry_after)
    if code == "REVOC_KILL_SWITCH_ACTIVE":
        raise RevocKillSwitchError(
            scope="global", dashboard_url=error.get("dashboard_url", "")
        )
    if code == "REVOC_GOVERNANCE_DEPTH_EXCEEDED":
        depth = 10
        message = error.get("message", "")
        try:
            fraction = message.split("(", 1)[1].split(")", 1)[0]
            depth = int(fraction.split("/", 1)[0])
        except (IndexError, ValueError):
            pass
        raise RevocDepthExceededError(depth=depth, max_depth=10)
    if code == "REVOC_GOVERNANCE_BLOCK":
        raise RevocGovernanceError(
            reason=error.get("message", ""),
            decision="block",
            blocked_by=error.get("blocked_by"),
            rules=error.get("rules") or [],
            trace_id=error.get("trace_id", ""),
            dashboard_url=error.get("dashboard_url", ""),
            documentation_url=error.get("documentation_url"),
        )


def _resolve_base_url(revoc_base_url: str | None, kwargs: dict[str, Any]) -> str | None:
    """Resolution order: explicit kwarg > REVOC_BASE_URL env > caller-supplied base_url."""
    if revoc_base_url:
        return revoc_base_url
    env_url = os.environ.get("REVOC_BASE_URL")
    if env_url:
        return env_url
    existing = kwargs.pop("base_url", None)
    return existing if isinstance(existing, str) or existing is None else None


class RevocOpenAI(OpenAI):
    """Synchronous OpenAI client transparently governed by REVOC.

    Drop-in replacement for ``openai.OpenAI``. All requests are routed
    through the REVOC proxy (`base_url`), and governance error responses are
    raised as typed exceptions (`RevocGovernanceError`, `RevocKillSwitchError`,
    `RevocDepthExceededError`, `RevocRateLimitError`).
    """

    def __init__(self, *, revoc_base_url: str | None = None, **kwargs: Any) -> None:
        base_url = _resolve_base_url(revoc_base_url, kwargs)
        http_client = kwargs.pop("http_client", None)
        if http_client is None:
            http_client = httpx.Client(event_hooks={"response": [_response_hook]})
        super().__init__(base_url=base_url, http_client=http_client, **kwargs)
        self._revoc_governance: GovernanceClient | None = None

    @property
    def governance(self) -> GovernanceClient:
        """Lazily-constructed client for the REVOC dashboard / admin-api."""
        if self._revoc_governance is None:
            base = str(self.base_url) if self.base_url else ""
            self._revoc_governance = GovernanceClient(base_url=base)
        return self._revoc_governance


class RevocAsyncOpenAI(AsyncOpenAI):
    """Asynchronous OpenAI client transparently governed by REVOC.

    Drop-in replacement for ``openai.AsyncOpenAI`` with the same governance
    exception translation as `RevocOpenAI`.
    """

    def __init__(self, *, revoc_base_url: str | None = None, **kwargs: Any) -> None:
        base_url = _resolve_base_url(revoc_base_url, kwargs)
        http_client = kwargs.pop("http_client", None)
        if http_client is None:
            http_client = httpx.AsyncClient(event_hooks={"response": [_async_response_hook]})
        super().__init__(base_url=base_url, http_client=http_client, **kwargs)
        self._revoc_governance: GovernanceClient | None = None

    @property
    def governance(self) -> GovernanceClient:
        """Lazily-constructed client for the REVOC dashboard / admin-api."""
        if self._revoc_governance is None:
            base = str(self.base_url) if self.base_url else ""
            self._revoc_governance = GovernanceClient(base_url=base)
        return self._revoc_governance


async def _async_response_hook(response: httpx.Response) -> None:
    """Async variant of `_response_hook` for `httpx.AsyncClient` event hooks."""
    if response.status_code < 400:
        return
    try:
        await response.aread()
        payload = response.json()
    except Exception:  # noqa: BLE001
        return
    if not isinstance(payload, dict):
        return
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    code = error.get("code", "")
    if not isinstance(code, str) or not code.startswith("REVOC_"):
        return
    if code == "REVOC_RATE_LIMIT_EXCEEDED":
        retry_after = 0
        try:
            retry_after = int(response.headers.get("retry-after", "0"))
        except ValueError:
            retry_after = 0
        raise RevocRateLimitError(retry_after_secs=retry_after)
    if code == "REVOC_KILL_SWITCH_ACTIVE":
        raise RevocKillSwitchError(
            scope="global", dashboard_url=error.get("dashboard_url", "")
        )
    if code == "REVOC_GOVERNANCE_DEPTH_EXCEEDED":
        depth = 10
        message = error.get("message", "")
        try:
            fraction = message.split("(", 1)[1].split(")", 1)[0]
            depth = int(fraction.split("/", 1)[0])
        except (IndexError, ValueError):
            pass
        raise RevocDepthExceededError(depth=depth, max_depth=10)
    if code == "REVOC_GOVERNANCE_BLOCK":
        raise RevocGovernanceError(
            reason=error.get("message", ""),
            decision="block",
            blocked_by=error.get("blocked_by"),
            rules=error.get("rules") or [],
            trace_id=error.get("trace_id", ""),
            dashboard_url=error.get("dashboard_url", ""),
            documentation_url=error.get("documentation_url"),
        )
