"""revoc_sdk.governance — async client for the REVOC dashboard / admin-api.

Exposed via `client.governance` on `RevocOpenAI` / `RevocAsyncOpenAI`. All
methods are thin wrappers over the admin-api REST surface (see
admin-api/app/routers/*) using httpx.AsyncClient under the hood.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx


class GovernanceClient:
    """Async helper for querying audit data and controlling governance state.

    Parameters
    ----------
    base_url:
        Base URL of the REVOC dashboard / admin-api (e.g. ``http://revoc:3000``).
    api_key:
        Optional bearer token / API key used to authenticate against the
        admin-api. Sent as ``Authorization: Bearer <api_key>`` when present.
    """

    def __init__(self, base_url: str, *, api_key: str | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def get_audit_events(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Fetch audit events matching the given query parameters.

        Accepts the same query parameters as ``GET /api/v1/audit`` (e.g.
        ``org_id``, ``decision``, ``limit``, ``offset``).
        """
        async with httpx.AsyncClient(base_url=self._base_url) as client:
            resp = await client.get("/api/v1/audit", params=kwargs, headers=self._headers())
            resp.raise_for_status()
            data: list[dict[str, Any]] = resp.json()
            return data

    async def get_audit_stats(self, start_time: datetime, end_time: datetime) -> dict[str, Any]:
        """Fetch aggregate audit statistics for a time window."""
        params = {"start_time": start_time.isoformat(), "end_time": end_time.isoformat()}
        async with httpx.AsyncClient(base_url=self._base_url) as client:
            resp = await client.get("/api/v1/audit/stats", params=params, headers=self._headers())
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data

    async def validate_policy(self, yaml_content: str) -> dict[str, Any]:
        """Validate a policy bundle YAML manifest without activating it."""
        async with httpx.AsyncClient(base_url=self._base_url) as client:
            resp = await client.post(
                "/api/v1/policies/validate",
                json={"yaml_content": yaml_content},
                headers=self._headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data

    async def activate_kill_switch(self, scope: str, reason: str) -> dict[str, Any]:
        """Activate the emergency kill-switch for the given scope.

        ``scope`` is one of ``"global"``, ``"org"``, or ``"caller"``.
        """
        async with httpx.AsyncClient(base_url=self._base_url) as client:
            resp = await client.post(
                "/api/v1/emergency/kill-switch/activate",
                json={"scope": scope, "reason": reason, "activated_by": "revoc-sdk"},
                headers=self._headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data

    async def deactivate_kill_switch(self, scope: str) -> dict[str, Any]:
        """Deactivate the emergency kill-switch for the given scope."""
        async with httpx.AsyncClient(base_url=self._base_url) as client:
            resp = await client.post(
                "/api/v1/emergency/kill-switch/deactivate",
                json={"scope": scope},
                headers=self._headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data
