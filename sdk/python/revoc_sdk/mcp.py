"""revoc_sdk.mcp — helpers for governed Model Context Protocol tool calls.

REVOC inspects MCP traffic bidirectionally (SPEC.md Section 11, MCP Handler
12-step lifecycle). When a `tools/call` request is blocked, the proxy returns
a JSON-RPC error response shaped like `McpBlockResponse`
(`{"error": {"code": -32603, "data": {"code": "REVOC_GOVERNANCE_BLOCK", ...}}}`).

This module provides a small helper that posts a governed `tools/call`
request through REVOC and raises :class:`RevocMcpError` when the call was
blocked, so MCP client code can handle governance outcomes uniformly with
the LLM-side exceptions in :mod:`revoc_sdk.exceptions`.
"""

from __future__ import annotations

from typing import Any

import httpx


class RevocMcpError(Exception):
    """Raised when REVOC blocks an MCP `tools/call` request.

    Mirrors the JSON-RPC error payload (`McpBlockResponse` /
    `McpBlockData`, see SPEC.md Section 7.4): the upstream MCP server never
    receives a blocked request (Rule 9 in Section 23).
    """

    def __init__(
        self,
        *,
        message: str,
        code: str,
        rules: list[str],
        trace_id: str,
        dashboard_url: str,
    ) -> None:
        self.message = message
        self.code = code
        self.rules = rules
        self.trace_id = trace_id
        self.dashboard_url = dashboard_url
        super().__init__(str(self))

    def __str__(self) -> str:
        return (
            f"REVOC blocked MCP tool call [{self.code}]: {self.message}\n"
            f"Trace: {self.dashboard_url}"
        )


class RevocMcpClient:
    """Stateful client for governed MCP `tools/call` requests through REVOC.

    Wraps :func:`governed_tool_call` with a persistent base URL, default
    headers, and an auto-incrementing JSON-RPC request id, so callers can
    issue repeated governed tool calls without repeating boilerplate.
    """

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url
        self.headers = headers or {}
        self._next_id = 1

    def _request_id(self) -> str:
        request_id = str(self._next_id)
        self._next_id += 1
        return request_id

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue a governed `tools/call` request.

        Raises :class:`RevocMcpError` if REVOC blocks the call before it
        ever reaches the upstream MCP server (SPEC.md §23 Rule 9).
        """
        return await governed_tool_call(
            self.base_url,
            tool_name=tool_name,
            arguments=arguments,
            server_id=server_id,
            request_id=self._request_id(),
            headers=self.headers,
        )


async def governed_tool_call(
    base_url: str,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    server_id: str | None = None,
    request_id: str = "1",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """POST a `tools/call` JSON-RPC request through the REVOC MCP endpoint.

    Returns the parsed JSON-RPC result on success. Raises
    :class:`RevocMcpError` if REVOC blocked the call before it ever reached
    the upstream MCP server.
    """
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    if server_id is not None:
        payload["params"]["server_id"] = server_id

    async with httpx.AsyncClient(base_url=base_url) as client:
        resp = await client.post("/mcp", json=payload, headers=headers or {})
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()

    error = body.get("error")
    if isinstance(error, dict):
        raw_data = error.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        if data.get("code") == "REVOC_GOVERNANCE_BLOCK":
            raise RevocMcpError(
                message=error.get("message", ""),
                code=data.get("code", "REVOC_GOVERNANCE_BLOCK"),
                rules=data.get("rules") or [],
                trace_id=data.get("trace_id", ""),
                dashboard_url=data.get("dashboard_url", ""),
            )
    return body
