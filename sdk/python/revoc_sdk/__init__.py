"""revoc_sdk — zero-code-change governance SDK for REVOC.

    from revoc_sdk import RevocOpenAI
    client = RevocOpenAI(api_key="sk-...")

See https://revoc.io/docs for full documentation.
"""

from __future__ import annotations

from revoc_sdk.client import RevocAsyncOpenAI, RevocOpenAI
from revoc_sdk.exceptions import (
    RevocDepthExceededError,
    RevocGovernanceError,
    RevocKillSwitchError,
    RevocRateLimitError,
)
from revoc_sdk.governance import GovernanceClient
from revoc_sdk.mcp import RevocMcpClient, RevocMcpError, governed_tool_call
from revoc_sdk.patch import patch, unpatch

__version__ = "1.0.0"

__all__ = [
    "GovernanceClient",
    "RevocAsyncOpenAI",
    "RevocDepthExceededError",
    "RevocGovernanceError",
    "RevocKillSwitchError",
    "RevocMcpClient",
    "RevocMcpError",
    "RevocOpenAI",
    "RevocRateLimitError",
    "__version__",
    "governed_tool_call",
    "patch",
    "unpatch",
]
