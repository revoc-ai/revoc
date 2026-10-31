"""revoc_sdk.exceptions — typed exceptions raised when REVOC governs a request.

These map 1:1 onto the `error.code` values produced by `RevocErrorResponse`
(see SPEC.md Section 7.5 / types/openai.rs). The REVOC client inspects the
JSON error body returned by the proxy and raises the matching exception type
so application code can branch on governance outcomes without parsing HTTP
responses by hand.
"""

from __future__ import annotations


class RevocGovernanceError(Exception):
    """Raised when REVOC blocks a request due to a policy violation.

    Corresponds to `error.code == "REVOC_GOVERNANCE_BLOCK"`.
    """

    def __init__(
        self,
        decision: str,
        blocked_by: str | None,
        rules: list[str],
        trace_id: str,
        dashboard_url: str,
        documentation_url: str | None = None,
        *,
        reason: str | None = None,
    ) -> None:
        self.decision = decision
        self.blocked_by = blocked_by
        self.rules = rules
        self.trace_id = trace_id
        self.dashboard_url = dashboard_url
        self.documentation_url = documentation_url
        self.reason = reason or f"Request blocked by rule(s): {', '.join(rules) or blocked_by or 'unknown'}"
        super().__init__(str(self))

    def __str__(self) -> str:
        return (
            f"REVOC blocked [{self.blocked_by}]: {self.reason}\n"
            f"Trace: {self.trace_id}\nDashboard: {self.dashboard_url}"
        )


class RevocKillSwitchError(Exception):
    """Raised when the emergency kill-switch is active.

    Corresponds to `error.code == "REVOC_KILL_SWITCH_ACTIVE"`.
    """

    def __init__(self, *, scope: str, dashboard_url: str) -> None:
        self.scope = scope
        self.dashboard_url = dashboard_url
        super().__init__(str(self))

    def __str__(self) -> str:
        return "REVOC emergency stop active. Contact your AI platform team."


class RevocDepthExceededError(Exception):
    """Raised when governance depth reaches the configured maximum.

    Corresponds to `error.code == "REVOC_GOVERNANCE_DEPTH_EXCEEDED"`.
    """

    def __init__(self, *, depth: int, max_depth: int = 10) -> None:
        self.depth = depth
        self.max_depth = max_depth
        super().__init__(str(self))

    def __str__(self) -> str:
        return (
            f"Governance depth {self.depth}/{self.max_depth} reached. "
            "Possible infinite agent loop."
        )


class RevocRateLimitError(Exception):
    """Raised when the caller has exceeded their configured rate limit.

    Corresponds to `error.code == "REVOC_RATE_LIMIT_EXCEEDED"`.
    """

    def __init__(self, *, retry_after_secs: int) -> None:
        self.retry_after_secs = retry_after_secs
        super().__init__(str(self))

    def __str__(self) -> str:
        return f"REVOC rate limit exceeded. Retry after {self.retry_after_secs} seconds."
