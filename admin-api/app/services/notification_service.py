from __future__ import annotations

import httpx

from app.core.logging import get_logger

_log = get_logger(__name__)

_TIMEOUT = 5.0  # seconds


class NotificationService:
    """Notify the REVOC proxy and OPA sidecar of configuration changes."""

    async def notify_proxy_reload(self, proxy_url: str) -> bool:
        """POST /internal/reload to trigger the proxy to re-read its policy bundle.

        Returns True if the proxy acknowledged the request.
        """
        url = f"{proxy_url}/internal/reload"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                resp = await client.post(url)
            except httpx.RequestError as exc:
                _log.warning("proxy_reload_error", url=url, error=str(exc))
                return False
            else:
                if not resp.is_success:
                    _log.warning("proxy_reload_failed", status=resp.status_code, url=url)
                return resp.is_success

    async def notify_opa_reload(self, opa_url: str) -> bool:
        """Check OPA health (and trigger bundle re-evaluation where applicable).

        OPA with --bundle auto-watches file changes; this call confirms OPA is
        reachable and that bundles are loaded.
        Returns True if OPA is healthy.
        """
        url = f"{opa_url}/health?bundles=true"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                resp = await client.get(url)
            except httpx.RequestError as exc:
                _log.warning("opa_health_error", url=url, error=str(exc))
                return False
            else:
                if not resp.is_success:
                    _log.warning("opa_health_failed", status=resp.status_code, url=url)
                return resp.is_success
