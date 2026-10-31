from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

# ── Domain exceptions ─────────────────────────────────────────────────────────

class RevocAdminError(Exception):
    """Base class for all admin-API errors."""

    http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PolicyNotFoundError(RevocAdminError):
    http_status = status.HTTP_404_NOT_FOUND
    error_code = "POLICY_NOT_FOUND"


class PolicyCompilationError(RevocAdminError):
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "POLICY_COMPILATION_ERROR"

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors: list[str] = errors or []


class PolicyConflictError(RevocAdminError):
    http_status = status.HTTP_409_CONFLICT
    error_code = "POLICY_CONFLICT"


class OPAError(RevocAdminError):
    http_status = status.HTTP_502_BAD_GATEWAY
    error_code = "OPA_ERROR"


class UnauthorizedError(RevocAdminError):
    http_status = status.HTTP_401_UNAUTHORIZED
    error_code = "UNAUTHORIZED"


class AuditStoreError(RevocAdminError):
    http_status = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code = "AUDIT_STORE_ERROR"


# ── FastAPI exception handlers ────────────────────────────────────────────────

def _error_body(exc: RevocAdminError) -> dict[str, object]:
    detail: dict[str, object] = {
        "code": exc.error_code,
        "message": exc.message,
    }
    if isinstance(exc, PolicyCompilationError) and exc.errors:
        detail["compilation_errors"] = exc.errors
    return {"error": detail}


async def _handle_revoc_error(_request: Request, exc: RevocAdminError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content=_error_body(exc))


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RevocAdminError, _handle_revoc_error)  # type: ignore[arg-type]
    # Subclass handlers (FastAPI checks MRO so explicit registration ensures correct status)
    for cls in (
        PolicyNotFoundError,
        PolicyCompilationError,
        PolicyConflictError,
        OPAError,
        UnauthorizedError,
        AuditStoreError,
    ):
        app.add_exception_handler(cls, _handle_revoc_error)  # type: ignore[arg-type]
