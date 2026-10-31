from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.exceptions import (
    PolicyCompilationError,
    PolicyConflictError,
    PolicyNotFoundError,
)
from app.core.security import get_current_user, require_role
from app.models.policy import PolicyAuditLog, PolicyBundle
from app.schemas.common import PaginatedResponse
from app.schemas.policy import (
    PolicyActivateResponse,
    PolicyBundleCreate,
    PolicyBundleResponse,
    PolicyValidateRequest,
    PolicyValidateResponse,
)
from app.services.bundle_service import PolicyBundleService
from app.services.compiler_service import PolicyCompilerService
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])

_compiler = PolicyCompilerService()
_bundle_svc = PolicyBundleService()
_notifier = NotificationService()


@router.get("", response_model=PaginatedResponse[PolicyBundleResponse])
async def list_policies(
    org_id: str,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> PaginatedResponse[PolicyBundleResponse]:
    """List all policy bundles for *org_id* (paginated)."""
    offset = (page - 1) * page_size
    count_q = select(func.count()).select_from(PolicyBundle).where(
        PolicyBundle.org_id == org_id
    )
    total: int = (await db.execute(count_q)).scalar_one()
    rows = (
        await db.execute(
            select(PolicyBundle)
            .where(PolicyBundle.org_id == org_id)
            .order_by(PolicyBundle.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
    ).scalars().all()
    items = [PolicyBundleResponse.model_validate(b) for b in rows]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


# /validate must be registered BEFORE /{bundle_id} so FastAPI matches it first.
@router.post("/validate", response_model=PolicyValidateResponse)
async def validate_policy(
    payload: PolicyValidateRequest,
    _user: Any = Depends(get_current_user),
) -> PolicyValidateResponse:
    """Validate a policy YAML without persisting it."""
    rego, errors = await _compiler.compile(payload.yaml_content)
    if errors:
        return PolicyValidateResponse(is_valid=False, errors=errors)
    return PolicyValidateResponse(is_valid=True, compiled_rego=rego or None)


@router.post("", response_model=PolicyBundleResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyBundleCreate,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> PolicyBundleResponse:
    """Compile and persist a new policy bundle (status=draft)."""
    rego, errors = await _compiler.compile(payload.yaml_content)
    if errors:
        raise PolicyCompilationError("Policy compilation failed", errors)

    now = datetime.now(UTC).isoformat()
    bundle = PolicyBundle(
        org_id=payload.org_id,
        name=payload.name,
        environment=payload.environment,
        version=payload.version,
        yaml_content=payload.yaml_content,
        rego_content=rego or None,
        compiled_at=now if rego else None,
        created_by=payload.created_by,
        status="draft",
    )
    db.add(bundle)
    try:
        await db.flush()
    except Exception as exc:
        raise PolicyConflictError(
            "A bundle with this org/name/version/environment already exists"
        ) from exc
    return PolicyBundleResponse.model_validate(bundle)


@router.get("/{bundle_id}", response_model=PolicyBundleResponse)
async def get_policy(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> PolicyBundleResponse:
    """Fetch a single policy bundle by ID."""
    bundle = (
        await db.execute(select(PolicyBundle).where(PolicyBundle.id == bundle_id))
    ).scalar_one_or_none()
    if bundle is None:
        raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")
    return PolicyBundleResponse.model_validate(bundle)


@router.post("/{bundle_id}/activate", response_model=PolicyActivateResponse)
async def activate_policy(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    user: Any = Depends(require_role("admin")),
    settings: Settings = Depends(get_settings),
) -> PolicyActivateResponse:
    """Compile, activate, write to disk, and notify proxy + OPA (admin only)."""
    bundle = (
        await db.execute(select(PolicyBundle).where(PolicyBundle.id == bundle_id))
    ).scalar_one_or_none()
    if bundle is None:
        raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")

    rego, errors = await _compiler.compile(bundle.yaml_content)
    if errors:
        raise PolicyCompilationError("Cannot activate: compilation failed", errors)

    bundle.rego_content = rego or None
    bundle.compiled_at = datetime.now(UTC).isoformat()

    activated = await _bundle_svc.activate(db, bundle_id, actor=user.username)

    # Best-effort — failures do not block activation
    await _notifier.notify_proxy_reload(settings.proxy_internal_url)
    await _notifier.notify_opa_reload(settings.opa_url)

    return PolicyActivateResponse(
        bundle_id=activated.id,
        status=activated.status,
        activated_at=activated.activated_at or datetime.now(UTC).isoformat(),
        message="Policy bundle activated successfully.",
    )


@router.get("/{bundle_id}/rego")
async def get_policy_rego(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> Response:
    """Return the compiled Rego as text/plain."""
    bundle = (
        await db.execute(select(PolicyBundle).where(PolicyBundle.id == bundle_id))
    ).scalar_one_or_none()
    if bundle is None:
        raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")
    if not bundle.rego_content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No compiled Rego for this bundle",
        )
    return Response(content=bundle.rego_content, media_type="text/plain")


@router.delete("/{bundle_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def archive_policy(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    user: Any = Depends(require_role("admin")),
) -> Response:
    """Archive a bundle. NEVER physically deletes from the database."""
    bundle = (
        await db.execute(select(PolicyBundle).where(PolicyBundle.id == bundle_id))
    ).scalar_one_or_none()
    if bundle is None:
        raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")

    await db.execute(
        update(PolicyBundle)
        .where(PolicyBundle.id == bundle_id)
        .values(status="archived")
    )
    db.add(
        PolicyAuditLog(
            policy_bundle_id=bundle_id,
            action="archived",
            actor=user.username,
            yaml_hash_before=hashlib.sha256(bundle.yaml_content.encode()).hexdigest(),
        )
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{bundle_id}/rollback", response_model=PolicyBundleResponse)
async def rollback_policy(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    user: Any = Depends(require_role("admin")),
    settings: Settings = Depends(get_settings),
) -> PolicyBundleResponse:
    """Re-activate the most-recently archived bundle (admin only)."""
    prev = await _bundle_svc.rollback(db, bundle_id, actor=user.username)

    await _notifier.notify_proxy_reload(settings.proxy_internal_url)
    await _notifier.notify_opa_reload(settings.opa_url)

    return PolicyBundleResponse.model_validate(prev)
