from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    generate_api_key,
    get_current_user,
    hash_api_key,
    hash_password,
    verify_password,
)
from app.models.user import APIKey, User
from app.schemas.user import APIKeyCreate, APIKeyResponse, TokenResponse, UserCreate, UserResponse

router = APIRouter(tags=["auth / users"])


# ── Authentication ─────────────────────────────────────────────────────────────

@router.post("/api/v1/auth/token", response_model=TokenResponse)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """Exchange username + password for a JWT access token."""
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()
    if user is None or not verify_password(form_data.password, user.hashed_pw):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({"sub": user.id}, settings=settings)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/api/v1/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> UserResponse:
    """Register a new user. In production this requires a superuser caller."""
    if settings.is_production and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can register new accounts in production",
        )
    # Check for duplicate username / email
    existing = (
        await db.execute(
            select(User).where(
                (User.username == payload.username) | (User.email == str(payload.email))
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or e-mail already registered",
        )
    user = User(
        org_id=payload.org_id,
        username=payload.username,
        email=str(payload.email),
        hashed_pw=hash_password(payload.password),
        role=payload.role,
        is_superuser=False,
    )
    db.add(user)
    await db.flush()
    return UserResponse.model_validate(user)


# ── User profile ───────────────────────────────────────────────────────────────

@router.get("/api/v1/users/me", response_model=UserResponse)
async def get_me(
    current_user: Any = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated user's profile."""
    return UserResponse.model_validate(current_user)


# ── API Keys ───────────────────────────────────────────────────────────────────

@router.post(
    "/api/v1/api-keys",
    response_model=APIKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    payload: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> APIKeyResponse:
    """Create a new API key. The raw key is returned ONCE and never stored."""
    raw_key = generate_api_key()
    key_obj = APIKey(
        org_id=payload.org_id,
        user_id=payload.user_id,
        name=payload.name,
        key_hash=hash_api_key(raw_key),
        caller_id=payload.caller_id,
        policy_profile=payload.policy_profile,
        expires_at=payload.expires_at,
    )
    db.add(key_obj)
    await db.flush()

    resp = APIKeyResponse.model_validate(key_obj)
    # Inject the plaintext key — shown ONCE only
    resp.key = raw_key
    return resp


@router.get("/api/v1/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
) -> list[APIKeyResponse]:
    """List API keys for the authenticated user's org (key values never returned)."""
    rows = (
        await db.execute(
            select(APIKey).where(APIKey.org_id == current_user.org_id)
        )
    ).scalars().all()
    return [APIKeyResponse.model_validate(k) for k in rows]


@router.delete(
    "/api/v1/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
) -> Response:
    """Delete an API key owned by the caller's org."""
    key_obj = (
        await db.execute(select(APIKey).where(APIKey.id == key_id))
    ).scalar_one_or_none()
    if key_obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    if key_obj.org_id != current_user.org_id and not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your key")
    await db.delete(key_obj)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
