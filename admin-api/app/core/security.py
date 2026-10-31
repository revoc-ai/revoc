from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    hashed: str = _pwd_context.hash(password)
    return hashed


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
    *,
    settings: Settings | None = None,
) -> str:
    cfg = settings or get_settings()
    expire = datetime.now(UTC) + (
        expires_delta if expires_delta is not None
        else timedelta(minutes=cfg.access_token_expire_minutes)
    )
    payload = {**data, "exp": expire}
    return jwt.encode(payload, cfg.secret_key, algorithm=cfg.algorithm)


def decode_access_token(
    token: str,
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    try:
        return jwt.decode(token, cfg.secret_key, algorithms=[cfg.algorithm])
    except PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── API-key helpers ───────────────────────────────────────────────────────────

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def validate_admin_key(key: str, settings: Settings) -> bool:
    return hmac.compare_digest(key.encode(), settings.admin_key.encode())


# ── FastAPI dependency helpers ────────────────────────────────────────────────

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Any:
    payload = decode_access_token(token)
    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# Role hierarchy — higher rank satisfies all lower-rank requirements.
_ROLE_RANK: dict[str, int] = {
    "viewer": 0,
    "audit_viewer": 1,
    "editor": 2,
    "admin": 3,
}


def require_role(min_role: str) -> Any:
    """Return a FastAPI dependency that enforces a minimum role (hierarchical).

    Usage: ``user: Annotated[User, Depends(require_role("admin"))]``
    Superusers bypass the role check entirely.
    Role order (ascending): viewer < audit_viewer < editor < admin.
    """
    min_rank = _ROLE_RANK.get(min_role, 999)

    async def _dependency(
        current_user: Annotated[Any, Depends(get_current_user)],
    ) -> Any:
        if current_user.is_superuser:
            return current_user
        user_rank = _ROLE_RANK.get(current_user.role, -1)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{min_role}' or higher required",
            )
        return current_user

    return _dependency
