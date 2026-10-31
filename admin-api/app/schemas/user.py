from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    org_id: str
    username: str
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = "viewer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    username: str
    email: str
    role: str
    is_superuser: bool
    created_at: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class APIKeyCreate(BaseModel):
    org_id: str
    user_id: str
    name: str
    caller_id: str
    policy_profile: str | None = None
    expires_at: str | None = None


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    user_id: str
    name: str
    caller_id: str
    policy_profile: str | None
    expires_at: str | None
    last_used: str | None
    created_at: str
    # Shown ONCE on creation only; None for all subsequent reads
    key: str | None = None
