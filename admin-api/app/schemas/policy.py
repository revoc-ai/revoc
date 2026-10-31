from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PolicyBundleCreate(BaseModel):
    org_id: str
    name: str
    environment: str = "production"
    version: str
    yaml_content: str
    created_by: str


class PolicyBundleUpdate(BaseModel):
    name: str | None = None
    environment: str | None = None
    yaml_content: str | None = None


class PolicyBundleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    name: str
    environment: str
    version: str
    status: str
    yaml_content: str
    rego_content: str | None
    compiled_at: str | None
    activated_at: str | None
    created_at: str
    created_by: str


class PolicyValidateRequest(BaseModel):
    yaml_content: str


class PolicyValidateResponse(BaseModel):
    is_valid: bool
    errors: list[str] = Field(default_factory=list)
    compiled_rego: str | None = None


class PolicyActivateResponse(BaseModel):
    bundle_id: str
    status: str
    activated_at: str
    message: str
