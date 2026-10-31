from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class KillSwitchActivateRequest(BaseModel):
    scope: Literal["global", "org", "caller"]
    target_id: str | None = None   # required when scope is org or caller
    reason: str
    activated_by: str


class KillSwitchDeactivateRequest(BaseModel):
    scope: Literal["global", "org", "caller"]
    target_id: str | None = None


class KillSwitchStatusResponse(BaseModel):
    global_active: bool
    active_orgs: list[str]
    active_callers: list[str]
    last_activated_at: str | None = None
    last_deactivated_at: str | None = None


class KillSwitchLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str | None = None        # None when ORM object not yet flushed to DB
    scope: str
    scope_value: str | None = None
    action: str
    activated_by: str
    reason: str | None = None
    timestamp: str | None = None  # None when ORM object not yet flushed to DB
