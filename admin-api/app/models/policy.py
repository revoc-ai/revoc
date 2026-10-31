from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


class PolicyBundle(Base):
    __tablename__ = "policy_bundles"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "name", "version", "environment",
            name="uq_bundle_org_name_ver_env",
        ),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(Text, nullable=False, default="production")
    version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    rego_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    compiled_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    activated_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False, default=_now)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)


class PolicyAuditLog(Base):
    __tablename__ = "policy_audit_log"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=_uuid)
    policy_bundle_id: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    yaml_hash_before: Mapped[str | None] = mapped_column(Text, nullable=True)
    yaml_hash_after: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str] = mapped_column(Text, nullable=False, default=_now)
