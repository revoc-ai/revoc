from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PolicyNotFoundError
from app.models.policy import PolicyAuditLog, PolicyBundle

# Module-level default — override in tests via:
#   monkeypatch.setattr("app.services.bundle_service.POLICY_DIR", str(tmp_path))
POLICY_DIR: str = "/etc/revoc/policies"


class PolicyBundleService:
    """Manage policy bundle lifecycle: write, activate, rollback."""

    # ── disk I/O ──────────────────────────────────────────────────────────────

    async def write_to_disk(self, bundle: PolicyBundle, policy_dir: str) -> None:
        """Write bundle YAML (and compiled Rego if present) to the policy directory."""
        base = Path(policy_dir) / bundle.org_id / bundle.name
        base.mkdir(parents=True, exist_ok=True)
        (base / "policy.yaml").write_text(bundle.yaml_content, encoding="utf-8")
        if bundle.rego_content:
            (base / "policy.rego").write_text(bundle.rego_content, encoding="utf-8")

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def activate(
        self,
        db: AsyncSession,
        bundle_id: str,
        actor: str = "system",
    ) -> PolicyBundle:
        """Activate a bundle: archive current active, write to disk, update status."""
        result = await db.execute(
            select(PolicyBundle).where(PolicyBundle.id == bundle_id)
        )
        bundle = result.scalar_one_or_none()
        if bundle is None:
            raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")

        # Archive currently active bundles for the same org + environment
        await db.execute(
            update(PolicyBundle)
            .where(
                PolicyBundle.org_id == bundle.org_id,
                PolicyBundle.environment == bundle.environment,
                PolicyBundle.status == "active",
            )
            .values(status="archived")
        )

        now = datetime.now(UTC).isoformat()
        bundle.status = "active"
        bundle.activated_at = now

        await self.write_to_disk(bundle, POLICY_DIR)

        yaml_hash = hashlib.sha256(bundle.yaml_content.encode()).hexdigest()
        db.add(
            PolicyAuditLog(
                policy_bundle_id=bundle_id,
                action="activated",
                actor=actor,
                yaml_hash_after=yaml_hash,
            )
        )
        await db.flush()
        return bundle

    async def rollback(
        self,
        db: AsyncSession,
        bundle_id: str,
        actor: str = "system",
    ) -> PolicyBundle:
        """Re-activate the most-recently archived bundle for the same org + environment."""
        result = await db.execute(
            select(PolicyBundle).where(PolicyBundle.id == bundle_id)
        )
        current = result.scalar_one_or_none()
        if current is None:
            raise PolicyNotFoundError(f"Bundle '{bundle_id}' not found")

        prev_result = await db.execute(
            select(PolicyBundle)
            .where(
                PolicyBundle.org_id == current.org_id,
                PolicyBundle.environment == current.environment,
                PolicyBundle.status == "archived",
                PolicyBundle.id != bundle_id,
            )
            .order_by(PolicyBundle.activated_at.desc())
            .limit(1)
        )
        prev = prev_result.scalar_one_or_none()
        if prev is None:
            raise PolicyNotFoundError(
                "No archived bundle available to roll back to"
            )

        # Archive current active
        await db.execute(
            update(PolicyBundle)
            .where(
                PolicyBundle.org_id == current.org_id,
                PolicyBundle.environment == current.environment,
                PolicyBundle.status == "active",
            )
            .values(status="archived")
        )

        prev.status = "active"
        prev.activated_at = datetime.now(UTC).isoformat()

        db.add(
            PolicyAuditLog(
                policy_bundle_id=prev.id,
                action="rollback",
                actor=actor,
            )
        )
        await db.flush()
        return prev
