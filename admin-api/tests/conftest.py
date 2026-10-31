"""Shared pytest fixtures for the REVOC Admin API test suite."""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Point tests at an isolated SQLite file (not the production revoc.db)
_TEST_DB_PATH = Path(__file__).parent / "test_revoc.db"
_TEST_DB_URL = f"sqlite+aiosqlite:///{_TEST_DB_PATH}"

# Override env before importing app modules so Settings picks it up
os.environ.setdefault("REVOC_ADMIN_DATABASE_URL", _TEST_DB_URL)
os.environ.setdefault("REVOC_ADMIN_ENVIRONMENT", "test")
os.environ.setdefault("REVOC_ADMIN_ADMIN_KEY", "test-admin-key")
os.environ.setdefault("REVOC_ADMIN_SECRET_KEY", "test-secret-key-long-enough-for-jwt")

from app.core.config import get_settings  # noqa: E402
from app.core.database import Base, get_db  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.user import User  # noqa: E402

# ── Database engine (shared across the session) ───────────────────────────────

_test_engine = create_async_engine(
    _TEST_DB_URL,
    connect_args={"check_same_thread": False},
)
_TestSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=_test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_tables() -> AsyncGenerator[None, None]:
    """Create all tables once per test session; drop them on teardown."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await _test_engine.dispose()
    _TEST_DB_PATH.unlink(missing_ok=True)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a fresh async session; roll back after each test."""
    async with _TestSessionLocal() as session:
        yield session
        await session.rollback()


# ── App + HTTP client ─────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Return an AsyncClient wired to an in-process FastAPI app with the test DB."""
    app = create_app()

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


# ── Users + auth headers ──────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create (and persist) a test user with role=admin."""
    user = User(
        org_id="test-org",
        username="testadmin",
        email="testadmin@example.com",
        hashed_pw=hash_password("password123"),
        role="admin",
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def viewer_user(db_session: AsyncSession) -> User:
    """Create a viewer-role user."""
    user = User(
        org_id="test-org",
        username="testviewer",
        email="testviewer@example.com",
        hashed_pw=hash_password("password123"),
        role="viewer",
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict[str, str]:
    """Return JWT Bearer headers for the admin test user."""
    settings = get_settings()
    token = create_access_token({"sub": test_user.id}, settings=settings)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers(viewer_user: User) -> dict[str, str]:
    """Return JWT Bearer headers for the viewer test user."""
    settings = get_settings()
    token = create_access_token({"sub": viewer_user.id}, settings=settings)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def internal_key_headers() -> dict[str, str]:
    """Return the X-Revoc-Internal-Key header used by the proxy for audit ingest."""
    return {"X-Revoc-Internal-Key": "test-admin-key"}


# ── Policy directory override ─────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def override_policy_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect all bundle disk writes to a per-test temp directory."""
    monkeypatch.setattr("app.services.bundle_service.POLICY_DIR", str(tmp_path))


# ── Compiler mock ─────────────────────────────────────────────────────────────

@pytest.fixture
def mock_compiler() -> Any:
    """Patch PolicyCompilerService.compile to return valid Rego without calling OPA."""
    compiled_rego = (
        "package revoc.governance.custom\n\n"
        "# Generated by REVOC PolicyCompilerService\n"
    )
    with patch(
        "app.routers.policies._compiler.compile",
        new_callable=AsyncMock,
        return_value=(compiled_rego, []),
    ) as mock:
        yield mock


@pytest.fixture
def mock_compiler_fail() -> Any:
    """Patch compile to simulate compilation failure."""
    with patch(
        "app.routers.policies._compiler.compile",
        new_callable=AsyncMock,
        return_value=("", ["YAML parse error: invalid syntax at line 1"]),
    ) as mock:
        yield mock


# ── Minimal valid policy YAML ─────────────────────────────────────────────────

VALID_POLICY_YAML = """\
apiVersion: revoc.io/v1
kind: PolicyManifest
metadata:
  name: test-policy
  org_id: test-org
spec:
  profile: internal-dev
  model_restrictions:
    allowed_models:
      - gpt-4o-mini
  quotas:
    default:
      tokens_per_request: 4096
"""

INVALID_POLICY_YAML = "this: is: not: valid: yaml: :"
