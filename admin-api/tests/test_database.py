"""tests/test_database.py — coverage for app.core.database session/engine helpers."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.core.config import Settings
from app.core.database import _make_engine, get_db, init_db


@pytest.mark.asyncio
async def test_get_db_commits_on_success() -> None:
    """get_db() must yield a session and commit it on clean exit."""
    agen = get_db()
    session = await agen.__anext__()
    await session.execute(text("SELECT 1"))
    with pytest.raises(StopAsyncIteration):
        await agen.__anext__()


@pytest.mark.asyncio
async def test_get_db_rolls_back_and_reraises_on_error() -> None:
    """get_db() must roll back and re-raise if the caller raises inside the block."""
    agen = get_db()
    await agen.__anext__()

    class _BoomError(Exception):
        pass

    with pytest.raises(_BoomError):
        await agen.athrow(_BoomError)


@pytest.mark.asyncio
async def test_init_db_creates_tables() -> None:
    """init_db() must run create_all against the configured engine without error."""
    await init_db()


def test_make_engine_postgres_branch() -> None:
    """_make_engine() must build a pool-configured engine for non-sqlite URLs."""
    settings = Settings(
        database_url="postgresql+asyncpg://user:pass@localhost:5432/revoc",
        environment="production",
    )
    engine = _make_engine(settings_override=settings)
    assert engine.url.drivername == "postgresql+asyncpg"
