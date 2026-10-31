from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import Settings, get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(settings_override: Settings | None = None) -> Any:
    settings = settings_override or get_settings()
    url = settings.database_url

    if settings.is_sqlite:
        return create_async_engine(
            url,
            echo=not settings.is_production,
            connect_args={"check_same_thread": False},
        )
    # PostgreSQL via asyncpg — no extra connect_args needed
    return create_async_engine(
        url,
        echo=not settings.is_production,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )


engine = _make_engine()

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
