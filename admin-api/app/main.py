from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import init_db
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging


def create_app() -> FastAPI:
    """Application factory — instantiates and wires up the FastAPI application."""
    settings = get_settings()

    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup: ensure all tables exist (auto-migrate in non-production too)
        await init_db()
        yield
        # Shutdown: nothing to clean up for SQLite/async engine

    app = FastAPI(
        title="REVOC Admin API",
        version="0.1.0-beta.1",
        description=(
            "REVOC — Runtime Execution Validation & Observability Control. "
            "Admin plane for policy management, audit, and emergency controls."
        ),
        lifespan=lifespan,
        # Disable Swagger UI and ReDoc in production to reduce attack surface
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ── Exception handlers ────────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ───────────────────────────────────────────────────────────────
    from app.routers.audit import router as audit_router
    from app.routers.emergency import router as emergency_router
    from app.routers.health import router as health_router
    from app.routers.policies import router as policies_router
    from app.routers.reports import router as reports_router
    from app.routers.users import router as users_router

    app.include_router(health_router)
    app.include_router(policies_router)
    app.include_router(audit_router)
    app.include_router(users_router)
    app.include_router(emergency_router)
    app.include_router(reports_router)

    # ── OpenTelemetry (no-op if not configured) ───────────────────────────────
    from app.middleware.telemetry import setup_telemetry

    setup_telemetry(app, settings)

    return app


# Module-level app instance for ASGI servers (uvicorn, gunicorn+uvicorn worker)
app = create_app()
