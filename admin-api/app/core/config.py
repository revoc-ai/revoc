from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///revoc.db"
    redis_url: str = "redis://localhost:6379"
    secret_key: str = "change-me-in-production"
    admin_key: str = "dev-admin-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    proxy_internal_url: str = "http://localhost:8081"
    policy_dir: str = "/etc/revoc/policies"
    log_level: str = "info"
    environment: str = "production"
    cors_origins: list[str] = []
    opa_url: str = "http://localhost:8181"
    dashboard_base_url: str = "http://localhost:3000"
    audit_retention_days: int = 90

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="REVOC_ADMIN_",
        extra="ignore",
    )

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"debug", "info", "warning", "error", "critical"}
        if v.lower() not in allowed:
            msg = f"log_level must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("environment")
    @classmethod
    def _validate_environment(cls, v: str) -> str:
        allowed = {"production", "staging", "development", "test"}
        if v.lower() not in allowed:
            msg = f"environment must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
