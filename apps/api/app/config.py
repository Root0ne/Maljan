"""Maljan API — Application configuration.

Loads from environment variables with sensible defaults for development.
All settings can be overridden via .env or OS environment.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class APISettings(BaseSettings):
    """API-level configuration (separate from maljan-core Settings)."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env", "../../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    app_name: str = "Maljan"
    app_version: str = "0.1.0"
    debug: bool = False
    cors_origins: list[str] = Field(default=["http://localhost:3000", "http://127.0.0.1:3000"])

    # ── Database ─────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://maljan:maljan_dev@127.0.0.1:5432/maljan"

    # ── Redis ────────────────────────────────────────────────────
    redis_url: str = "redis://127.0.0.1:6379/0"

    # ── MinIO / S3 ───────────────────────────────────────────────
    minio_endpoint: str = "127.0.0.1:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "maljan-samples"
    minio_secure: bool = False

    # ── JWT Auth ─────────────────────────────────────────────────
    jwt_secret_key: str = "CHANGE-ME-IN-PRODUCTION-USE-OPENSSL-RAND"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ── Qdrant (passed through to maljan-core) ───────────────────
    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_collection: str = "maljan_ltm"


settings = APISettings()
