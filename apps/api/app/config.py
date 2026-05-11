"""Maljan API — Application configuration.

Loads from environment variables with sensible defaults for development.
All settings can be overridden via .env or OS environment.

Security-sensitive defaults (JWT secret, MinIO credentials) refuse to boot
the API in non-debug mode unless the operator provided real values.
"""

from __future__ import annotations

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_JWT_SECRETS = {
    "",
    "CHANGE-ME-IN-PRODUCTION-USE-OPENSSL-RAND",
    "change-me",
    "changeme",
    "secret",
}

_PLACEHOLDER_MINIO_KEYS = {"minioadmin", ""}


def _is_test_env() -> bool:
    """Return True when running under pytest or with the explicit skip flag set."""
    import os as _os
    import sys as _sys

    return (
        "pytest" in _sys.modules
        or "PYTEST_CURRENT_TEST" in _os.environ
        or _os.environ.get("MALJAN_API_SKIP_SECRET_CHECK") == "1"
    )


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
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    cors_allow_headers: list[str] = Field(
        default=["Authorization", "Content-Type", "X-Correlation-Id"]
    )

    # Trusted reverse-proxy IPs allowed to set X-Forwarded-For for rate limiting.
    # Empty list means do not honour XFF (uvicorn peer IP only).
    trusted_proxy_ips: list[str] = Field(default=[])

    # ── Database ─────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://maljan:maljan_dev@127.0.0.1:5433/maljan"
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle_seconds: int = 1800
    # When True, the application calls Alembic upgrade on startup. Production
    # deployments should run migrations as a separate deploy step instead.
    run_migrations_on_startup: bool = False

    # ── Redis ────────────────────────────────────────────────────
    redis_url: str = "redis://127.0.0.1:6379/0"

    # ── MinIO / S3 ───────────────────────────────────────────────
    minio_endpoint: str = "127.0.0.1:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: SecretStr = SecretStr("minioadmin")
    minio_bucket: str = "maljan-samples"
    minio_secure: bool = False

    # ── JWT Auth ─────────────────────────────────────────────────
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    jwt_issuer: str = "maljan-api"
    jwt_audience: str = "maljan-clients"

    # Login throttle (per-account)
    login_max_attempts: int = 10
    login_lockout_seconds: int = 300

    # ── Qdrant (passed through to maljan-core) ───────────────────
    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_collection: str = "maljan_ltm"

    # ── Rate Limiting ────────────────────────────────────────────
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_requests: int = Field(default=100)
    rate_limit_window_seconds: int = Field(default=60)
    rate_limit_whitelist: list[str] = Field(default=["/health", "/docs", "/redoc", "/openapi.json"])

    # ── File upload ──────────────────────────────────────────────
    upload_max_bytes: int = Field(default=50 * 1024 * 1024)  # 50 MB
    upload_allowed_mime_types: list[str] = Field(
        default=[
            "application/x-dosexec",
            "application/x-mach-binary",
            "application/x-elf",
            "application/octet-stream",
            "application/zip",
            "application/x-msdownload",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
        ]
    )

    @field_validator("jwt_secret_key")
    @classmethod
    def _enforce_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        # Allow weak/empty secrets in test runs so suite collection doesn't fail.
        if _is_test_env():
            return value if secret else SecretStr("test-secret-do-not-use-in-prod-0123456789ab")
        if secret in _PLACEHOLDER_JWT_SECRETS or len(secret) < 32:
            raise ValueError(
                "JWT_SECRET_KEY is unset or too weak. Generate one with "
                "`openssl rand -hex 32` and set it via the JWT_SECRET_KEY env var."
            )
        return value

    @field_validator("minio_secret_key")
    @classmethod
    def _enforce_minio_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if secret in _PLACEHOLDER_MINIO_KEYS:
            # Soft-fail in tests: only raise when DEBUG is False; the validator
            # itself cannot see other fields, so we leave the assertion to a
            # post-init hook (model_post_init).
            return SecretStr(secret)
        return value

    def model_post_init(self, __context: object) -> None:
        # Skip the strict placeholder check when pytest is running or when
        # the caller has explicitly opted out (e.g. local Docker compose
        # with the default minioadmin bootstrap). Production deployments
        # MUST set DEBUG=False *and* a real MinIO secret.
        if self.debug or _is_test_env():
            return
        secret = (
            self.minio_secret_key.get_secret_value()
            if isinstance(self.minio_secret_key, SecretStr)
            else str(self.minio_secret_key)
        )
        if secret in _PLACEHOLDER_MINIO_KEYS:
            raise ValueError(
                "MINIO_SECRET_KEY is using the default placeholder. "
                "Set a real value before running in non-debug mode."
            )


_settings: APISettings | None = None


def get_settings() -> APISettings:
    """Return the cached APISettings instance (lazy)."""
    global _settings
    if _settings is None:
        _settings = APISettings()
    return _settings


def reset_settings_cache() -> None:
    """Drop the cached settings (intended for tests)."""
    global _settings
    _settings = None


class _LazyAPISettings:
    """Attribute-forwarding proxy that builds APISettings on first access."""

    __slots__ = ()

    def __getattr__(self, name: str):  # noqa: ANN204
        return getattr(get_settings(), name)


# Legacy import surface — many modules still do ``from app.config import settings``.
settings = _LazyAPISettings()
