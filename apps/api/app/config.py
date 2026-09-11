"""Maljan API — Application configuration.

Loads from the process environment only, with sensible defaults for local
development. No ``.env`` file is discovered or read — set variables in the
process environment (or the container/orchestrator config) instead.

Construction never refuses. Security-sensitive defaults (JWT secret, MinIO
credentials, the auth bypass) are checked at startup instead, by
``app.bootstrap.validate_bootstrap``, so a misconfigured deployment dies with
one ``bootstrap: ...`` line naming every problem rather than a traceback from
whichever import built the settings singleton first.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_JWT_SECRETS = {
    "",
    "CHANGE-ME-IN-PRODUCTION-USE-OPENSSL-RAND",
    "change-me",
    "changeme",
    "secret",
}

_PLACEHOLDER_MINIO_KEYS = {"minioadmin", ""}

# Substituted for an unset ``JWT_SECRET_KEY`` under pytest only, so suite
# collection does not need a secret in the environment. It is published in
# this repository, so nothing outside a test run may ever receive it: the
# substitution is gated on ``_is_test_env`` and ``validate_bootstrap`` reads
# the environment rather than the substituted field.
TEST_JWT_SECRET = "pytest-only-jwt-secret-00000000000000000000"


def _is_test_env() -> bool:
    """Return True when running under pytest.

    Read from the interpreter state alone. Nothing in the environment may
    answer this question: a variable that turns a boot refusal off is a
    variable that ships to production with it turned off, and
    ``PYTEST_CURRENT_TEST=1`` would have handed a real deployment the
    published ``TEST_JWT_SECRET`` exactly the way
    ``MALJAN_API_SKIP_SECRET_CHECK`` did. The import is what every real run
    has: pytest imports itself in the main process and in each xdist worker.
    """
    import sys as _sys

    return "pytest" in _sys.modules


class APISettings(BaseSettings):
    """API-level configuration (separate from maljan-core Settings)."""

    model_config = SettingsConfigDict(
        env_file=None,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    app_name: str = "Maljan"
    app_version: str = "0.1.0"
    debug: bool = False
    # Echo every SQL statement to the log. Deliberately independent of ``debug``
    # (audit 2026-07-26, Ö6): with DEBUG=true this drowned the worker/API logs in
    # duplicated SQL and made pipeline stages impossible to follow. Enable only
    # when actively debugging queries: ``SQL_ECHO=true``.
    sql_echo: bool = False

    cors_origins: list[str] = Field(default=["http://localhost:3000", "http://127.0.0.1:3000"])
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    # "X-API-Key" is required for the API-key auth path (audit 2026-07-26, K2);
    # without it the browser preflight strips the header and keys silently fail.
    cors_allow_headers: list[str] = Field(
        default=["Authorization", "Content-Type", "X-Correlation-Id", "X-API-Key"]
    )

    # ── Database ─────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://maljan:maljan_dev@127.0.0.1:5433/maljan"
    # Bounds, here and on every numeric leaf below (B4, dev audit 2026-09-06):
    # each of these is a size, a count or a period, and a value at or below
    # zero does not mean "unlimited" for any of them -- it means a pool that
    # cannot serve, a token already expired, or a Redis expiry that deletes
    # the key it was meant to set. The editable ones are PATCHable, so an
    # out-of-range value comes back as a 422 under its own key instead of
    # being applied.
    db_pool_size: int = Field(default=5, ge=1)
    db_max_overflow: int = Field(default=10, ge=0)
    db_pool_recycle_seconds: int = Field(default=1800, ge=1)
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

    # ── Ghidra MCP container delivery (Wave 6 GHIDRA-DELIVERY-01) ───
    # Worker mirrors each MinIO-downloaded sample into ``data/samples/``
    # on the host so the Ghidra MCP container can read it through its
    # bind mount. ``ghidra_container_samples_path`` is the path at which
    # the Ghidra container sees that directory — it must match the
    # right-hand side of the ``../data/samples:/data/samples`` mount in
    # ``docker/docker-compose.yml``. Override via env when relocating
    # the mount or running Ghidra outside Docker.
    ghidra_container_samples_path: str = "/data/samples"

    # ── Settings-store encryption ──────────────────────────────
    # Fernet key that encrypts secret values in the runtime settings store.
    # Read directly from the environment by ``maljan.core.settings_secrets``
    # too (that reader is unchanged by this field); declared here as well so
    # bootstrap validation can see it alongside the rest of the contract.
    settings_encryption_key: SecretStr = SecretStr("")

    # ── JWT Auth ─────────────────────────────────────────────────
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "maljan-api"
    jwt_audience: str = "maljan-clients"

    # SEC-JWT-ROTATION-01 (audit 2026-05-19) — minimal viable secret
    # rotation. New tokens carry the ``kid`` header set to ``jwt_key_id``.
    # During rotation, operators set ``jwt_previous_secret_key`` to the
    # old value for a grace period; ``decode_token`` accepts both. Once
    # every token with the old ``kid`` has expired, the previous secret
    # can be removed. TODO(audit-2026-05-19): wire a cron / admin
    # endpoint that automates the rotation cadence.
    jwt_key_id: str = "v1"
    jwt_previous_secret_key: SecretStr = SecretStr("")
    jwt_previous_key_id: str = "v0"

    # Secure flag on the HttpOnly refresh cookie. Left unset by default so it
    # can default to the inverse of ``debug`` (true outside debug, so the
    # cookie only ever crosses the wire over HTTPS); an operator may still
    # force it either way.
    cookie_secure: bool | None = Field(
        default=None,
        description="Secure flag on the refresh cookie; defaults to the inverse of debug.",
    )

    # ── Auth bypass (local development only) ─────────────────────
    # When True, the API skips all JWT decoding and pretends every
    # request is made by a fixed dev admin user. The user row is
    # auto-seeded on startup. NEVER enable this outside trusted local
    # environments — there is no rate limiting and every operation
    # (including admin-only ones) becomes unauthenticated.
    auth_disabled: bool = False
    auth_disabled_user_id: str = "00000000-0000-0000-0000-000000000001"
    auth_disabled_user_email: str = "dev@local"
    auth_disabled_user_full_name: str = "Dev User"

    # Wave 9 (2026-05-29): the 2026-05-29 Linux ELF audit found that
    # ``tempfile.NamedTemporaryFile`` defaults to the system temp dir
    # (``%LOCALAPPDATA%\Temp`` on Windows), which is the Defender quarantine
    # zone. Sample uploads + worker writes targeting that path were
    # silently quarantined, surfacing as "Storage service unavailable"
    # (HTTP 503). The fix: route every sample-handling tempfile through
    # a Defender-excluded directory created at API startup.
    upload_temp_dir: str = Field(default="data/uploads/.tmp")
    samples_dir: str = Field(
        default="data/samples",
        description="Host directory bind-mounted into the Ghidra container; the worker's "
        "per-job mirror lives in its .work subdirectory.",
    )

    @field_validator("jwt_secret_key")
    @classmethod
    def _enforce_jwt_secret(cls, value: SecretStr) -> SecretStr:
        """Fill in the in-repo test secret under pytest, and never refuse.

        Constructing settings is not the place a misconfigured deployment
        dies: a refusal raised here surfaces as a pydantic traceback from
        whichever import happened to build the singleton first, instead of
        the single ``bootstrap: ...`` line naming every problem at once.
        Every JWT refusal lives in ``app.bootstrap.validate_bootstrap``, and
        it reads the environment rather than this (possibly substituted)
        field, so the substitution below cannot satisfy a real check.
        """
        secret = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if not secret and _is_test_env():
            return SecretStr(TEST_JWT_SECRET)
        return value

    @model_validator(mode="after")
    def _cookie_secure_default(self) -> APISettings:
        if self.cookie_secure is None:
            self.cookie_secure = not self.debug
        return self

    def model_post_init(self, __context: object) -> None:
        # The auth-bypass flag is for interactive local development only;
        # never let it leak into the test suite, where it would mask real
        # 401 / 403 assertions. Force it off whenever pytest is active.
        #
        # This is the only thing construction decides. The refusals that used
        # to live here -- the auth bypass outside debug, the MinIO placeholder
        # outside debug -- are bootstrap problems now
        # (``app.bootstrap.validate_bootstrap``), so a misconfigured process
        # dies with one ``bootstrap: ...`` line listing every problem rather
        # than a pydantic traceback naming whichever one pydantic reached
        # first.
        if _is_test_env() and self.auth_disabled:
            object.__setattr__(self, "auth_disabled", False)


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

    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        # Forwarded (rather than raising) so tests can ``monkeypatch.setattr``
        # a single field on this module-level singleton — e.g.
        # ``monkeypatch.setattr(settings, "upload_temp_dir", tmp_path)`` —
        # without replacing the whole proxy and losing every other field.
        setattr(get_settings(), name, value)


# Legacy import surface — many modules still do ``from app.config import settings``.
settings = _LazyAPISettings()
