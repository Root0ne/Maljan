"""Maljan API — Application configuration.

Loads from environment variables with sensible defaults for development.
All settings can be overridden via .env or OS environment.

Security-sensitive defaults (JWT secret, MinIO credentials) refuse to boot
the API in non-debug mode unless the operator provided real values.
"""

from __future__ import annotations

import ipaddress
from typing import Any

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
    # Echo every SQL statement to the log. Deliberately independent of ``debug``
    # (audit 2026-07-26, Ö6): with DEBUG=true this drowned the worker/API logs in
    # duplicated SQL and made pipeline stages impossible to follow. Enable only
    # when actively debugging queries: ``SQL_ECHO=true``.
    sql_echo: bool = False

    # ── Pipeline mock-mode gate ──────────────────────────────────
    # ``MALJAN_MOCK_MODE=true`` alone no longer flips the pipeline
    # into mock mode — the operator must ALSO set this gate to True
    # (or pass ``config.mock_mode=true`` on the job itself). Stops a
    # leaked env var from silently disabling real LLM + sandbox calls.
    mock_mode_allowed: bool = False
    cors_origins: list[str] = Field(default=["http://localhost:3000", "http://127.0.0.1:3000"])
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    # "X-API-Key" is required for the API-key auth path (audit 2026-07-26, K2);
    # without it the browser preflight strips the header and keys silently fail.
    cors_allow_headers: list[str] = Field(
        default=["Authorization", "Content-Type", "X-Correlation-Id", "X-API-Key"]
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

    # ── Ghidra MCP container delivery (Wave 6 GHIDRA-DELIVERY-01) ───
    # Worker mirrors each MinIO-downloaded sample into ``data/samples/``
    # on the host so the Ghidra MCP container can read it through its
    # bind mount. ``ghidra_container_samples_path`` is the path at which
    # the Ghidra container sees that directory — it must match the
    # right-hand side of the ``../data/samples:/data/samples`` mount in
    # ``docker/docker-compose.yml``. Override via env when relocating
    # the mount or running Ghidra outside Docker.
    ghidra_container_samples_path: str = "/data/samples"

    # ── JWT Auth ─────────────────────────────────────────────────
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
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

    # Login throttle (per-account)
    login_max_attempts: int = 10
    login_lockout_seconds: int = 300

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

    # ── Qdrant (passed through to maljan-core) ───────────────────
    qdrant_url: str = "http://127.0.0.1:6333"
    qdrant_collection: str = "maljan_ltm"

    # ── Threat-intel enrichment (Faz 6) ──────────────────────────
    # API keys are optional. When empty the enrichment task skips the
    # corresponding provider and leaves reputation fields as ``null``.
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    enrichment_max_lookups: int = 25
    enrichment_enabled: bool = True

    # ── Rate Limiting ────────────────────────────────────────────
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_requests: int = Field(default=100)
    rate_limit_window_seconds: int = Field(default=60)
    rate_limit_whitelist: list[str] = Field(default=["/health"])

    # ── File upload ──────────────────────────────────────────────
    upload_max_bytes: int = Field(default=100 * 1024 * 1024)  # 100 MB
    upload_allowed_mime_types: list[str] = Field(
        # The list mirrors every analyzer package shipped by CAPEv2 under
        # ``external/CAPEv2/analyzer/{windows,linux}/modules/packages/`` so
        # any file the sandbox can detonate also clears the API gate.
        #
        # Synonym handling: ``filetype`` (magic-byte) and libmagic disagree
        # on some entries — ELF is ``x-elf`` vs ``x-executable``; PE is
        # ``x-msdownload`` vs ``vnd.microsoft.portable-executable``. Every
        # documented synonym is listed. Scripts (.vbs/.ps1/.bat/.py/.js)
        # typically come back as ``text/plain`` or ``None`` from filetype;
        # those still pass because samples.py only enforces the allow-list
        # when a MIME was actually detected.
        default=[
            # ── Generic / catch-all ─────────────────────────────────
            "application/octet-stream",
            # ── Windows PE family (exe / dll / service / regsvr / msbuild) ──
            "application/x-dosexec",
            "application/x-msdownload",
            "application/vnd.microsoft.portable-executable",
            # ── Windows installers (msi / msix / nsis) ──────────────
            "application/x-ms-installer",
            "application/x-msi",
            "application/vnd.ms-msi",
            # ── *nix executables (ELF / Mach-O / shared libs) ───────
            "application/x-mach-binary",
            "application/x-elf",
            "application/x-executable",
            "application/x-sharedlib",
            "application/x-pie-executable",
            # ── Android (APK) ───────────────────────────────────────
            "application/vnd.android.package-archive",
            # ── Archives (CAPE ``zip`` / ``rar`` / ``jar`` / ``archive``) ──
            "application/zip",
            "application/x-zip-compressed",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/vnd.rar",
            "application/gzip",
            "application/x-gzip",
            "application/x-bzip2",
            "application/x-xz",
            "application/x-lzma",
            "application/x-tar",
            "application/x-iso9660-image",
            "application/java-archive",
            # ── Linux package formats (CAPE Linux ``deb`` package) ──
            "application/x-deb",
            "application/vnd.debian.binary-package",
            # ── PDF (CAPE ``pdf`` package) ──────────────────────────
            "application/pdf",
            # ── Microsoft Office — legacy binary formats ────────────
            "application/msword",
            "application/vnd.ms-word",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/vnd.ms-publisher",
            "application/x-mspublisher",
            "application/vnd.ms-access",
            "application/x-msaccess",
            "application/onenote",
            "application/msonenote",
            "application/vnd.ms-xpsdocument",
            # ── Office Open XML (.docx / .xlsx / .pptx + macro variants) ──
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-word.document.macroEnabled.12",
            "application/vnd.ms-excel.sheet.macroEnabled.12",
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            "application/vnd.ms-word.template.macroEnabled.12",
            "application/vnd.ms-excel.template.macroEnabled.12",
            # ── Rich Text + Hangul + Ichitaro ───────────────────────
            "application/rtf",
            "text/rtf",
            "application/x-hwp",
            "application/haansofthwp",
            "application/x-ichitaro",
            # ── Mail (CAPE ``eml`` / ``msg`` / ``mht``) ─────────────
            "message/rfc822",
            "application/vnd.ms-outlook",
            "application/x-mimearchive",
            "multipart/related",
            # ── Browser / web (CAPE ``chrome`` / ``ie`` / ``crx``) ──
            "text/html",
            "application/xhtml+xml",
            "application/xml",
            "text/xml",
            "application/x-chrome-extension",
            # ── Shortcuts, HTA, registry, control panel ─────────────
            "application/x-ms-shortcut",
            "application/x-mslnk",
            "application/hta",
            "application/x-hta",
            "application/x-registry",
            "text/x-ms-regedit",
            "application/x-cpl",
            "application/x-rdp",
            # ── Help, Flash, Java applet ────────────────────────────
            "application/vnd.ms-htmlhelp",
            "application/x-chm",
            "application/x-shockwave-flash",
            "application/x-java-applet",
            # ── Scripts that DO carry a magic-byte MIME ─────────────
            # (the .vbs/.ps1/.bat/.py/.js majority come back None and
            # pass via samples.py's "detected_mime is None" branch)
            "text/x-shellscript",
            "application/x-shellscript",
            "text/x-python",
            "application/x-python",
            "text/x-perl",
            "application/x-perl",
            "application/javascript",
            "application/x-javascript",
            "text/javascript",
            "application/x-powershell",
            "text/x-powershell",
            "application/x-vbscript",
            "text/vbscript",
            "application/x-bat",
            "text/x-msdos-batch",
            "application/x-msdos-program",
        ]
    )
    # Wave 9 (2026-05-29): the 2026-05-29 Linux ELF audit found that
    # ``tempfile.NamedTemporaryFile`` defaults to the system temp dir
    # (``%LOCALAPPDATA%\Temp`` on Windows), which is the Defender quarantine
    # zone. Sample uploads + worker writes targeting that path were
    # silently quarantined, surfacing as "Storage service unavailable"
    # (HTTP 503). The fix: route every sample-handling tempfile through
    # a Defender-excluded directory created at API startup.
    upload_temp_dir: str = Field(default="data/uploads/.tmp")

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

    @field_validator("trusted_proxy_ips")
    @classmethod
    def _proxies_are_networks(cls, value: list[str]) -> list[str]:
        for entry in value:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"trusted_proxy_ips entry {entry!r} is not an IP address or CIDR network"
                ) from exc
        return value

    def model_post_init(self, __context: object) -> None:
        # The auth-bypass flag is for interactive local development only;
        # never let it leak into the test suite, where it would mask real
        # 401 / 403 assertions. Force it off whenever pytest is active.
        if _is_test_env() and self.auth_disabled:
            object.__setattr__(self, "auth_disabled", False)

        # Skip the strict placeholder check when pytest is running or when
        # the caller has explicitly opted out (e.g. local Docker compose
        # with the default minioadmin bootstrap). Production deployments
        # MUST set DEBUG=False *and* a real MinIO secret.
        if self.debug or _is_test_env():
            return

        # Same contract as the MinIO placeholder below, and it was the one
        # missing: ``auth_disabled`` makes ``get_current_user`` return the dev
        # admin for *every* request without inspecting the token at all
        # (deps.py). The pytest guard above is not a production guard — a
        # ``.env`` carried from a dev box to a real deployment would serve an
        # unauthenticated admin API and nothing would say so.
        if self.auth_disabled:
            raise ValueError(
                "AUTH_DISABLED is set with DEBUG=False. The auth bypass serves "
                "every request as the dev admin user and is for local "
                "development only. Unset AUTH_DISABLED before running in "
                "non-debug mode."
            )

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

    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)


# Legacy import surface — many modules still do ``from app.config import settings``.
settings = _LazyAPISettings()
