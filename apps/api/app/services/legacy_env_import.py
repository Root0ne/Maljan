"""One-shot import of the previous ``.env``-based configuration into the store.

Before the env-free configuration work, every application-shaped setting
(``mock_mode_allowed``, ``core.llm.provider``, ...) was read from the process
environment or a discovered ``.env`` file. It now comes from the
``runtime_settings`` store only (``app.services.settings_service``,
``maljan.core.settings_overrides.build_settings``). A deployment upgrading
from before that change still has its old configuration sitting in ``.env``
or the process environment, and it would otherwise silently fall back to the
catalog defaults on the first start.

``run_legacy_import`` bridges that gap exactly once: on the first start after
this change, for every catalog key whose legacy value differs from the
catalog default and that has no ``runtime_settings`` row yet, it writes one
(secrets encrypted with the same Fernet box ``SettingsService`` uses),
records one audit entry naming the keys (never the values), and writes the
``settings_meta`` marker that stops it from ever running again. A key that
already has a row is left untouched -- a value an operator saved through the
UI always wins over whatever the old environment said.

This module is the one place, besides the lazy ``APISettings`` singleton in
``app.config``, allowed to construct a bare ``Settings()``/``LegacyAPIView()``
-- see ``tests/unit/test_no_bare_settings_in_app.py``. Nothing else may read
either the process environment or a ``.env`` file for an application-shaped
setting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from maljan.core import settings_secrets as box
from maljan.core.config import Settings
from maljan.core.settings_overrides import build_settings, flatten_leaves
from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models import RuntimeSetting
from app.models.settings_meta import SettingsMeta
from app.services import audit
from app.services.settings_catalog_api import (
    API_DEFAULTS,
    catalog_index,
    validate_editable_api_value,
)

logger = get_logger("legacy_env_import")

MARKER_KEY = "legacy_env_import"


class LegacyAPIView(BaseSettings):
    """The application-shaped fields Task 2 removed from ``APISettings``.

    Same field names and defaults ``APISettings`` carried before the settings
    store became the only source of application configuration -- mirrored
    from ``API_DEFAULTS`` so the two tables cannot drift apart -- read with
    the same ``.env`` discovery the old ``APISettings`` used. Exists only for
    ``run_legacy_import`` below; nothing else may read it.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../../.env", "../../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    mock_mode_allowed: bool = API_DEFAULTS["mock_mode_allowed"]
    enrichment_enabled: bool = API_DEFAULTS["enrichment_enabled"]
    enrichment_max_lookups: int = API_DEFAULTS["enrichment_max_lookups"]
    virustotal_api_key: SecretStr = SecretStr(API_DEFAULTS["virustotal_api_key"])
    abuseipdb_api_key: SecretStr = SecretStr(API_DEFAULTS["abuseipdb_api_key"])
    rate_limit_enabled: bool = API_DEFAULTS["rate_limit_enabled"]
    rate_limit_requests: int = API_DEFAULTS["rate_limit_requests"]
    rate_limit_window_seconds: int = API_DEFAULTS["rate_limit_window_seconds"]
    rate_limit_whitelist: list[str] = Field(
        default_factory=lambda: list(API_DEFAULTS["rate_limit_whitelist"])
    )
    login_max_attempts: int = API_DEFAULTS["login_max_attempts"]
    login_lockout_seconds: int = API_DEFAULTS["login_lockout_seconds"]
    upload_max_bytes: int = API_DEFAULTS["upload_max_bytes"]
    upload_allowed_mime_types: list[str] = Field(
        default_factory=lambda: list(API_DEFAULTS["upload_allowed_mime_types"])
    )
    trusted_proxy_ips: list[str] = Field(
        default_factory=lambda: list(API_DEFAULTS["trusted_proxy_ips"])
    )
    qdrant_url: str = API_DEFAULTS["qdrant_url"]
    qdrant_collection: str = API_DEFAULTS["qdrant_collection"]
    qdrant_api_key: SecretStr = SecretStr(API_DEFAULTS["qdrant_api_key"])
    jwt_access_token_expire_minutes: int = API_DEFAULTS["jwt_access_token_expire_minutes"]
    jwt_refresh_token_expire_days: int = API_DEFAULTS["jwt_refresh_token_expire_days"]


def _unwrap(value: Any) -> Any:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else value


def _plain_leaf(model: Any, dotted_path: str) -> Any:
    """A core leaf's real value, secret or not -- walked by attribute, never dumped.

    ``model.model_dump(mode="json")`` (what ``flatten_leaves`` uses) masks
    every non-empty ``SecretStr`` to the literal ``"**********"``, which is
    fine for comparing "is this set" but useless as a value to import.
    """
    cursor: Any = model
    for part in dotted_path.split("."):
        cursor = getattr(cursor, part)
    return _unwrap(cursor)


async def run_legacy_import(
    db: AsyncSession,
    *,
    legacy_core: Settings | None = None,
    legacy_api: LegacyAPIView | None = None,
) -> list[str]:
    """Import the legacy environment configuration into the store, once.

    ``legacy_core``/``legacy_api`` are injection points for tests -- a real
    caller never passes them and gets the bare, environment- and
    ``.env``-reading constructors. A test must always pass its own instances,
    built against a temporary ``.env`` (``_env_file=tmp_path / ".env"``): the
    bare constructors here resolve the *real* project ``.env``, secrets
    included, from the process environment.
    """
    existing_marker = (
        await db.execute(select(SettingsMeta).where(SettingsMeta.key == MARKER_KEY))
    ).scalar_one_or_none()
    if existing_marker is not None:
        return []

    legacy_core = legacy_core if legacy_core is not None else Settings()
    legacy_api = legacy_api if legacy_api is not None else LegacyAPIView()

    index = catalog_index()
    default_core = build_settings({})
    core_paths = [e.path for e in index.values() if e.namespace == "core"]
    legacy_core_flat = flatten_leaves(legacy_core, core_paths)
    default_core_flat = flatten_leaves(default_core, core_paths)

    existing_keys = {row[0] for row in (await db.execute(select(RuntimeSetting.key))).all()}

    keys: list[str] = []
    skipped_invalid: list[str] = []
    rows: list[RuntimeSetting] = []

    for entry in index.values():
        if not entry.editable or entry.key in existing_keys:
            continue

        if entry.namespace == "core":
            if entry.secret:
                legacy_value = _plain_leaf(legacy_core, entry.path)
                default_value = _plain_leaf(default_core, entry.path)
            else:
                legacy_value = legacy_core_flat[entry.path]
                default_value = default_core_flat[entry.path]
        elif entry.namespace == "api" and entry.path in API_DEFAULTS:
            legacy_value = _unwrap(getattr(legacy_api, entry.path))
            default_value = _unwrap(API_DEFAULTS[entry.path])
        else:
            continue

        if legacy_value == default_value:
            continue

        if entry.namespace == "core":
            try:
                build_settings({entry.path: legacy_value})
            except ValidationError:
                skipped_invalid.append(entry.key)
                continue
        else:
            if validate_editable_api_value(entry, legacy_value) is not None:
                skipped_invalid.append(entry.key)
                continue

        stored = box.encrypt(str(legacy_value)) if entry.secret else legacy_value
        rows.append(
            RuntimeSetting(key=entry.key, value=stored, is_secret=entry.secret, updated_by=None)
        )
        keys.append(entry.key)

    for row in rows:
        db.add(row)
    db.add(
        SettingsMeta(
            key=MARKER_KEY,
            value={"imported": len(keys), "at": datetime.now(UTC).isoformat()},
        )
    )
    await db.commit()

    await audit.record(
        "settings.legacy_import",
        resource_type="settings",
        details={"keys": keys, "count": len(keys), "skipped_invalid": skipped_invalid},
    )
    return keys
