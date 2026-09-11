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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models import RuntimeSetting
from app.models.settings_meta import SettingsMeta
from app.services import audit
from app.services.frontier_arms import ARMS_KEY, arm_key_key, split_arm_secrets
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


def _arms_with_keys(model: Settings) -> dict[str, Any]:
    """The frontier arms as JSON, with each arm's real ``api_key`` in place.

    ``flatten_leaves`` dumps the map through ``model_dump(mode="json")``, which
    masks every non-empty ``SecretStr`` -- fine for "is this set", useless as a
    value to import, and actively wrong to store (walkthrough finding W3: the
    masks were what the old import left behind, beside real keys in clear).
    The keys read here are split back out by ``split_arm_secrets`` and stored
    encrypted, one row per arm.
    """
    out: dict[str, Any] = {}
    for name, arm in (model.llm.frontier.arms or {}).items():
        entry = arm.model_dump(mode="json")
        entry["api_key"] = _unwrap(arm.api_key) if arm.api_key is not None else None
        out[name] = entry
    return out


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
            elif entry.key == ARMS_KEY:
                legacy_value = _arms_with_keys(legacy_core)
                default_value = _arms_with_keys(default_core)
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

        if entry.key == ARMS_KEY:
            # Per-arm keys never enter the composite row; each becomes its own
            # encrypted row, exactly as an arm saved from the UI does.
            legacy_value, arm_keys = split_arm_secrets(legacy_value)
            for arm_name, api_key in arm_keys.items():
                row_key = arm_key_key(arm_name)
                if not api_key or row_key in existing_keys:
                    continue
                rows.append(
                    RuntimeSetting(
                        key=row_key, value=box.encrypt(api_key), is_secret=True, updated_by=None
                    )
                )
                keys.append(row_key)

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
    try:
        await db.commit()
    except IntegrityError:
        # Two replicas raced the same first start; the marker's primary key
        # rejects the loser's insert and its whole transaction (rows
        # included) rolls back with it -- the winner already wrote the rows,
        # the marker, and its own audit entry, so this is a benign outcome,
        # not a failure.
        await db.rollback()
        logger.info("Legacy import marker already exists (another replica imported first).")
        return []

    if keys or skipped_invalid:
        await audit.record(
            "settings.legacy_import",
            resource_type="settings",
            details={"keys": keys, "count": len(keys), "skipped_invalid": skipped_invalid},
        )
    return keys


async def repair_frontier_arm_keys(db: AsyncSession) -> int:
    """Move any clear-text arm API key out of the composite row, once.

    Walkthrough finding W3: the ``core.llm.frontier.arms`` row an earlier
    import wrote is plain JSONB with each arm's ``api_key`` inside it --
    ``is_secret=false``, never through the Fernet box, sitting in the database
    in clear beside values the UI echoes back. This moves every such key into
    its own encrypted ``core.llm.frontier.arms.<arm>.api_key`` row and rewrites
    the composite without them.

    Idempotent: a composite that carries no ``api_key`` field is left alone, so
    a second start does nothing. An arm that already has its own row keeps it
    (whatever the operator saved wins). Only the count is logged, never a key.
    """
    row = (
        await db.execute(select(RuntimeSetting).where(RuntimeSetting.key == ARMS_KEY))
    ).scalar_one_or_none()
    if row is None or not isinstance(row.value, dict):
        return 0

    cleaned, arm_keys = split_arm_secrets(row.value)
    if cleaned == row.value:
        return 0

    existing_keys = {r[0] for r in (await db.execute(select(RuntimeSetting.key))).all()}
    to_store = {
        arm_key_key(name): api_key
        for name, api_key in arm_keys.items()
        if api_key and arm_key_key(name) not in existing_keys
    }
    if to_store and not box.is_available():
        # Rewriting the composite now would destroy the only copy of a key
        # that cannot yet be encrypted; leave everything as it is and say so.
        logger.warning(
            "Frontier arm API keys are stored in clear but SETTINGS_ENCRYPTION_KEY "
            "is unusable; the repair will run again on the next start."
        )
        return 0

    for key, api_key in to_store.items():
        db.add(RuntimeSetting(key=key, value=box.encrypt(str(api_key)), is_secret=True))
    row.value = cleaned
    await db.commit()
    logger.info("Frontier arm API keys moved into encrypted rows: %d", len(to_store))
    return len(to_store)
