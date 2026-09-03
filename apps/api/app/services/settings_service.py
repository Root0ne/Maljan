"""Read and write runtime overrides, validating the merged models first."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from maljan.core import settings_secrets as box
from maljan.core.config import Settings
from maljan.core.settings_overrides import (
    build_settings,
    effective_source,
    flatten_leaves,
    nest,
    split_key,
)
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import observability
from app.config import APISettings
from app.config import settings as api_settings
from app.database import async_session_factory
from app.models import AuditLog, RuntimeSetting
from app.services.settings_catalog_api import _masked, catalog_index

logger = logging.getLogger(__name__)


class SettingsValidationError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


@dataclass
class ValueInfo:
    value: Any | None
    is_set: bool | None
    hint: str | None
    source: str
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None


@dataclass
class SaveResult:
    applied: list[str] = field(default_factory=list)
    applies: dict[str, int] = field(default_factory=dict)


def _loc_to_key(ns: str, loc: tuple[Any, ...]) -> str:
    return f"{ns}." + ".".join(str(p) for p in loc if not isinstance(p, int))


class SettingsService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ---- reading -------------------------------------------------------
    async def _rows(self) -> list[RuntimeSetting]:
        res = await self.db.execute(select(RuntimeSetting))
        return list(res.scalars().all())

    async def load_overrides(self) -> dict[str, Any]:
        """Full keys -> plain values; secrets decrypted, or dropped if they cannot be."""
        out: dict[str, Any] = {}
        for row in await self._rows():
            if row.is_secret:
                try:
                    out[row.key] = box.decrypt(str(row.value))
                except box.SecretsUnavailable:
                    logger.warning(
                        "Stored override for %s cannot be decrypted (encryption key "
                        "changed?); the environment value stays in effect.",
                        row.key,
                    )
                    continue
            else:
                out[row.key] = row.value
        return out

    async def values(self) -> dict[str, ValueInfo]:
        index = catalog_index()
        rows = {r.key: r for r in await self._rows()}
        env_core = Settings()
        core_paths = [e.path for e in index.values() if e.namespace == "core"]
        core_env = flatten_leaves(env_core, core_paths)
        out: dict[str, ValueInfo] = {}
        for key, entry in index.items():
            row = rows.get(key)
            if entry.namespace == "core":
                env_value = core_env[entry.path]
            else:
                raw = getattr(api_settings, entry.path)
                env_value = raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            if entry.secret:
                if row is not None:
                    # A row exists: the secret is set, full stop -- even if it
                    # cannot be decrypted right now (missing/rotated/wrong
                    # SETTINGS_ENCRYPTION_KEY, or a corrupted value). is_set
                    # must not depend on whether decryption happened to work.
                    try:
                        plain = box.decrypt(str(row.value))
                    except box.SecretsUnavailable:
                        plain = ""
                    out[key] = ValueInfo(
                        None,
                        True,
                        box.hint(plain) if plain else None,
                        "ui",
                        row.updated_at,
                        row.updated_by,
                    )
                else:
                    # No row: whatever the secret's effective value is comes
                    # straight from the environment. For a core secret,
                    # `core_env` was built from `Settings().model_dump(mode=
                    # "json")`, and pydantic's default SecretStr JSON dump
                    # masks any non-empty secret to the literal "**********" --
                    # useless for a hint. Read the live Settings instance by
                    # attribute instead and unwrap SecretStr directly.
                    if entry.namespace == "core":
                        obj: Any = env_core
                        for part in entry.path.split("."):
                            obj = getattr(obj, part)
                        plain = (
                            obj.get_secret_value()
                            if hasattr(obj, "get_secret_value")
                            else (obj or "")
                        )
                    else:
                        plain = env_value or ""
                    src = effective_source(
                        overridden=False, env_value=bool(plain), default_value=False
                    )
                    out[key] = ValueInfo(
                        None,
                        bool(plain),
                        box.hint(plain) if plain else None,
                        src,
                        None,
                        None,
                    )
                continue
            if row is not None:
                out[key] = ValueInfo(row.value, None, None, "ui", row.updated_at, row.updated_by)
            else:
                # Ruling: a read-only (API_READONLY) entry shows its live
                # environment value, not the code default -- an operator
                # needs to see what is actually in effect. URL-shaped values
                # go through the same credential mask the catalog's default
                # uses, so a password never reaches the response either way.
                shown = env_value if entry.editable else _masked(entry.path, env_value)
                src = effective_source(
                    overridden=False, env_value=env_value, default_value=entry.default
                )
                out[key] = ValueInfo(shown, None, None, src)
        return out

    # ---- validation ----------------------------------------------------
    def check_keys(self, changes: dict[str, Any]) -> None:
        index = catalog_index()
        errors = {}
        for key in changes:
            entry = index.get(key)
            if entry is None:
                errors[key] = "unknown setting"
            elif not entry.editable:
                errors[key] = entry.reason or "read-only"
            elif entry.secret and changes[key] is not None and not box.is_available():
                errors[key] = "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
        if errors:
            raise SettingsValidationError(errors)

    def validate(self, merged_core: dict[str, Any], merged_api: dict[str, Any]) -> None:
        errors: dict[str, str] = {}
        try:
            build_settings(merged_core)
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("core", err["loc"])] = err["msg"]
        try:
            APISettings(**nest(merged_api))
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("api", err["loc"])] = err["msg"]
        if errors:
            raise SettingsValidationError(errors)

    # ---- writing -------------------------------------------------------
    async def save(
        self, changes: dict[str, Any], *, user_id: uuid.UUID | None, ip: str | None
    ) -> SaveResult:
        self.check_keys(changes)
        index = catalog_index()
        current = await self.load_overrides()
        merged = {**current}
        for key, value in changes.items():
            # ``null`` means "drop the override" for every key, secrets
            # included; an admin cannot pin a nullable field to None against
            # a non-null environment value (the spec defines null only for
            # clearing).
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        core = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("core.")}
        api = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("api.")}
        self.validate(core, api)

        rows = {r.key: r for r in await self._rows()}
        before: dict[str, Any] = {}
        after: dict[str, Any] = {}
        result = SaveResult()
        for key, value in changes.items():
            entry = index[key]
            existing = rows.get(key)
            if entry.secret:
                before[key] = "set" if existing else "unset"
            else:
                before[key] = existing.value if existing else None
            if value is None:
                if existing is not None:
                    await self.db.delete(existing)
                after[key] = "unset" if entry.secret else None
            else:
                stored = box.encrypt(str(value)) if entry.secret else value
                if existing is None:
                    self.db.add(
                        RuntimeSetting(
                            key=key, value=stored, is_secret=entry.secret, updated_by=user_id
                        )
                    )
                else:
                    existing.value = stored
                    existing.is_secret = entry.secret
                    existing.updated_by = user_id
                after[key] = "set" if entry.secret else value
            result.applied.append(key)
            result.applies[entry.applies] = result.applies.get(entry.applies, 0) + 1
        await self.db.commit()
        details = {"changed": list(changes), "before": before, "after": after}
        await _audit(user_id, "settings.update", details, ip)
        return result

    async def reset(
        self, keys: list[str], *, user_id: uuid.UUID | None, ip: str | None
    ) -> list[str]:
        rows = {r.key: r for r in await self._rows()}
        removed = []
        for key in keys:
            if key in rows:
                await self.db.delete(rows[key])
                removed.append(key)
        await self.db.commit()
        if removed:
            await _audit(user_id, "settings.reset", {"keys": removed}, ip)
        return removed


async def _audit(
    user_id: uuid.UUID | None, action: str, details: dict[str, Any], ip: str | None
) -> None:
    """Independent transaction, same reasoning as auth._audit; best effort."""
    try:
        async with async_session_factory() as s:
            s.add(
                AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type="settings",
                    resource_id=None,
                    details=details,
                    ip_address=ip or None,
                )
            )
            await s.commit()
    except Exception as exc:  # noqa: BLE001 - audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Audit write failed (action=%s): %s", action, type(exc).__name__)


async def load_core_overrides(db: AsyncSession) -> dict[str, Any]:
    """For the worker: core paths without the namespace prefix."""
    overrides = await SettingsService(db).load_overrides()
    return {split_key(k)[1]: v for k, v in overrides.items() if k.startswith("core.")}
