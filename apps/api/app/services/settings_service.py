"""Read and write runtime overrides, validating the merged models first."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from maljan.core import settings_secrets as box
from maljan.core.config import Settings
from maljan.core.settings_overrides import (
    build_settings,
    effective_source,
    flatten_leaves,
    split_key,
)
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as api_settings
from app.models import RuntimeSetting
from app.services.frontier_arms import (
    ARMS_KEY,
    arm_key_key,
    masked_arms,
    merge_arm_secrets,
    split_arm_secrets,
)
from app.services.server_map import (
    SERVER_MAP_KEY,
    TOKEN_MASK,
    ServerMapError,
    merge_server_secrets,
    server_token_key,
    split_server_secrets,
)
from app.services.settings_catalog_api import (
    API_DEFAULTS,
    _masked,
    catalog_index,
    validate_editable_api_value,
)

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


# The composite catalog leaves whose nested credential is stored as its own
# runtime-keyed row, and the suffix those rows carry. Resetting the composite
# resets them; ``save`` prunes the ones whose name left the map.
_COMPOSITE_SECRET_SUFFIX = {SERVER_MAP_KEY: ".auth_token", ARMS_KEY: ".api_key"}


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
        """Full keys -> plain values; secrets decrypted, or dropped if they cannot be.

        The per-server MCP tokens are stored as their own ``is_secret`` rows
        (see ``server_map``); they are merged back into the ``core.mcp.servers``
        map here, so every caller downstream — the worker's ``Settings``, the
        probes, ``runtime_config`` — sees one map with the tokens in place and
        never has to know the storage was split. The per-arm frontier API keys
        (see ``frontier_arms``) are stored and merged the same way.
        """
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
        return merge_arm_secrets(merge_server_secrets(out))

    async def values(self) -> dict[str, ValueInfo]:
        index = catalog_index()
        rows = {r.key: r for r in await self._rows()}
        core_defaults = build_settings({})
        core_paths = [e.path for e in index.values() if e.namespace == "core"]
        core_defaults_by_path = flatten_leaves(core_defaults, core_paths)
        out: dict[str, ValueInfo] = {}
        for key, entry in index.items():
            row = rows.get(key)
            if entry.namespace == "core":
                default_value = core_defaults_by_path[entry.path]
            elif entry.path in API_DEFAULTS:
                # Editable api.* leaves no longer live on APISettings
                # (and so no longer come from the environment) -- their
                # fallback is the catalog default table instead.
                raw = API_DEFAULTS[entry.path]
                default_value = raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            else:
                raw = getattr(api_settings, entry.path)
                default_value = raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            if entry.key == SERVER_MAP_KEY:
                stored_map: Any = row.value if row is not None else default_value
                shown = self._masked_server_map(
                    dict(stored_map or {}), core_defaults.mcp.servers, rows
                )
                src = "ui" if row is not None else effective_source(overridden=False)
                out[key] = ValueInfo(
                    shown,
                    None,
                    None,
                    src,
                    row.updated_at if row is not None else None,
                    row.updated_by if row is not None else None,
                )
                continue
            if entry.key == ARMS_KEY:
                # Same split as the server map: the composite row never holds a
                # key, each set one is its own encrypted row, and what the
                # editor shows is the mask -- which ``split_arm_secrets`` reads
                # back as "leave the row alone".
                stored_arms: Any = row.value if row is not None else default_value
                out[key] = ValueInfo(
                    masked_arms(dict(stored_arms or {}), rows),
                    None,
                    None,
                    "ui" if row is not None else effective_source(overridden=False),
                    row.updated_at if row is not None else None,
                    row.updated_by if row is not None else None,
                )
                continue
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
                    # from the model default. For a core secret,
                    # `core_defaults` was built from `build_settings({})
                    # .model_dump(mode="json")`, and pydantic's default
                    # SecretStr JSON dump masks any non-empty secret to the
                    # literal "**********" -- useless for a hint. Read the
                    # live Settings instance by attribute instead and unwrap
                    # SecretStr directly.
                    if entry.namespace == "core":
                        obj: Any = core_defaults
                        for part in entry.path.split("."):
                            obj = getattr(obj, part)
                        plain = (
                            obj.get_secret_value()
                            if hasattr(obj, "get_secret_value")
                            else (obj or "")
                        )
                    else:
                        plain = default_value or ""
                    src = effective_source(overridden=False)
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
                # A read-only (API_READONLY) entry shows what is actually in
                # effect: for a core leaf, the model default resolved through
                # build_settings({}) above; for an api.* leaf, its live
                # bootstrap value (``getattr(api_settings, entry.path)`` --
                # APISettings is still process-environment-only by design).
                # URL-shaped values go through the same credential
                # mask the catalog's default uses, so a password never
                # reaches the response either way.
                shown = default_value if entry.editable else _masked(entry.path, default_value)
                src = effective_source(overridden=False)
                out[key] = ValueInfo(shown, None, None, src)
        return out

    def _masked_server_map(
        self, stored_map: dict[str, Any], default_servers: dict[str, Any], rows: dict[str, Any]
    ) -> dict[str, Any]:
        """The map as the UI may see it: every token a mask, never a value.

        ``auth_token_source`` rides along beside it for the same reason every
        other row carries ``source``: "set from the UI" and "the built-in
        default" are different facts, and an operator deciding whether to
        type a new token needs to know which one they are looking at. The
        editor sends the mask straight back for an unchanged field, and
        ``split_server_secrets`` reads that as "leave the row alone".
        """
        out: dict[str, Any] = {}
        for name, entry in stored_map.items():
            shown = dict(entry)
            if server_token_key(name) in rows:
                shown["auth_token"], shown["auth_token_source"] = TOKEN_MASK, "ui"
            else:
                # No built-in server ships with a non-empty default
                # auth_token today, so has_default_token is always False in
                # practice and this always shows "" -- kept as a real check
                # rather than a hardcoded "" so a future built-in server that
                # does ship one still masks correctly instead of silently
                # showing empty.
                default_entry = default_servers.get(name)
                has_default_token = bool(
                    default_entry is not None and default_entry.auth_token.get_secret_value()
                )
                shown["auth_token"] = TOKEN_MASK if has_default_token else ""
                shown["auth_token_source"] = "default"
            out[name] = shown
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
        if errors:
            raise SettingsValidationError(errors)

    def validate(self, merged_core: dict[str, Any], merged_api: dict[str, Any]) -> None:
        errors: dict[str, str] = {}
        try:
            build_settings(merged_core)
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("core", err["loc"])] = err["msg"]
        # No ``APISettings(**nest(merged_api))`` here: ``extra="ignore"`` drops
        # everything a catalog ``api.*`` key could supply (every one of them
        # moved off the model), so the call could only ever have failed
        # on the process environment -- which bootstrap already validated.
        # Each editable api leaf is checked against its catalog entry below.
        index = catalog_index()
        for name, value in merged_api.items():
            if name not in API_DEFAULTS:
                continue
            entry = index.get(f"api.{name}")
            if entry is None:
                continue
            msg = validate_editable_api_value(entry, value)
            if msg:
                errors[f"api.{name}"] = msg
        if errors:
            raise SettingsValidationError(errors)

    # ---- writing -------------------------------------------------------
    async def save(
        self, changes: dict[str, Any], *, user_id: uuid.UUID | None, ip: str | None
    ) -> SaveResult:
        self.check_keys(changes)
        index = catalog_index()
        current = await self.load_overrides()
        # An import document carries the mask wherever a secret was omitted.
        # For a secret leaf the mask means "unchanged", exactly as it does in
        # a composite editor -- never a credential whose literal characters
        # are ten asterisks.
        changes = {k: v for k, v in changes.items() if not (index[k].secret and v == TOKEN_MASK)}
        tokens: dict[str, str | None] = {}
        server_map_kept: set[str] | None = None
        if SERVER_MAP_KEY in changes:
            if changes[SERVER_MAP_KEY] is None:
                # An explicit null drops the override like every other key
                # (handled below); every per-server token row goes with it --
                # ``split_server_secrets`` never runs, there is no map left to
                # validate against.
                server_map_kept = set()
            else:
                # The map is one non-secret row and the tokens are not in it. Split
                # first so neither validation nor the audit trail ever sees one.
                # A malformed map is reported here, before the generic pydantic
                # validation below, with one message per offending key.
                stored_map = current.get(SERVER_MAP_KEY)
                try:
                    changes[SERVER_MAP_KEY], tokens = split_server_secrets(
                        changes[SERVER_MAP_KEY],
                        stored=stored_map if isinstance(stored_map, dict) else None,
                        stored_settings=current,
                    )
                except ServerMapError as exc:
                    raise SettingsValidationError(
                        {f"{SERVER_MAP_KEY}.{k}": v for k, v in exc.errors.items()}
                    ) from exc
                unstorable = [
                    server_token_key(name)
                    for name, token in tokens.items()
                    if token and not box.is_available()
                ]
                if unstorable:
                    raise SettingsValidationError(
                        {
                            key: "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
                            for key in unstorable
                        }
                    )
                server_map_kept = set(changes[SERVER_MAP_KEY])

        arm_keys: dict[str, str | None] = {}
        arms_kept: set[str] | None = None
        if ARMS_KEY in changes:
            if changes[ARMS_KEY] is None:
                # An explicit null drops the override like every other key
                # (handled below); every per-arm key row goes with it.
                arms_kept = set()
            else:
                stored_arms_map = current.get(ARMS_KEY)
                changes[ARMS_KEY], arm_keys = split_arm_secrets(
                    changes[ARMS_KEY],
                    stored=stored_arms_map if isinstance(stored_arms_map, dict) else None,
                )
                unstorable = [
                    arm_key_key(name)
                    for name, api_key in arm_keys.items()
                    if api_key and not box.is_available()
                ]
                if unstorable:
                    raise SettingsValidationError(
                        {
                            key: "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
                            for key in unstorable
                        }
                    )
                if isinstance(changes[ARMS_KEY], dict):
                    arms_kept = set(changes[ARMS_KEY])

        from app.services.agent_map import (
            AGENT_DEFINITIONS_KEY,
            AGENT_PROFILE_KEY,
            AGENT_PROFILES_KEY,
            AgentMapError,
            validate_agent_map,
        )

        if {AGENT_DEFINITIONS_KEY, AGENT_PROFILES_KEY, AGENT_PROFILE_KEY} & set(changes):
            # Per-key messages, so the two composite editors can put each error
            # on the card that caused it — the same reason the server map has
            # its own validation module.
            try:
                changes.update(validate_agent_map(changes, current))
            except AgentMapError as exc:
                raise SettingsValidationError(dict(exc.errors)) from exc
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
        if server_map_kept is not None:
            await self._save_server_tokens(tokens, server_map_kept)
        if arms_kept is not None:
            await self._save_runtime_secrets(
                arm_keys, arms_kept, prefix=f"{ARMS_KEY}.", suffix=".api_key", key_of=arm_key_key
            )
        await self.db.commit()
        details = {"changed": list(changes), "before": before, "after": after}
        await _audit(user_id, "settings.update", details, ip)
        return result

    async def _save_server_tokens(self, tokens: dict[str, str | None], kept: set[str]) -> None:
        """One encrypted row per server that has a token, and none for one that does not."""
        await self._save_runtime_secrets(
            tokens,
            kept,
            prefix=f"{SERVER_MAP_KEY}.",
            suffix=".auth_token",
            key_of=server_token_key,
        )

    async def _save_runtime_secrets(
        self,
        secrets: dict[str, str | None],
        kept: set[str],
        *,
        prefix: str,
        suffix: str,
        key_of: Callable[[str], str],
    ) -> None:
        """The encrypted rows behind one composite map, written and pruned.

        Runtime-keyed rows: the catalog is a static list and cannot hold a name
        an operator invents, so these are written here rather than through the
        catalog-driven path in ``save``. They are otherwise ordinary secret
        rows — same Fernet box, same ``is_secret`` flag, same decrypt-or-drop
        behaviour in ``load_overrides`` — so a rotated key degrades them the
        same way it degrades every other secret.

        ``kept`` is the set of names the new map still holds; a row for a name
        that is gone is deleted with it, so a re-created server or frontier arm
        never inherits a predecessor's credential.
        """
        rows = {r.key: r for r in await self._rows()}
        for key, row in rows.items():
            if not (key.startswith(prefix) and key.endswith(suffix)):
                continue
            if key[len(prefix) : -len(suffix)] not in kept:
                await self.db.delete(row)
        for name, secret in secrets.items():
            key = key_of(name)
            existing = rows.get(key)
            if not secret:
                if existing is not None:
                    await self.db.delete(existing)
                continue
            stored = box.encrypt(secret)
            if existing is None:
                self.db.add(RuntimeSetting(key=key, value=stored, is_secret=True))
            else:
                existing.value = stored
                existing.is_secret = True

    async def reset(
        self, keys: list[str], *, user_id: uuid.UUID | None, ip: str | None
    ) -> list[str]:
        """Drop the stored rows for ``keys``, credentials nested in them included.

        Resetting a composite takes its per-name secret rows with it. Leaving
        them behind is what ``_save_runtime_secrets`` already refuses to do for
        a name that leaves the map, and for the same reason: a re-created
        server or frontier arm of the same name would have a predecessor's
        credential folded straight back in by ``merge_server_secrets`` /
        ``merge_arm_secrets``, and ``values()`` would show it as set.
        """
        rows = {r.key: r for r in await self._rows()}
        targets = dict.fromkeys(keys)
        for key in keys:
            suffix = _COMPOSITE_SECRET_SUFFIX.get(key)
            if suffix is None:
                continue
            prefix = f"{key}."
            targets.update(
                dict.fromkeys(k for k in rows if k.startswith(prefix) and k.endswith(suffix))
            )
        removed = []
        for key in targets:
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
    """Independent transaction, same reasoning as auth._audit; best effort.

    The write itself is ``services.audit.record``, shared with auth and with
    the sample, job and sandbox-report endpoints.
    """
    from app.services import audit

    await audit.record(action, resource_type="settings", user_id=user_id, details=details, ip=ip)


async def load_core_overrides(db: AsyncSession) -> dict[str, Any]:
    """For the worker: core paths without the namespace prefix."""
    overrides = await SettingsService(db).load_overrides()
    return {split_key(k)[1]: v for k, v in overrides.items() if k.startswith("core.")}


class _CoreSettingsCache:
    """Short-TTL cache of ``build_settings(await load_core_overrides(db))``.

    Mirrors ``app.runtime_config.RuntimeConfig``'s TTL cache, but for the one
    whole core ``Settings`` object a request-path handler needs (the sandbox
    upload size/format gates today -- see ``effective_core_settings``) rather
    than a single ``api.*`` knob. A request handler must never build this from
    the store on every call: that would be a DB round trip per request for a
    value that changes only when an admin saves a setting.
    """

    def __init__(
        self, ttl_seconds: float = 5.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._cached: Settings | None = None
        self._loaded_at: float | None = None

    async def get(self, db: AsyncSession) -> Settings:
        now = self._clock()
        if (
            self._cached is not None
            and self._loaded_at is not None
            and now - self._loaded_at < self._ttl
        ):
            return self._cached
        self._cached = build_settings(await load_core_overrides(db))
        self._loaded_at = now
        return self._cached

    def invalidate(self) -> None:
        self._cached = None
        self._loaded_at = None


core_settings_cache = _CoreSettingsCache()


async def effective_core_settings(db: AsyncSession) -> Settings:
    """The application's core settings as they stand right now: store overrides
    over model defaults, cached for a few seconds so a request-path handler
    (e.g. an upload route reading ``sandbox.upload.*``) does not read the
    database on every request. ``core_settings_cache.invalidate()`` is called
    from the same PATCH/DELETE routes that already invalidate
    ``runtime_config`` (``app.api.v1.settings``), so a saved override is
    visible within one TTL window either way.
    """
    return await core_settings_cache.get(db)
