"""Read and write runtime overrides, validating the merged models first."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from maljan.core import settings_secrets as box
from maljan.core.config import BUILTIN_SERVER_KEYS, Settings, builtin_env_allow
from maljan.core.settings_overrides import (
    SERVER_MAP_PATH,
    build_settings,
    effective_source,
    flatten_leaves,
    pack_step_refusals,
    settings_from_store,
    shipped_tool_facts,
    split_key,
)
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as api_settings
from app.models import RuntimeSetting
from app.services.enrichment_sources import SOURCE_SECRETS
from app.services.frontier_arms import ARMS
from app.services.nested_secrets import NestedSecretMap
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


# The catalog leaves that hold a provider block's tool declarations
# (``core.static.ghidra.tool_facts`` …): each is a map of tool name to
# declaration, stored as its changes over what the block ships, one tool at a
# time. The server map's declarations are checked inside it (``server_map``).
TOOL_FACTS_LEAF_SUFFIX = ".tool_facts"


def _is_declaration_leaf(key: str, value: Any) -> bool:
    return (
        key.startswith("core.") and key.endswith(TOOL_FACTS_LEAF_SUFFIX) and isinstance(value, dict)
    )


def incoming_declaration_leaves(changes: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """``changes`` with each provider block's tool declarations marked as changes over what ships.

    A ``core.<block>.tool_facts`` value is read as every path reads a sent
    map (``tool_declarations.sent_in_force``): marked, as the block's changes
    over what it ships, so a shipped tool it leaves out stays as shipped and
    only ``null`` removes one; without the mark, whole, as an earlier release
    read it. A value sent back exactly as stored therefore says what the
    stored one says; one stored marked is passed on as it is. A value holding
    the mark's key with anything but the mark
    (``tool_declarations.unreadable_map``) is passed on as sent, since marking
    it would drop that key, for :func:`changed_declaration_refusals` to
    refuse. Every other key is unchanged.
    """
    from maljan.core.tool_declarations import (
        holds_changes,
        stored_changes,
        unreadable_map,
        with_mark,
    )

    out = dict(changes)
    for key, value in changes.items():
        if not _is_declaration_leaf(key, value):
            continue
        held = current.get(key)
        if (value == held and holds_changes(held)) or unreadable_map(value):
            continue
        out[key] = with_mark(stored_changes(value, _shipped_leaf(key)))
    return out


def _leaf_changes(
    key: str, value: dict[str, Any], held: Any
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """What a leaf's save ships, changes (kept tools aside) and keeps as stored.

    ``value`` is marked (:func:`incoming_declaration_leaves`); a tool it
    sends with its refused stored change exactly as stored is kept as stored
    (``tool_declarations.kept_stored_changes``) and left out of the rest.
    """
    from maljan.core.tool_declarations import kept_stored_changes, without_mark

    shipped = _shipped_leaf(key)
    incoming = without_mark(value)
    kept = kept_stored_changes(incoming, held, shipped)
    edited = {tool: change for tool, change in incoming.items() if tool not in kept}
    return shipped, edited, kept


def changed_declaration_refusals(
    changes: dict[str, Any], current: dict[str, Any]
) -> dict[str, str]:
    """The strict refusals of the provider tool declarations a save adds or changes.

    Each ``core.<block>.tool_facts`` value is a map of tool name to
    declaration; one the save leaves as stored (or as shipped) is not held to
    the strict rules (``tool_declarations.changed_declaration_errors``), so a
    stored row with a key this version does not read blocks no unrelated
    save. Keys are ``<leaf>.<tool>[.<field>]``; a value that is not a map,
    or that names a tool no tool can be called (``check_tool_name``) other
    than one sent back with its stored change exactly as stored, is refused
    under ``<leaf>`` itself, as the settings model refuses it.
    """
    from maljan.core.tool_declarations import (
        changed_declaration_errors,
        merge_tool_facts,
        sent_names_refusal,
        stored_in_force,
    )

    errors: dict[str, str] = {}
    for key, value in changes.items():
        if not (key.startswith("core.") and key.endswith(TOOL_FACTS_LEAF_SUFFIX)):
            continue
        if value is None:
            continue
        if not isinstance(value, dict):
            errors[key] = "tool declarations are a JSON object keyed by tool name"
            continue
        held = current.get(key)
        shipped, edited, kept = _leaf_changes(key, value, held)
        refusal = sent_names_refusal(value, kept)
        if refusal:
            errors[key] = refusal
            continue
        before = stored_in_force(shipped, held)[0] if isinstance(held, dict) else None
        for where, message in changed_declaration_errors(
            merge_tool_facts(shipped, edited), [before, shipped]
        ).items():
            errors[f"{key}.{where}"] = message
    return errors


def _shipped_leaf(key: str) -> dict[str, Any]:
    """What the provider block of a ``core.<block>.tool_facts`` leaf ships for it."""
    return shipped_tool_facts(split_key(key)[1].removesuffix(TOOL_FACTS_LEAF_SUFFIX))


def stored_declaration_leaves(
    changes: dict[str, Any], current: dict[str, Any] | None = None
) -> dict[str, Any]:
    """``changes`` with each provider block's tool declarations in the form they are stored.

    A ``core.<block>.tool_facts`` value (:func:`incoming_declaration_leaves`)
    is validated as it is in force and stored as its changes one tool at a
    time (``tool_declarations.tool_facts_changes``), marked as such, so a
    tool an operator never changed keeps following later releases. A value
    sent back exactly as stored is stored as it was, and so is each tool sent
    with its refused stored change exactly as stored (:func:`_leaf_changes`).
    Every other key is unchanged.
    """
    from maljan.core.config import MCPServerConfig
    from maljan.core.tool_declarations import merge_tool_facts, tool_facts_changes, with_mark

    out = dict(changes)
    for key, value in changes.items():
        if not _is_declaration_leaf(key, value):
            continue
        held = None if current is None else current.get(key)
        if current is not None and value == held:
            continue
        shipped, edited, kept = _leaf_changes(key, value, held)
        try:
            in_force = MCPServerConfig.model_validate(
                {"tool_facts": merge_tool_facts(shipped, edited)}
            ).model_dump(mode="json")["tool_facts"]
        except ValidationError as exc:
            # Every refusal above should have said it first; this keeps a save
            # a precise refusal of the leaf rather than a failed request.
            raise SettingsValidationError(
                {key: "; ".join(str(err["msg"]) for err in exc.errors())}
            ) from None
        out[key] = with_mark({**tool_facts_changes(in_force, shipped), **kept})
    return out


def served_tool_facts(stored: dict[str, Any], shipped: dict[str, Any]) -> dict[str, Any]:
    """A stored map of a block's tool declarations as the API serves and exports it.

    Its changes over what the block ships, marked as such
    (``tool_declarations.with_mark``), whichever form it was stored in: one
    an earlier release stored whole is served as the changes that put the
    same in force, so what the console shows and sends back, and what an
    export carries, reads the same as what is in force. A stored map whose
    form no release writes (``tool_declarations.unreadable_map``) is not in
    force and is served as no change at all, so what the console sends back
    keeps the shipped declarations in force.
    """
    from maljan.core.tool_declarations import stored_changes, unreadable_map, with_mark

    if unreadable_map(stored):
        return with_mark({})
    return with_mark(stored_changes(stored, shipped))


def lenient_imported_declarations(
    values: dict[str, Any], *, whole_maps: bool = False
) -> tuple[dict[str, Any], dict[str, str]]:
    """An import document's tool declarations, without what this version cannot read.

    An export written by another version may hold a key this one does not
    read (or a field only a kind makes readable, on a declaration that names
    none): it is left out, the rest is imported, and each tool's leaving-out
    is returned as a warning keyed by its dotted path. A declaration left
    with nothing it says is left out whole. The file is never refused for it.

    A block's tool declarations marked as changes
    (``tool_declarations.holds_changes``) are its changes over what the block
    ships, one tool at a time; each tool the document names is read as it is
    in force, and kept as its changes again, marked. A map without the mark,
    and every map when ``whole_maps`` says the document was written before
    declarations were stored that way, is its whole map: a shipped tool it
    does not name was removed, and stays removed.
    """
    from maljan.core.tool_declarations import (
        holds_changes,
        lenient_declarations,
        loggable_names,
        merge_tool_facts,
        own_prefixed_names,
        reads_no_kind,
        refused_tool_names,
        tool_facts_changes,
        unreadable_map,
        whole_as_changes,
        with_mark,
        without_mark,
    )

    from app.services.server_map import SERVER_MAP_KEY

    warnings: dict[str, str] = {}

    def _warn(key: str, text: str) -> None:
        # Every warning about one tool is kept, in the order it was found.
        held = warnings.get(key)
        warnings[key] = f"{held}; then {text}" if held else text

    def _clean(declared: Any, prefix: str, shipped: dict[str, Any], server: str = "") -> Any:
        if not isinstance(declared, dict) or unreadable_map(declared):
            # Passed on as written (reading it would drop the mark's key), for
            # the save to refuse with the key named.
            return declared
        # A name no tool can have is carried through as written, whatever its
        # value (``null`` included, which reading the map would drop), for the
        # save to refuse with the key named, or keep where it is sent back
        # exactly as stored.
        carried = {
            tool: declared[tool]
            for tool in [*refused_tool_names(declared), *own_prefixed_names(declared, server)]
            if tool in declared
        }
        declared = {tool: held for tool, held in declared.items() if tool not in carried}
        # A map marked as changes is read as changes; one without the mark
        # (every map of a ``/1`` document, or of a ``/2`` one exported from a
        # store a release before the mark wrote) is read whole, as it was
        # written: a shipped tool it does not name was removed, and a field a
        # shipped tool's declaration leaves out is at its default.
        declared = (
            without_mark(declared)
            if holds_changes(declared) and not whole_maps
            else whole_as_changes(declared, shipped)
        )
        in_force = merge_tool_facts(shipped, declared)
        named = {tool: in_force[tool] for tool in declared if tool in in_force}
        kept, notes = lenient_declarations(named, where=f"{prefix} ")
        for tool, names in notes.items():
            _warn(
                f"{prefix}.{tool}",
                "left out " + loggable_names(names) + ": this version does not read them",
            )
        for tool, held in list(kept.items()):
            if isinstance(held, dict) and reads_no_kind(held):
                held = {**held, "kind": ""}
            if isinstance(held, dict) and not any(
                name for name, value in held.items() if value not in ("", None, [], {}, False)
            ):
                kept.pop(tool)
                _warn(f"{prefix}.{tool}", "left out whole: it declares nothing this version reads")
        held_in_force = {
            tool: kept[tool] if tool in named else facts
            for tool, facts in in_force.items()
            if tool not in named or tool in kept
        }
        return {**with_mark(tool_facts_changes(held_in_force, shipped)), **carried}

    out = dict(values)
    for key, value in values.items():
        if key == SERVER_MAP_KEY and isinstance(value, dict):
            servers = {}
            for name, entry in value.items():
                if isinstance(entry, dict) and isinstance(entry.get("tool_facts"), dict):
                    entry = {
                        **entry,
                        "tool_facts": _clean(
                            entry["tool_facts"],
                            f"{key}.{name}.tool_facts",
                            shipped_tool_facts(f"{SERVER_MAP_PATH}.{name}"),
                            str(name),
                        ),
                    }
                servers[name] = entry
            out[key] = servers
        elif key.startswith("core.") and key.endswith(TOOL_FACTS_LEAF_SUFFIX):
            out[key] = _clean(value, key, _shipped_leaf(key))
    return out, warnings


_DEFINITIONS_KEY = "core.agents.definitions"


def definitions_after_save(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """The stored overrides with the agent definitions this save puts in force.

    A server's ``agents`` list is checked against the definition keys, and a
    console apply sends the definition map and the server map in one request:
    an agent added in it is known to the server binding, and one the request
    removes is not. The definition map is sent whole, so its value replaces
    the stored one, an entry set to ``null`` names no agent, and a ``null``
    map leaves the built-ins alone (``server_map._definition_keys`` adds them).
    """
    if _DEFINITIONS_KEY not in changes:
        return current
    incoming = changes[_DEFINITIONS_KEY]
    out = {key: value for key, value in current.items() if key != _DEFINITIONS_KEY}
    if isinstance(incoming, dict):
        out[_DEFINITIONS_KEY] = {k: v for k, v in incoming.items() if v is not None}
    return out


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
#
# Every composite but the server map keeps its entries' credential the one
# way ``nested_secrets.NestedSecretMap`` describes: the frontier arms and the
# enrichment sources.
NESTED_SECRET_MAPS: tuple[NestedSecretMap, ...] = (ARMS, SOURCE_SECRETS)
_NESTED_BY_KEY = {spec.key: spec for spec in NESTED_SECRET_MAPS}
_COMPOSITE_SECRET_SUFFIX = {
    SERVER_MAP_KEY: ".auth_token",
    **{spec.key: spec.suffix for spec in NESTED_SECRET_MAPS},
}


def _merge_nested(overrides: dict[str, Any]) -> dict[str, Any]:
    for spec in NESTED_SECRET_MAPS:
        overrides = spec.merge(overrides)
    return overrides


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
        return _merge_nested(merge_server_secrets(out))

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
            nested = _NESTED_BY_KEY.get(entry.key)
            if nested is not None:
                # Same split as the server map: the composite row never holds a
                # credential, each set one is its own encrypted row, and what
                # the editor shows is the mask -- which ``NestedSecretMap.split``
                # reads back as "leave the row alone".
                stored_composite: Any = row.value if row is not None else default_value
                out[key] = ValueInfo(
                    nested.masked(dict(stored_composite or {}), rows),
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
                held = row.value
                shown_value = (
                    served_tool_facts(held, _shipped_leaf(key))
                    if isinstance(held, dict) and _is_declaration_leaf(key, held)
                    else held
                )
                out[key] = ValueInfo(shown_value, None, None, "ui", row.updated_at, row.updated_by)
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

        A built-in's ``env_allow`` is shown with the names its sidecar cannot
        run without in it (``builtin_env_allow``), which is what its child is
        really started with, rather than whatever a row saved before one of
        them existed still holds. A shipped default an admin has taken out
        stays out, and is shown as taken out.

        An entry's tool declarations are shown as its changes over what the
        server ships, marked as such (:func:`served_tool_facts`), whichever
        form they were stored in.

        The map shown is the stored one: a built-in key a row predates is
        re-seeded for the run and written back by the next save
        (``validate_server_map``), but it is not conjured into this view.
        """
        out: dict[str, Any] = {}
        for name, entry in stored_map.items():
            shown = dict(entry)
            if isinstance(shown.get("tool_facts"), dict):
                shown["tool_facts"] = served_tool_facts(
                    shown["tool_facts"], shipped_tool_facts(f"{SERVER_MAP_PATH}.{name}")
                )
            if name in BUILTIN_SERVER_KEYS:
                shown["env_allow"] = builtin_env_allow(name, shown.get("env_allow") or [])
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
    def check_keys(self, changes: dict[str, Any], stored: dict[str, Any] | None = None) -> None:
        """Refuse unknown, read-only and out-of-choice keys.

        ``stored`` is what is saved now: a value equal to it is not checked
        against the choices again, so a form re-sending a stored id whose
        backend package later broke can still save its other keys.
        """
        index = catalog_index()
        stored = stored or {}
        errors = {}
        for key in changes:
            entry = index.get(key)
            if entry is None:
                errors[key] = "unknown setting"
            elif not entry.editable:
                errors[key] = entry.reason or "read-only"
            elif (
                entry.choices_from
                and entry.choices is not None
                and changes[key] is not None
                and changes[key] != stored.get(key)
                and changes[key] not in entry.choices
            ):
                # Exactly as the registry spells it: a value that differs in
                # case or spacing names no provider when a job is built, so it
                # is refused here rather than stored for every job to fail on.
                # A choice a registry holds (a memory backend, say) is checked
                # here, where it is saved, rather than wherever the settings
                # are read: a stored id whose package later breaks still loads.
                errors[key] = f"not one of: {', '.join(entry.choices)}"
        if errors:
            raise SettingsValidationError(errors)

    def _with_value_errors(
        self,
        refused: SettingsValidationError,
        changes: dict[str, Any],
        current: dict[str, Any],
    ) -> SettingsValidationError:
        """``refused``, with what ``validate`` says about the keys it did not refuse."""
        errors = dict(refused.errors)
        index = catalog_index()
        merged = dict(current)
        for key, value in changes.items():
            if key in errors or key not in index:
                continue
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        core = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("core.")}
        api = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("api.")}
        try:
            self.validate(core, api)
        except SettingsValidationError as more:
            for key, message in more.errors.items():
                errors.setdefault(key, message)
        except Exception:  # noqa: BLE001 — the refusal stands on its own
            pass
        try:
            # Stored pack steps are read leniently by ``validate``; the steps
            # this save changes are held to the strict rules here as well.
            stored_core = {split_key(k)[1]: v for k, v in current.items() if k.startswith("core.")}
            for key, message in pack_step_refusals(core, stored_core).items():
                errors.setdefault(key, message)
        except Exception:  # noqa: BLE001 — the refusal stands on its own
            pass
        return SettingsValidationError(errors)

    def validate(self, merged_core: dict[str, Any], merged_api: dict[str, Any]) -> None:
        errors: dict[str, str] = {}
        try:
            built = build_settings(merged_core)
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("core", err["loc"])] = err["msg"]
        else:
            # The selected provider's role models are read from its own block,
            # never borrowed from another provider's.
            from maljan.llm.provider_base import role_block_problem

            problem = role_block_problem(built)
            if problem:
                errors["core.llm.provider"] = problem
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
        current = await self.load_overrides()
        try:
            self.check_keys(changes, current)
        except SettingsValidationError as refused:
            # Every refused key is named in one answer: what the model would
            # refuse among the keys that passed is said beside it.
            raise self._with_value_errors(refused, changes, current) from None
        index = catalog_index()
        # An import document carries the mask wherever a secret was omitted.
        # For a secret leaf the mask means "unchanged", exactly as it does in
        # a composite editor -- never a credential whose literal characters
        # are ten asterisks.
        changes = {k: v for k, v in changes.items() if not (index[k].secret and v == TOKEN_MASK)}
        changes = incoming_declaration_leaves(changes, current)
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
                        stored_settings=definitions_after_save(current, changes),
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

        # Per nested-secret composite in the change: its credentials to write
        # and the entry names it still holds.
        nested_writes: list[tuple[NestedSecretMap, dict[str, str | None], set[str]]] = []
        for spec in NESTED_SECRET_MAPS:
            if spec.key not in changes:
                continue
            if changes[spec.key] is None:
                # An explicit null drops the override like every other key
                # (handled below); every per-entry credential row goes with it.
                nested_writes.append((spec, {}, set()))
                continue
            stored_composite = current.get(spec.key)
            changes[spec.key], secrets = spec.split(
                changes[spec.key],
                stored=stored_composite if isinstance(stored_composite, dict) else None,
            )
            unstorable = [
                spec.row_key(name)
                for name, secret in secrets.items()
                if secret and not box.is_available()
            ]
            if unstorable:
                raise SettingsValidationError(
                    {
                        key: "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
                        for key in unstorable
                    }
                )
            if isinstance(changes[spec.key], dict):
                nested_writes.append((spec, secrets, set(changes[spec.key])))

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
            #
            # In a worker thread: the team lint behind it is CPU work over
            # whatever the PATCH holds, and the event loop has other requests.
            try:
                changes.update(await asyncio.to_thread(validate_agent_map, changes, current))
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
        # Every refusal of the merged values in one answer: the model's, the
        # pack steps this save changes (stored ones are read leniently, the
        # changed ones held to the strict rules) and the tool declarations it
        # changes.
        refusals: dict[str, str] = {}
        try:
            self.validate(core, api)
        except SettingsValidationError as refused:
            refusals.update(refused.errors)
        stored_core = {split_key(k)[1]: v for k, v in current.items() if k.startswith("core.")}
        for more in (
            pack_step_refusals(core, stored_core),
            changed_declaration_refusals(changes, current),
        ):
            for key, message in more.items():
                refusals.setdefault(key, message)
        if refusals:
            raise SettingsValidationError(refusals)
        changes = stored_declaration_leaves(changes, current)

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
        for spec, secrets, kept in nested_writes:
            await self._save_runtime_secrets(
                secrets, kept, prefix=f"{spec.key}.", suffix=spec.suffix, key_of=spec.row_key
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
        # A stored value the model refuses fails the read loudly, naming the
        # key and the remedy; only the settings page reads past it.
        self._cached = settings_from_store(await load_core_overrides(db))
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
