"""Build the application's core settings from the store and defaults only.

Overrides are dotted paths (``llm.openai.base_url``). ``build_settings`` nests
them and passes them to ``Settings(**nested)`` with the module-level
``STORE_ONLY`` flag set, which drops the environment, ``.env``, and secrets
directory sources for that one construction (see
``maljan.core.config.Settings.settings_customise_sources``). Precedence is
therefore ``UI > default`` — the environment is no longer a layer for the
application. The bare ``Settings()`` constructor is unaffected by this
module and stays environment- and dotenv-capable; it is a documented library
behaviour, relied on by the legacy one-shot environment import.
"""

from __future__ import annotations

import copy
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar
from functools import cache
from typing import Any, Literal

from pydantic import BaseModel

from maljan.core.config import STORE_ONLY, Settings
from maljan.core.pack_steps import (
    LeftOutStep,
    PackStep,
    steps_left_out,
)
from maljan.core.tool_declarations import stored_in_force

CORE_NS = "core"
API_NS = "api"
Source = Literal["ui", "default"]


def split_key(key: str) -> tuple[str, str]:
    ns, sep, path = key.partition(".")
    if not sep or ns not in (CORE_NS, API_NS) or not path:
        raise ValueError(f"settings key must be '<core|api>.<path>', got {key!r}")
    return ns, path


def nest(flat: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in flat.items():
        cursor = out
        parts = key.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                raise ValueError(f"{key!r} descends into a non-mapping at {part!r}")
        cursor[parts[-1]] = value
    return out


def flatten(obj: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested mapping -> dotted keys. Every mapping is structure; see flatten_leaves."""
    out: dict[str, Any] = {}
    for k, v in obj.items():
        path = f"{prefix}{k}"
        if isinstance(v, Mapping):
            out.update(flatten(v, path + "."))
        else:
            out[path] = v
    return out


def flatten_leaves(model: BaseModel, leaf_keys: Iterable[str]) -> dict[str, Any]:
    """Values for exactly ``leaf_keys`` from a model instance, JSON-serialisable.

    Nested models are walked attribute by attribute; a leaf that is itself a
    mapping (``llm.agents``, ``react_agent_timeout_overrides``) is returned
    whole, which is what ``flatten`` alone would not do.
    """
    dumped = model.model_dump(mode="json")
    out: dict[str, Any] = {}
    for key in leaf_keys:
        cursor: Any = dumped
        for part in key.split("."):
            cursor = cursor[part]
        out[key] = cursor
    return out


def build_settings(core_overrides: Mapping[str, Any]) -> Settings:
    """The application's core settings: ``core_overrides`` over model defaults.

    Store-only: the environment, ``.env``, and any secrets directory are
    never consulted, regardless of what is set in the process. This is the
    only construction path the application (API, worker) may use — see
    ``tests/unit/test_no_bare_settings_in_app.py``.
    """
    return _built(core_overrides)[0]


class StoredValueRefused(ValueError):
    """A stored setting value the model refuses: named, with why and the remedy.

    Raised by every read that runs something (a job, an API read, the ATT&CK
    cron) instead of falling back to a default: a refused spend cap, server
    map, allow-list or timeout must never quietly become a less safe one.
    """

    def __init__(self, refused: Mapping[str, str]) -> None:
        self.refused = {f"core.{key}": reason for key, reason in refused.items()}
        named = "; ".join(f"{key}: {reason}" for key, reason in self.refused.items())
        super().__init__(
            f"A stored setting value is refused ({named}). Fix it or reset it in the "
            "console (Settings, Configuration); nothing runs on a default in its place."
        )


def settings_from_store(
    core_overrides: Mapping[str, Any], *, stored_keys: Iterable[str] | None = None
) -> Settings:
    """:func:`build_settings` for a read that runs something: a refused stored value
    fails it loudly, naming the key, the reason and the remedy.

    A refusal not about a key in ``stored_keys`` (all of ``core_overrides``
    when ``None``), such as a value a job brought itself, is raised as the
    model raised it.
    """
    from pydantic import ValidationError

    try:
        return build_settings(core_overrides)
    except ValidationError as exc:
        eligible = set(core_overrides if stored_keys is None else stored_keys)
        found = _refused_stored_keys(exc, core_overrides, eligible)
        if not found:
            raise
        refused = StoredValueRefused(found)
        from maljan.core.logger import logger

        logger.error("%s", refused)
        # ``from None``: the model's error, whose text holds the refused input
        # (a secret, possibly), never travels with this one.
        raise refused from None


def stored_settings(
    core_overrides: Mapping[str, Any], *, stored_keys: Iterable[str] | None = None
) -> tuple[Settings, dict[str, str]]:
    """The settings page's read alone: the stored values the model refuses, read past.

    Only so the console can open while a stored value is refused and the admin
    can repair it there: that key is left out (its default shown), and it is
    returned with the reason, for the page's banner and the row's notice.
    Nothing that runs reads settings this way (:func:`settings_from_store`
    refuses); a save validates with :func:`build_settings`, which refuses.
    """
    from pydantic import ValidationError

    remaining = dict(core_overrides)
    eligible = set(remaining if stored_keys is None else stored_keys)
    refused: dict[str, str] = {}
    while True:
        try:
            built = build_settings(remaining)
        except ValidationError as exc:
            found = _refused_stored_keys(exc, remaining, eligible)
            if not found:
                raise
            for key, reason in found.items():
                remaining.pop(key, None)
                refused[key] = reason
            continue
        if refused:
            _warn_refused_values(refused)
        return built, refused


def _refused_stored_keys(
    exc: Any, remaining: Mapping[str, Any], eligible: set[str]
) -> dict[str, str]:
    """Each stored key a validation error is about, with its message."""
    found: dict[str, str] = {}
    for error in exc.errors():
        path = ".".join(str(part) for part in error.get("loc", ()))
        owners = [
            key
            for key in remaining
            if key in eligible and (path == key or path.startswith(key + "."))
        ]
        if owners:
            found[max(owners, key=len)] = str(error.get("msg") or "refused")
    return found


_WARNED_VALUES: set[tuple[tuple[str, str], ...]] = set()


def _warn_refused_values(refused: Mapping[str, str]) -> None:
    from maljan.core.logger import logger

    marker = tuple(sorted(refused.items()))
    if marker in _WARNED_VALUES:
        return
    if len(_WARNED_VALUES) < _WARNED_STEPS_MAX:
        _WARNED_VALUES.add(marker)
    for key, reason in refused.items():
        logger.warning(
            "The stored value of %s is not in force (%s); its default is used until it is "
            "saved again or reset.",
            key,
            reason,
        )


# The stored leaf of the triage pack's steps (``core.pack_steps``).
PACK_STEPS_PATH = "triage.steps"

# Whether the stored steps are read for a save (:func:`pack_step_refusals`):
# a step named that no step of the list is and no configured server's tool
# gives is then a problem; a stored list read for a run keeps such a name for
# the run to resolve (``core.pack_steps._effective``).
_SAVING: ContextVar[bool] = ContextVar("pack_steps_saving", default=False)


def _built(
    core_overrides: Mapping[str, Any], set_aside: Callable[[PackStep], str | None] | None = None
) -> tuple[Settings, list[LeftOutStep]]:
    """The settings :func:`build_settings` builds, and the stored pack steps it left out.

    The stored steps are read leniently (``core.pack_steps.steps_left_out``):
    a step this release cannot run is left out with one warning, the shipped
    step it changed in force again, so one stale step never costs a job every
    setting. A save holds the steps it changes to the strict rules
    (:func:`pack_step_refusals`); the console names each step left out and
    why (:func:`pack_steps_left_out`). A step ``set_aside`` answers for
    (anything but ``None``) is not held to the settings' own check: its
    answer is its problem, ``""`` for none (:func:`_left_out_checked`).
    """
    from maljan.core.settings_annotations import MOVED_UNREAD_BY_MODELS, read_as_current

    token = STORE_ONLY.set(True)
    try:
        # A row a revision has not moved yet is read as the key that now holds
        # it, where no settings model reads the old key itself.
        moved = read_as_current(core_overrides, prefix="", only=MOVED_UNREAD_BY_MODELS)
        in_force = declarations_in_force(moved)
        if PACK_STEPS_PATH not in in_force:
            return Settings(**nest(in_force)), []
        stored = in_force.pop(PACK_STEPS_PATH)
        built = Settings(**nest(in_force))
    finally:
        STORE_ONLY.reset(token)
    problem = built.pack_step_problem
    if set_aside is not None:
        held = set_aside

        def problem(step: PackStep) -> str:
            said = held(step)
            return built.pack_step_problem(step) if said is None else said

    servers = built.mcp.servers if _SAVING.get() else None
    kept, left = steps_left_out(stored, problem, servers)
    if left:
        _warn_left_out_steps(_names_once(left))
    built.triage = built.triage.model_copy(update={"steps": kept})
    return built, left


def _names_once(left: Iterable[LeftOutStep]) -> list[str]:
    return list(dict.fromkeys(entry.name for entry in left))


_WARNED_STEPS: set[tuple[str, ...]] = set()
_WARNED_STEPS_MAX = 256


def _warn_left_out_steps(left: list[str]) -> None:
    from maljan.core.logger import logger
    from maljan.core.tool_declarations import loggable_names

    held = tuple(left)
    if held in _WARNED_STEPS:
        return
    if len(_WARNED_STEPS) >= _WARNED_STEPS_MAX:
        _WARNED_STEPS.clear()
    _WARNED_STEPS.add(held)
    logger.warning(
        "A stored triage pack step cannot run as declared under this release's settings; "
        "it is left out, and the shipped step it changed, if any, is in force: %s",
        loggable_names(held),
    )


def left_out_pack_steps(core_overrides: Mapping[str, Any]) -> list[str]:
    """The stored pack steps :func:`build_settings` leaves out, by id (else position), once each."""
    return _names_once(_left_out_checked(core_overrides, list_set_aside=True))


def pack_steps_left_out(core_overrides: Mapping[str, Any]) -> dict[str, str]:
    """Each stored pack step :func:`build_settings` leaves out, by name, with why, sanitised.

    Whatever leaves it out: a stored step this release cannot run, a reset
    of the server it calls, a shipped declaration that changed its tool's
    kind. The shipped step it changed, if any, is in force instead; the
    console marks each one for the operator to edit or remove. A name stored
    twice carries both reasons. Stored settings that do not build list the
    steps all the same (:func:`_left_out_checked`), never an error.
    """
    from maljan.core.tool_declarations import loggable_text

    out: dict[str, list[str]] = {}
    for entry in _left_out_checked(core_overrides, list_set_aside=True):
        reasons = out.setdefault(loggable_text(entry.name), [])
        reason = loggable_text(entry.reason)
        if reason not in reasons:
            reasons.append(reason)
    return {name: "; ".join(reasons) for name, reasons in out.items()}


UNKNOWN_KEY_MAPS: tuple[str, ...] = (
    "llm.agents",
    "react_agent_timeout_overrides",
    "react_agent_max_steps_overrides",
)
DEFINITIONS_PATH = "agents.definitions"


def unknown_reference_refusals(
    merged: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, str]:
    """The refusal of a save that brings a reference to nothing the settings hold.

    ``merged`` and ``current`` are core overrides (no ``core.`` prefix) after
    and before the save. Refused: a key of ``llm.agents`` or of a
    ``react_agent_*_overrides`` map that names no agent definition and no
    model-calling role (nothing would read it), and a ``capability`` tool
    reference no server declares a tool of (it would resolve to no server).
    Each is named, with what is available. What is already stored, sent back
    as stored, is never refused, so stored settings stay readable and no
    unrelated save is blocked; where the merged values do not build, the model
    refuses them itself.
    """
    from pydantic import ValidationError

    from maljan.agents.composition import servers_of_capability
    from maljan.core.config import ROLE_ENTRY_KEYS

    try:
        built = build_settings(merged)
    except ValidationError:
        return {}
    roster = {*built.agents.definitions, *ROLE_ENTRY_KEYS}
    available = ", ".join(sorted(roster))
    refused: dict[str, str] = {}
    for path in UNKNOWN_KEY_MAPS:
        held = merged.get(path)
        stored = current.get(path)
        stored_keys = set(stored) if isinstance(stored, Mapping) else set()
        unknown = [
            str(key)
            for key in (held if isinstance(held, Mapping) else {})
            if key not in roster and key not in stored_keys
        ]
        if unknown:
            refused[f"{CORE_NS}.{path}"] = (
                f"{', '.join(unknown)}: names no agent, so nothing would read it. "
                f"Available: {available}"
            )
    stored_defs = current.get(DEFINITIONS_PATH)
    stored_defs = stored_defs if isinstance(stored_defs, Mapping) else {}
    problems: list[str] = []
    for key, definition in built.agents.definitions.items():
        stored_refs = stored_defs.get(key)
        stored_refs = stored_refs.get("tools") if isinstance(stored_refs, Mapping) else None
        stored_caps = {
            ref.get("capability")
            for ref in (stored_refs if isinstance(stored_refs, list) else [])
            if isinstance(ref, Mapping)
        }
        for ref in definition.tools:
            capability = str(ref.capability)
            if (
                ref.kind == "capability"
                and capability not in stored_caps
                and not servers_of_capability(built.mcp.servers, capability)
            ):
                problems.append(
                    f"{key!r} references capability {capability!r}, which no tool server "
                    "declares a tool of, so it would resolve to no server"
                )
    if problems:
        refused[f"{CORE_NS}.{DEFINITIONS_PATH}"] = "; ".join(problems)
    return refused


def pack_step_refusals(merged: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, str]:
    """The strict refusal of a save that brings a pack step item the settings leave out.

    ``merged`` and ``current`` are core overrides (no ``core.`` prefix) after
    and before the save. What it guarantees: no new or changed item that is
    left out passes a save. Items are matched by the whole stored item, so an
    item the stored settings already leave out, sent back exactly as stored
    (wherever it stands), blocks no unrelated save; it stays left out and
    listed (:func:`pack_steps_left_out`). Each refused item is named under
    ``core.triage.steps`` with the settings model's own words for it. Where
    other settings of ``merged`` do not build, those are refused by the model
    itself and the steps are checked as :func:`_left_out_checked` says.
    """
    token = _SAVING.set(True)
    try:
        left = _left_out_checked(merged)
        if not left:
            return {}
        kept = Counter(_left_out_items(current, _left_out_checked(current)))
    finally:
        _SAVING.reset(token)
    refused: list[LeftOutStep] = []
    for entry, item in zip(left, _left_out_items(merged, left), strict=True):
        if kept[item]:
            kept[item] -= 1
        else:
            refused.append(entry)
    if not refused:
        return {}
    return {
        f"{CORE_NS}.{PACK_STEPS_PATH}": "; ".join(
            f"{entry.name}: {entry.reason}" for entry in refused
        )
    }


def _left_out_checked(
    core_overrides: Mapping[str, Any], *, list_set_aside: bool = False
) -> list[LeftOutStep]:
    """The stored steps left out of ``core_overrides``, also where other settings do not build.

    What the model refuses is set aside, a refused entry of a map setting
    alone where the refusal names one, the rest kept, and the steps are
    checked against what is left. A step whose ``server`` is a set-aside
    entry of the tool-server map is not held to the settings' own check, so
    a server present in a refused map is never called unknown, its own
    refusal standing for it: a save's refusal leaves it to that refusal,
    and with ``list_set_aside`` (the console's listing) it is listed, saying
    its server's stored entry is refused. Only the step's server is matched,
    never another value it holds. Where even that does not build, the steps
    are checked on their own, without the checks that need the built settings.
    """
    try:
        return _built(core_overrides)[1]
    except ValueError as exc:  # a pydantic ValidationError is one
        errors = getattr(exc, "errors", None)
        locs = (
            [tuple(str(p) for p in e.get("loc", ())) for e in errors()] if callable(errors) else []
        )
    keys = {tuple(key.split(".")): key for key in core_overrides if key != PACK_STEPS_PATH}
    whole: set[str] = set()
    entries: dict[str, set[str]] = {}
    for loc in locs:
        for size in range(1, len(loc) + 1):
            key = keys.get(loc[:size])
            if key is None:
                continue
            value = core_overrides[key]
            if size < len(loc) and isinstance(value, Mapping) and loc[size] in value:
                entries.setdefault(key, set()).add(loc[size])
            else:
                whole.add(key)
            break
        else:
            # A refusal above any stored key: every key under it.
            whole.update(key for parts, key in keys.items() if parts[: len(loc)] == loc and loc)
    if not whole and not entries:
        return steps_left_out(core_overrides.get(PACK_STEPS_PATH))[1]
    servers: set[str] = set()
    rest: dict[str, Any] = {}
    for key, value in core_overrides.items():
        if key in whole:
            if key == SERVER_MAP_PATH and isinstance(value, Mapping):
                servers.update(str(name) for name in value)
        elif key in entries:
            dropped = entries[key]
            if key == SERVER_MAP_PATH:
                servers.update(dropped)
            rest[key] = {name: item for name, item in value.items() if name not in dropped}
        else:
            rest[key] = value

    def on_a_refused_server(step: PackStep) -> str | None:
        if not step.server or step.server not in servers:
            return None
        if not list_set_aside:
            return ""
        return (
            f"triage step {step.id!r}: the stored entry of its server {step.server!r} is "
            "refused (see the refused stored values), so the step is not checked or run "
            "until that entry is fixed or reset"
        )

    try:
        return _built(rest, on_a_refused_server)[1]
    except ValueError:
        return steps_left_out(core_overrides.get(PACK_STEPS_PATH))[1]


def _left_out_items(core_overrides: Mapping[str, Any], left: Iterable[LeftOutStep]) -> list[str]:
    """Each left-out stored item, whole, as one canonical text to match by identity."""
    held = core_overrides.get(PACK_STEPS_PATH)
    out: list[str] = []
    for entry in left:
        item = held
        if isinstance(held, list) and entry.position is not None:
            item = held[entry.position]
        try:
            out.append(json.dumps(item, sort_keys=True, default=repr))
        except (TypeError, ValueError, RecursionError):
            # Too deep to write out: the same stored object, else no match.
            out.append(f"\x00{id(item)}")
    return out


# The stored tool-server map, and the field holding a block's tool declarations.
SERVER_MAP_PATH = "mcp.servers"
TOOL_FACTS_FIELD = "tool_facts"
_TOOL_FACTS_SUFFIX = f".{TOOL_FACTS_FIELD}"


@cache
def _shipped_dump() -> dict[str, Any]:
    """Every block as it ships, as JSON: the settings built from no override at all."""
    return build_settings({}).model_dump(mode="json")


def shipped_tool_facts(block: str) -> dict[str, Any]:
    """The tool declarations the block at dotted path ``block`` ships, as JSON; ``{}`` for none.

    ``mcp.servers.<key>`` for a server of the tool-server map, a provider
    block's own path (``static.ghidra``) otherwise. A block that is not in the
    shipped settings (a server an operator added) ships nothing.
    """
    node: Any = _shipped_dump()
    for part in block.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return {}
        node = node[part]
    held = node.get(TOOL_FACTS_FIELD) if isinstance(node, Mapping) else None
    # A copy all the way down: the dump is cached for the process.
    return copy.deepcopy(dict(held)) if isinstance(held, Mapping) else {}


def shipped_tools(block: str) -> list[str] | None:
    """The tool allow-list the block at dotted path ``block`` ships; ``None`` for every tool.

    Read as :func:`shipped_tool_facts` reads its block; a block that is not in
    the shipped settings ships no allow-list.
    """
    node: Any = _shipped_dump()
    for part in block.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    held = node.get("tools") if isinstance(node, Mapping) else None
    return [str(name) for name in held] if isinstance(held, list) else None


_SERVER_PREFIX = f"{SERVER_MAP_PATH}."


def _block_in_force(block: str, stored: Any) -> tuple[dict[str, Any], list[str]]:
    """What one block's stored tool declarations put in force, and the changes refused.

    A block of the tool-server map refuses a name spelled as its own server's
    renamed tool, as the settings model does (``check_own_prefix``).
    """
    server = block.removeprefix(_SERVER_PREFIX) if block.startswith(_SERVER_PREFIX) else ""
    return stored_in_force(shipped_tool_facts(block), stored, where=block, server=server)


def server_entry_in_force(name: str, entry: Any) -> Any:
    """One stored server entry with its tool declarations as they are in force.

    A stored entry's ``tool_facts`` marked as changes hold its changes over
    what the server ships (``tool_declarations.stored_in_force``): in force
    they are the shipped ones with those changes over them. One without the
    mark was stored whole by an earlier release and is in force as stored.
    An entry that sets no tool declarations is returned as it is, and takes
    the shipped ones on load. One whose ``tool_facts`` is not a map at all is
    read as setting none, with a warning (``stored_in_force``).
    """
    if not isinstance(entry, Mapping) or TOOL_FACTS_FIELD not in entry:
        return entry
    held = entry[TOOL_FACTS_FIELD]
    in_force, _refused = _block_in_force(f"{SERVER_MAP_PATH}.{name}", held)
    if not isinstance(held, Mapping):
        return {field: value for field, value in entry.items() if field != TOOL_FACTS_FIELD}
    return {**entry, TOOL_FACTS_FIELD: in_force}


def _stored_blocks(core_overrides: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    """Each stored map of a block's tool declarations, with the block's dotted path."""
    for key, value in core_overrides.items():
        if key == SERVER_MAP_PATH and isinstance(value, Mapping):
            for name, entry in value.items():
                if isinstance(entry, Mapping) and TOOL_FACTS_FIELD in entry:
                    yield f"{SERVER_MAP_PATH}.{name}", entry[TOOL_FACTS_FIELD]
        elif key.endswith(_TOOL_FACTS_SUFFIX):
            yield key.removesuffix(_TOOL_FACTS_SUFFIX), value


def declarations_in_force(core_overrides: Mapping[str, Any]) -> dict[str, Any]:
    """``core_overrides`` with every stored block's tool declarations read as they are in force.

    What a store holds for a block's tool declarations (a server's entry in
    the tool-server map, a provider block's ``tool_facts`` leaf) is, marked
    as such, its changes over the shipped ones, one tool at a time, or,
    without the mark, the whole map an earlier release stored; the settings
    model holds the declarations in force. This is the one place the first
    is read as the second, for every construction from stored overrides
    (:func:`build_settings`). A stored change the model refuses over this
    release's declaration is left out with a warning, never a refusal of the
    settings, and a stored value whose form no release writes (one that is not
    a map, or holds the mark's key with anything but the mark) is read as
    absent, with a warning. Every other key is passed through unchanged.
    """
    out = dict(core_overrides)
    for key, value in core_overrides.items():
        if key == SERVER_MAP_PATH and isinstance(value, Mapping):
            out[key] = {name: server_entry_in_force(name, entry) for name, entry in value.items()}
        elif key.endswith(_TOOL_FACTS_SUFFIX):
            in_force = _block_in_force(key.removesuffix(_TOOL_FACTS_SUFFIX), value)[0]
            if isinstance(value, Mapping):
                out[key] = in_force
            else:
                out.pop(key)
    return out


def refused_tool_changes(core_overrides: Mapping[str, Any]) -> dict[str, list[str]]:
    """Per block path, the tools whose stored change the model refuses over what ships now.

    The tools :func:`declarations_in_force` puts in force as shipped instead,
    so the console can mark each one for the operator to reset or edit. A
    block with none is not named.
    """
    out: dict[str, list[str]] = {}
    for block, stored in _stored_blocks(core_overrides):
        refused = _block_in_force(block, stored)[1]
        if refused:
            out[block] = refused
    return out


def effective_source(*, overridden: bool) -> Source:
    return "ui" if overridden else "default"


def _scrubbed(value: Any, secrets: list[str]) -> Any:
    """``value`` with no configured secret value left in it."""
    from maljan.core.settings_masking import SNAPSHOT_MASK

    if isinstance(value, str):
        if value in secrets:
            return SNAPSHOT_MASK
        for secret in secrets:
            value = value.replace(secret, SNAPSHOT_MASK)
        return value
    if isinstance(value, list):
        return [_scrubbed(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _scrubbed(item, secrets) for key, item in value.items()}
    return value


def masked_settings_tree(settings: Settings) -> tuple[dict[str, Any], list[str]]:
    """``(the settings dump masked for a record, the secret leaf paths)``.

    The one masking of a settings instance for a record (``public_snapshot``,
    and through it the efficiency fingerprint): ``settings_masking.masked_dump``
    (each tool-server block's env values with their names kept, credential
    flags in its arguments, every URL, every open-mapping entry whose key names
    a credential).
    """
    from maljan.core.settings_catalog import snapshot_hidden_paths
    from maljan.core.settings_masking import masked_dump

    typed, _servers = snapshot_hidden_paths(settings)
    return masked_dump(settings, settings.model_dump(mode="json")), typed


def public_snapshot(settings: Settings, secret_keys: Iterable[str] = ()) -> dict[str, Any]:
    """The settings as they ran, with nothing in them a reader may not see.

    This snapshot reaches everyone who may read the report, through
    ``run_summary.settings_snapshot`` and the disclosure record, so it carries
    no secret:

    * every leaf the catalogue types as a secret, wherever it sits
      (``settings_catalog.snapshot_hidden_paths``), and each of
      ``secret_keys``, is ``"***"`` when set and ``None`` when not;
    * every tool server's ``env`` value is ``"***"``, its names kept; a
      credential a flag of its arguments names is ``"***"``
      (``settings_masking.masked_server``);
    * every URL keeps no user name, password, query value or fragment, and
      every entry whose key names a credential is ``"***"``
      (``settings_masking.masked_value``);
    * every value the settings hold as a secret by the event scrub's rules
      (``settings_catalog.configured_secret_values``) is masked wherever it
      still appears.
    """
    from maljan.core.settings_catalog import configured_secret_values
    from maljan.core.settings_masking import SNAPSHOT_MASK

    tree, typed = masked_settings_tree(settings)
    secrets = set(secret_keys) | set(typed)
    values = sorted(configured_secret_values(settings), key=len, reverse=True)
    snap: dict[str, Any] = {}
    for key, value in flatten(tree).items():
        if key in secrets:
            snap[key] = SNAPSHOT_MASK if value else None
        else:
            snap[key] = _scrubbed(value, values)
    return snap


def declaration_blocks(settings: Settings) -> dict[str, str]:
    """Each server block's dotted path, by the source its declaration is read under."""
    from maljan.core.tool_declarations import provider_blocks

    blocks = {f"mcp:{key}": f"mcp.servers.{key}" for key in settings.mcp.servers}
    blocks.update(provider_blocks())
    for key in settings.providers:
        blocks.setdefault(f"provider:{key}", f"providers.{key}")
    return blocks


def trim_declarations(
    snap: dict[str, Any], settings: Settings, overrides: Mapping[str, Any]
) -> dict[str, Any]:
    """``snap`` with each block's declaration recorded only where an operator set it.

    A built-in's shipped declaration is the same on every run of a release
    and runs to a thousand leaves, so the record keeps, of the declaration
    fields beside ``sample_open``, only those the stored overrides set (a
    provider block's leaf row, or the field in a server's entry of the stored
    tool-server map), and names everything in force by a short digest per
    source (``declaration_digest.<source>``) and one of the shipped data
    (``declaration_digest.shipped``). Nothing re-renders a stored run from
    these: a stored run is read by the legacy readers.
    """
    from maljan.core.builtin_declarations import shipped_digest
    from maljan.core.tool_declarations import SNAPSHOT_DIGESTED_FIELDS, ToolDeclarations

    # The two maps of blocks, each stored as one row: a field is the
    # operator's where the stored entry holds it.
    stored_maps: dict[str, Mapping[str, Any]] = {}
    for map_path in ("mcp.servers", "providers"):
        held = overrides.get(map_path)
        stored_maps[map_path] = held if isinstance(held, Mapping) else {}
    kept_prefixes: list[str] = []
    dropped_prefixes: list[str] = []
    for path in declaration_blocks(settings).values():
        for name in SNAPSHOT_DIGESTED_FIELDS:
            field_path = f"{path}.{name}"
            held_in = next((m for m in stored_maps if path.startswith(f"{m}.")), None)
            if held_in is not None:
                entry = stored_maps[held_in].get(path.removeprefix(f"{held_in}."))
                operator_set = isinstance(entry, Mapping) and name in entry
            else:
                operator_set = any(
                    key == field_path or key.startswith(f"{field_path}.") for key in overrides
                )
            (kept_prefixes if operator_set else dropped_prefixes).append(field_path)
    dropped = tuple(dropped_prefixes)
    dropped_dotted = tuple(f"{p}." for p in dropped_prefixes)
    out = {
        key: value
        for key, value in snap.items()
        if not (key in dropped or key.startswith(dropped_dotted))
    }
    # The blocks alone: what a server declared of its own tools is recorded by
    # its own digest when it attaches (``core.served_declarations``).
    blocks = ToolDeclarations.from_settings(settings, served=False)
    for source, digest in sorted(blocks.digests().items()):
        out[f"declaration_digest.{source}"] = digest
    out["declaration_digest.shipped"] = shipped_digest()
    return out


# Everything between "://" and the LAST "@" before the path is userinfo. Greedy
# on purpose: a password may itself contain "@" or ":" and the username may be
# empty (redis://:password@host is the usual Redis AUTH shape).
_CREDENTIAL_IN_URL = re.compile(r"(://)[^\s/@]*(?:@[^\s/@]*)*@")


# The words that make a parameter name a secret's, read as whole tokens: the
# name is split at ``_``, ``.``, ``-`` and camelCase humps, so ``clientSecret``
# and ``x-sig`` are caught and ``design``, ``keyword`` and ``author`` are not.
_SECRET_WORDS = frozenset(
    {
        "key", "apikey", "token", "secret", "password", "passwd", "pwd", "auth",
        "credential", "sig", "signature", "sas", "code",
    }
)  # fmt: skip
_QUERY_PARAM = re.compile(r"([?&#])([\w.-]+)=([^\s&#\"'<>]*)")
# A URL: from its scheme to the next space or quote.
_URL_SPAN = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]*")


def _secret_name(name: str) -> bool:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    return any(token in _SECRET_WORDS for token in re.split(r"[_.-]+", spaced))


def _mask_param(param: re.Match[str]) -> str:
    if _secret_name(param.group(2)):
        return f"{param.group(1)}{param.group(2)}=***"
    return param.group(0)


def _mask_secret_params(url: re.Match[str]) -> str:
    return _QUERY_PARAM.sub(_mask_param, url.group(0))


def redact_url(text: str) -> str:
    """Mask any ``scheme://user:pass@`` credential, and any secret-named query parameter.

    Applied to free text (a driver's error message, a config value echoed
    back), not only to values known to be URLs. An address written with no
    scheme (``user:pass@host:8080``) has its userinfo masked too
    (``settings_masking.masked_bare_userinfo``).
    """
    from maljan.core.settings_masking import masked_bare_userinfo

    redacted = _URL_SPAN.sub(_mask_secret_params, _CREDENTIAL_IN_URL.sub(r"\1***@", text))
    return masked_bare_userinfo(redacted)
