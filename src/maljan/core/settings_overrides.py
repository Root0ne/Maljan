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

import re
from collections.abc import Iterable, Mapping
from functools import cache
from typing import Any, Literal

from pydantic import BaseModel

from maljan.core.config import STORE_ONLY, Settings
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
    token = STORE_ONLY.set(True)
    try:
        return Settings(**nest(declarations_in_force(core_overrides)))
    finally:
        STORE_ONLY.reset(token)


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
    return dict(held) if isinstance(held, Mapping) else {}


def _block_in_force(block: str, stored: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """What one block's stored tool declarations put in force, and the changes refused."""
    return stored_in_force(shipped_tool_facts(block), stored, where=block)


def server_entry_in_force(name: str, entry: Any) -> Any:
    """One stored server entry with its tool declarations as they are in force.

    A stored entry's ``tool_facts`` marked as changes hold its changes over
    what the server ships (``tool_declarations.stored_in_force``): in force
    they are the shipped ones with those changes over them. One without the
    mark was stored whole by an earlier release and is in force as stored.
    An entry that sets no tool declarations is returned as it is, and takes
    the shipped ones on load.
    """
    if not isinstance(entry, Mapping) or not isinstance(entry.get(TOOL_FACTS_FIELD), Mapping):
        return entry
    in_force, _refused = _block_in_force(f"{SERVER_MAP_PATH}.{name}", entry[TOOL_FACTS_FIELD])
    return {**entry, TOOL_FACTS_FIELD: in_force}


def _stored_blocks(core_overrides: Mapping[str, Any]) -> Iterable[tuple[str, Any]]:
    """Each stored map of a block's tool declarations, with the block's dotted path."""
    for key, value in core_overrides.items():
        if not isinstance(value, Mapping):
            continue
        if key == SERVER_MAP_PATH:
            for name, entry in value.items():
                if isinstance(entry, Mapping) and isinstance(entry.get(TOOL_FACTS_FIELD), Mapping):
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
    settings. Every other key is passed through unchanged.
    """
    out = dict(core_overrides)
    for key, value in core_overrides.items():
        if not isinstance(value, Mapping):
            continue
        if key == SERVER_MAP_PATH:
            out[key] = {name: server_entry_in_force(name, entry) for name, entry in value.items()}
        elif key.endswith(_TOOL_FACTS_SUFFIX):
            out[key] = _block_in_force(key.removesuffix(_TOOL_FACTS_SUFFIX), value)[0]
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


# ``mcp.servers.<key>.env.<VAR>`` after flattening: an open-ended mapping an
# admin fills in, and the natural place for a server's own credential (a token
# a sidecar reads from its environment).
_SERVER_ENV_VALUE = re.compile(r"^mcp\.servers\.[^.]+\.env\.")


def public_snapshot(settings: Settings, secret_keys: Iterable[str]) -> dict[str, Any]:
    """The settings as they ran, with nothing in them a reader may not see.

    ``secret_keys`` names the leaves typed as secrets. To those this adds
    the one place a credential can live without being typed as one: a
    server's ``env`` map. This snapshot reaches the job owner
    through ``run_summary.settings_snapshot``, so every value under such a map
    is masked. The variable names stay -- an operator debugging a server needs
    to see what it was handed -- and only the values go.
    """
    secrets = set(secret_keys)
    snap = flatten(settings.model_dump(mode="json"))
    for key in list(snap):
        if key in secrets or _SERVER_ENV_VALUE.match(key):
            snap[key] = "***" if snap[key] else None
    return snap


def declaration_blocks(settings: Settings) -> dict[str, str]:
    """Each server block's dotted path, by the source its declaration is read under."""
    from maljan.core.tool_declarations import PROVIDER_BLOCKS

    blocks = {f"mcp:{key}": f"mcp.servers.{key}" for key in settings.mcp.servers}
    blocks.update(PROVIDER_BLOCKS)
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

    stored_map = overrides.get("mcp.servers")
    stored_map = stored_map if isinstance(stored_map, Mapping) else {}
    kept_prefixes: list[str] = []
    dropped_prefixes: list[str] = []
    for path in declaration_blocks(settings).values():
        for name in SNAPSHOT_DIGESTED_FIELDS:
            field_path = f"{path}.{name}"
            if path.startswith("mcp.servers."):
                entry = stored_map.get(path.removeprefix("mcp.servers."))
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
    for source, digest in sorted(ToolDeclarations.from_settings(settings).digests().items()):
        out[f"declaration_digest.{source}"] = digest
    out["declaration_digest.shipped"] = shipped_digest()
    return out


# Everything between "://" and the LAST "@" before the path is userinfo. Greedy
# on purpose: a password may itself contain "@" or ":" and the username may be
# empty (redis://:password@host is the usual Redis AUTH shape).
_CREDENTIAL_IN_URL = re.compile(r"(://)[^\s/@]*(?:@[^\s/@]*)*@")


def redact_url(text: str) -> str:
    """Mask any ``scheme://user:pass@`` credential in ``text`` before it is shown.

    Applied to free text (a driver's error message, a config value echoed
    back), not only to values known to be URLs.
    """
    return _CREDENTIAL_IN_URL.sub(r"\1***@", text)
