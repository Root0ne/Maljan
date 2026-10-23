"""The installed provider plugins in the API: listed from metadata, loaded only to run their code.

Listing, the provider choices, the settings pages and every check of a saved
provider id read package metadata and the store (``maljan.core.plugins``):
the API imports no plugin for them, and none at start or after a save. It
loads an allowed plugin only where a request runs that plugin's own code, and
that plugin alone: a save or import that changes a key of an LLM or memory
plugin's own settings block and does not drop that plugin, a connection test
of the plugin, and the memory purge and health check when the selected
backend is a plugin. A block key sent with the value stored for it writes
nothing and loads nothing (a secret is never taken as sent back), and a clear
deletes the stored row without loading anything. A block whose plugin this
process has not loaded is shown from its stored rows.

Those loads follow the stored allow-list and run on one thread of their own,
never on the event loop; a request waits for one at most the budget it is
given (a connection test's, or the health check's own), then goes on without
the plugin. A load that hangs keeps that thread and no request: no second
load starts behind it, so later loads in this process wait until it ends or
the API restarts, and a request no longer waits once a load has outlived its
budget.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import re
import threading
import time
from collections.abc import Iterable, Mapping
from typing import Any

from maljan.core.plugins import (
    ALLOW_LIST_KEY,
    allowed_names,
    installed,
    listing,
    load_named,
    named_settled,
    registry_changes,
    selections,
    usable_list,
)
from maljan.core.settings_annotations import group_for
from maljan.core.settings_catalog import CatalogEntry
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

# A key of an LLM or memory plugin's own settings block: ``core.llm.<id>.*``,
# ``core.memory.<id>.*``.
_BLOCK_KEY = re.compile(r"core\.(?P<block>llm|memory)\.(?P<name>[^.]+)\.(?P<leaf>.+)")

_LOADER = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="plugin-load")
_INFLIGHT_LOCK = threading.Lock()
# The one load running or last run: its future and when it started.
_INFLIGHT: list[tuple[concurrent.futures.Future[None], float] | None] = [None]
_SAID: set[str] = set()


def _start(listed: list[str], entries: list[str]) -> tuple[concurrent.futures.Future[None], float]:
    """The load running now, else a new one of ``entries`` by ``listed``; one at a time."""
    with _INFLIGHT_LOCK:
        held = _INFLIGHT[0]
        if held is not None and not held[0].done():
            return held
        started = (_LOADER.submit(load_named, listed, entries), time.monotonic())
        _INFLIGHT[0] = started
        return started


def _forget_built_settings() -> None:
    """Read the settings afresh after a load: a plugin's own block is read with its model."""
    from app.runtime_config import runtime_config
    from app.services.settings_service import core_settings_cache

    core_settings_cache.invalidate()
    runtime_config.invalidate()


async def load_in_background(allowed: Any, entries: Iterable[str], timeout: float) -> bool:
    """Load the plugins ``entries`` names that ``allowed`` names too, off the event loop.

    Only those, each once (``maljan.core.plugins.load_named``); a plugin this
    process loaded that ``allowed`` no longer names is withdrawn on the way.
    Waits at most ``timeout`` seconds, and not at all behind a load that has
    already run longer than that. True when each of them is tried as it
    returns; one still loading is then simply absent from what the caller reads.
    """
    listed = usable_list(allowed)
    wanted = list(dict.fromkeys(entries))
    if named_settled(listed, wanted):
        return True
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    before = registry_changes()
    while not named_settled(listed, wanted):
        future, started = _start(listed, wanted)
        remaining = deadline - loop.time()
        if remaining <= 0 or (not future.done() and time.monotonic() - started > timeout):
            break
        try:
            await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), remaining)
        except (TimeoutError, Exception):  # noqa: BLE001 — the request goes on without it
            break
    if registry_changes() != before:
        _forget_built_settings()
    done = named_settled(listed, wanted)
    if not done:
        marker = f"{sorted(listed)}:{sorted(wanted)}"
        if marker not in _SAID:
            _SAID.add(marker)
            logger.warning(
                "Loading plugin %s in the API did not finish within %.0f s; the request went "
                "on without it.",
                ", ".join(sorted(wanted)) or "(none)",
                timeout,
            )
    return done


def writes_a_plugin_block(keys: Iterable[str]) -> bool:
    """Whether any of ``keys`` is in the own settings block of an installed LLM or memory plugin.

    Read from package metadata; a shipped provider's block (``llm.openai``,
    ``memory.qdrant``) is no plugin's.
    """
    names: dict[str, set[str]] = {}
    for key in keys:
        match = _BLOCK_KEY.fullmatch(str(key))
        if match is None:
            continue
        kind = match["block"]
        if kind not in names:
            names[kind] = {plugin.name for plugin in installed(kind)}
        if match["name"] in names[kind]:
            return True
    return False


def block_writes(changes: Mapping[str, Any], allowed: Any) -> list[str]:
    """The plugins to load for a change: those whose own settings-block keys ``changes`` writes.

    Only a plugin both the stored list ``allowed`` and the list the change
    leaves name: a change that drops a plugin never loads it, whatever of its
    block it carries.
    """
    listed = set(usable_list(allowed))
    if ALLOW_LIST_KEY in changes:
        listed &= set(usable_list(changes[ALLOW_LIST_KEY]))
    out: list[str] = []
    for key, value in changes.items():
        match = _BLOCK_KEY.fullmatch(str(key))
        # A clear (``None``) deletes the stored row, which needs no model.
        if match is None or value is None:
            continue
        kind, name = match["block"], match["name"]
        if name in allowed_names(kind, listed):
            out.append(f"{kind}:{name}")
    return list(dict.fromkeys(out))


def _canonical(value: Any) -> str | None:
    """``value`` as canonical JSON (keys sorted), or ``None`` when it has no JSON form."""
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return None


def unchanged_block_keys(
    changes: Mapping[str, Any], rows: Iterable[tuple[str, Any, bool]]
) -> set[str]:
    """The keys of installed plugins' own blocks ``changes`` sends with the value stored for them.

    ``rows`` are the stored ``(key, value, is_secret)``. Such a key writes
    nothing, whether its plugin is allowed, loaded or neither: a save or
    import leaves it out and loads no plugin for it. An export carries every
    block as stored, so importing it back unedited loads no plugin. Values
    are compared as canonical JSON, so ``1``, ``1.0`` and ``true`` differ and
    key order does not. A secret row is never compared, nor ever decrypted
    for it: a secret sent is always a write, judged by the secret rules, so
    no answer depends on what a stored secret holds.
    """
    plain = {key: value for key, value, secret in rows if not secret}
    names: dict[str, set[str]] = {}
    out: set[str] = set()
    for key, value in changes.items():
        match = _BLOCK_KEY.fullmatch(str(key))
        if match is None or value is None or key not in plain:
            continue
        sent = _canonical(value)
        if sent is None or sent != _canonical(plain[key]):
            continue
        kind = match["block"]
        if kind not in names:
            names[kind] = {plugin.name for plugin in installed(kind)}
        if match["name"] in names[kind]:
            out.add(key)
    return out


# The settings that select a provider for every agent, beside each agent's own.
_SHARED_SELECTORS = frozenset(
    {"core.llm.provider", "core.static.provider", "core.sandbox.provider", "core.memory.backend"}
)


def selected_plugins(
    core: Mapping[str, Any], allowed: Any, kinds: Iterable[str], agent: str
) -> list[str]:
    """The allowed plugins of ``kinds`` the core overrides ``core`` select for ``agent``.

    ``core`` holds dotted paths. What ``agent`` runs on: the shared provider
    settings, its own ``static_provider``, each team's ``static_provider``
    (a team's choice outranks its members' own at run time) and its own model
    and fallbacks.
    """
    listed = usable_list(allowed)
    wanted = set(kinds)
    own = (
        f"core.agents.definitions.{agent}.",
        f"core.llm.agents.{agent.lower()}.",
        "core.agents.profiles.",
    )
    return list(
        dict.fromkeys(
            f"{kind}:{name}"
            for key, kind, name in selections(core)
            if kind in wanted
            and (key in _SHARED_SELECTORS or key.startswith(own))
            and name in allowed_names(kind, listed)
        )
    )


async def load_written_blocks(changes: Mapping[str, Any], allowed: Any) -> bool:
    """Load the plugins whose own settings block ``changes`` writes, so their model reads it.

    Only those, only when the stored list ``allowed`` names them and the
    change does not drop them (``block_writes``); waits at most a connection
    test's budget (``settings_probes.TIMEOUT``). A save of the allow-list
    alone, or of any key outside a plugin's block, loads nothing.
    """
    wanted = block_writes(changes, allowed)
    if not wanted:
        return True
    from app.services.settings_probes import TIMEOUT

    return await load_in_background(allowed, wanted, TIMEOUT)


async def stored_allow_list(db: AsyncSession) -> list[str]:
    """The stored plugin allow-list."""
    stored = await SettingsService(db).load_overrides()
    return usable_list(stored.get(ALLOW_LIST_KEY))


def _raw_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return "list"
    if isinstance(value, list | dict):
        return "json"
    return "str"


def block_plugin_names() -> dict[str, set[str]]:
    """The installed LLM and memory plugins by kind, read from package metadata."""
    return {kind: {plugin.name for plugin in installed(kind)} for kind in ("llm", "memory")}


def raw_block_entries(
    rows: Iterable[tuple[str, Any, bool]], known: Iterable[str], names: Mapping[str, set[str]]
) -> list[CatalogEntry]:
    """Catalogue entries for the stored rows of plugin blocks this process has not read.

    ``rows`` are the stored ``(key, value, is_secret)``; ``known`` the keys the
    catalogue already holds (a loaded plugin's block is read with its model);
    ``names`` the installed LLM and memory plugins (``block_plugin_names``).
    A row of an installed plugin's own block is shown as stored, typed from
    its value; changing it loads that plugin to read it while the stored list
    allows it, and resetting it removes it without loading anything.
    """
    held = set(known)
    out: list[CatalogEntry] = []
    for key, value, secret in rows:
        match = _BLOCK_KEY.fullmatch(str(key))
        if match is None or key in held:
            continue
        kind, name, leaf = match["block"], match["name"], match["leaf"]
        if name not in names.get(kind, set()):
            continue
        path = key[len("core.") :]
        out.append(
            CatalogEntry(
                key=key,
                namespace="core",
                path=path,
                type="secret" if secret else _raw_type(value),  # type: ignore[arg-type]
                default=None,
                nullable=True,
                choices=None,
                minimum=None,
                maximum=None,
                secret=bool(secret),
                group=group_for(path),
                title=leaf,
                description=(
                    f"Stored for plugin {kind}:{name}, and shown as stored: the API has not "
                    "loaded the plugin, so its own settings model has not read this value. "
                    "Saving a change loads that plugin to read it while the plugin allow-list "
                    "names it; resetting it loads nothing."
                ),
                applies="next_job",
                editable=True,
                reason=None,
                probe=None,
                subgroup=f"{kind}:{name} (as stored)",
            )
        )
    return out


async def stored_block_entries(db: AsyncSession) -> list[CatalogEntry]:
    """``raw_block_entries`` for what the store holds now; nothing is loaded.

    The stored rows are read for it only where an LLM or memory plugin is
    installed: with none, no row can be such a block.
    """
    from app.services.settings_catalog_api import catalog_index

    names = await asyncio.to_thread(block_plugin_names)
    if not any(names.values()):
        return []
    rows = await SettingsService(db)._rows()
    held = [(str(row.key), row.value, bool(row.is_secret)) for row in rows]
    return await asyncio.to_thread(raw_block_entries, held, list(catalog_index()), names)


async def plugins_listing(db: AsyncSession) -> dict[str, Any]:
    """Every installed plugin per kind, with what the stored allow-list says of it.

    Read from package metadata; this loads nothing. A row's load result is
    the API process's own, where the API loaded the plugin for itself.
    """
    allowed = await stored_allow_list(db)
    kinds = await asyncio.to_thread(listing, allowed)
    for kind in kinds:
        for row in kind["plugins"]:
            # This process is the API: its own load result, named as such.
            row["api_state"] = row.pop("process_state")
            row["api_error"] = row.pop("process_error")
    return {"allow_list_key": ALLOW_LIST_KEY, "kinds": kinds}
