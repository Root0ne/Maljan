"""An operator-written prompt that names a tool its agent does not have.

An agent definition may carry a prompt of its own, and an operator writes it
against the tool servers ticked at the time. Later a server is unticked,
swapped or renamed, and the prompt goes on telling the agent to use a tool it
no longer has, with nothing saying so. This module finds those names.

A name counts only when it is a tool name the platform knows somewhere (a tool
a configured server declares or allow-lists, or a shipped declaration of a
built-in server or static provider) and is absent from this agent's set. An
ordinary word that no declaration spells that way never counts, and no tool is
singled out: the candidates are read from the declarations alone.

The result is advisory. Nothing here refuses a save or a run, and nothing the
model is sent changes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from maljan.core.logger import logger

# Two readings of the prompt, both linear: runs of word characters, and runs
# between blanks and quoting punctuation, so a declared name holding ``-`` or
# ``.`` is still found whole.
_WORDS = re.compile(r"[A-Za-z0-9_]+")
_CHUNKS = re.compile(r"[^\s\"'`()\[\]{},;:<>]+")
_RENAMED = "__"
# A name set off in backticks or quotes, with no blank inside it.
_QUOTED = re.compile(r"`([^`\s]+)`|\"([^\"\s]+)\"|'([^'\s]+)'")


def _facts_names(block: Any) -> Iterable[str]:
    facts = (
        block.get("tool_facts") if isinstance(block, dict) else getattr(block, "tool_facts", None)
    )
    return [str(name) for name in (facts or {})]


def known_tool_names(settings: Any) -> frozenset[str]:
    """Every tool name the platform knows, across all configured servers and shipped declarations."""
    from maljan.core.builtin_declarations import (
        builtin_server_names,
        provider_names,
    )
    from maljan.core.declared_reading import builtin_tools, tools_in_force

    names: set[str] = set()
    for key, server in settings.mcp.servers.items():
        names.update(_facts_names(server))
        # And each tool its server declared of itself when it attached.
        names.update(str(tool) for tool in tools_in_force(f"mcp:{key}", server))
        names.update(str(tool) for tool in (server.tools or []))
    for key in builtin_server_names():
        names.update(str(tool) for tool in builtin_tools(key))
    for provider in provider_names():
        names.update(_provider_tool_names(provider))
    return frozenset(names)


def _provider_tool_names(provider: str) -> set[str]:
    """The tool names a static provider declares, and what it declared of itself when listed."""
    from types import SimpleNamespace

    from maljan.core.builtin_declarations import provider_declaration
    from maljan.core.declared_reading import tools_in_force

    block = provider_declaration(provider)
    names = set(_facts_names(block))
    try:
        facts = block.get("tool_facts") if isinstance(block, dict) else None
        listed = tools_in_force(f"provider:{provider}", SimpleNamespace(tool_facts=facts or {}))
        names.update(str(tool) for tool in listed)
    except Exception as exc:  # noqa: BLE001 - advisory, the declared names stand
        logger.debug("provider %s listing not read: %s", provider, type(exc).__name__)
    return names


def names_in(prompt: str, known: frozenset[str]) -> list[str]:
    """The known tool names ``prompt`` spells exactly, sorted, once each."""
    if not prompt or not known:
        return []
    plain = set(_WORDS.findall(prompt)) | {c.rstrip(".!?") for c in _CHUNKS.findall(prompt)}
    # A bare plain word is prose; only a code-shaped name (it holds a character
    # that is not a letter) or one set off in backticks or quotes is a candidate.
    found = {word for word in plain if not word.isalpha()}
    found |= {name for groups in _QUOTED.findall(prompt) for name in groups if name}
    return sorted(found & known)


def held_names(tool_names: Iterable[str]) -> frozenset[str]:
    """The names a tool set answers to: each tool's own, and a renamed tool's declared one."""
    held: set[str] = set()
    for name in tool_names:
        held.add(name)
        if _RENAMED in name:
            held.add(name.split(_RENAMED, 1)[1])
    return frozenset(held)


def missing_from(definition: Any, known: frozenset[str], held: frozenset[str]) -> list[str]:
    """Known tool names an operator-written prompt names that ``held`` lacks.

    A definition with no prompt of its own (every built-in) has none to check.
    """
    prompt = getattr(definition, "prompt", None)
    if not isinstance(prompt, str):
        return []
    return [name for name in names_in(prompt, known) if name not in held]


def missing_message(key: str, missing: list[str]) -> str:
    """The one sentence the log, the run summary and the settings answer share."""
    return (
        f"agent '{key}': its prompt names tool(s) it does not have: {', '.join(missing)}. "
        "Edit the prompt, or tick the server that offers them."
    )


def note_for_resolved(settings: Any, definition: Any, key: str, tools: Iterable[Any]) -> str | None:
    """The warning for agent ``key`` resolved to ``tools``, logged once, or ``None``. Never raises."""
    try:
        if not isinstance(getattr(definition, "prompt", None), str):
            return None
        held = held_names(str(getattr(t, "name", "")) for t in tools)
        missing = missing_from(definition, known_tool_names(settings), held)
        if not missing:
            return None
        message = missing_message(key, missing)
        logger.warning("%s", message)
        return message
    except Exception as exc:  # noqa: BLE001 - advisory, never blocks a job
        logger.debug("prompt tool check skipped for %s: %s", key, type(exc).__name__)
        return None


def declared_set(settings: Any, key: str, definition: Any) -> frozenset[str]:
    """The tool names agent ``key`` would hold, from declarations alone (no server is opened)."""
    from maljan.agents.composition import servers_bound_to

    held: set[str] = set()
    for name in servers_bound_to(settings, key):
        server = settings.mcp.servers.get(name)
        if server is None:
            continue
        if server.tools is not None:
            held.update(str(t) for t in server.tools)
        else:
            held.update(_facts_names(server))
    # Each provider a ``provider`` reference stands for, as resolution reads
    # them (``composition.referenced_provider_ids``, a team's forced provider
    # included). A later provider's tool whose name an earlier one holds is
    # offered as ``<provider>__<name>`` (``composition._claim_provider_tools``),
    # and is held under both.
    from maljan.agents.composition import referenced_provider_ids, static_provider_id_for

    providers = referenced_provider_ids(settings, definition, static_provider_id_for(settings, key))
    claimed: set[str] = set()
    for provider in providers:
        names = _provider_tool_names(provider)
        held.update(names)
        if len(providers) > 1:
            held.update(f"{provider}__{name}" for name in names if name in claimed)
            claimed.update(names)
    return frozenset(held)


def warnings_for_settings(settings: Any) -> dict[str, str]:
    """Each operator-written prompt's warning, keyed by the definition, from the settings as saved."""
    known = known_tool_names(settings)
    out: dict[str, str] = {}
    for key, definition in settings.agents.definitions.items():
        if not isinstance(getattr(definition, "prompt", None), str):
            continue
        missing = missing_from(definition, known, declared_set(settings, key, definition))
        if missing:
            out[key] = missing_message(key, missing)
    return out
