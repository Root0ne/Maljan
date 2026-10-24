"""Which tool server each of the triage pack's in-process steps reads.

The pack's decoded-strings, capa and carve steps run in this process but stand
in for a server's tool, and read that server's own ``env``. Which server that
is has one answer, here, read by the pack (``pipeline.nodes``) and by the
question "which servers does a job call" (``agents.composition``), so the two
cannot drift.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from functools import partial
from typing import Any

from maljan.core.logger import logger

# The renderers of the pack's decoded-strings step, its capa step and its UPX
# carve. The in-process decoder and capa read the environment of the server
# declaring their tool (``FlossSettings.environ``, ``CapaSettings.environ``);
# the carve writes where the server declaring the unpack tool's kind reads
# (``PackInputs.carve_environ``).
_DECODER_RENDERER = "emulated_strings"
_CAPA_RENDERER = "capability_rules"
_CARVE_RENDERER = "unpacked_image"


def _pack_step_of(renderer: str, steps: Sequence[Any]) -> Any:
    """The step of ``renderer`` in ``steps``, else its shipped declaration, else ``None``."""
    from maljan.core.pack_steps import default_steps

    def _of(held: Sequence[Any]) -> Any:
        return next((s for s in held if getattr(s, "renderer", "") == renderer), None)

    return _of(steps) or _of(default_steps())


def _declared_kind(called: str) -> str:
    """The kind the platform ships for a step's ``called`` tool, ``""`` for none."""
    from maljan.core.declared_reading import shipped_by_name

    facts = shipped_by_name().get(called)
    return str(getattr(facts, "kind", "") or "")


def _declaring_server_key(
    servers: Mapping[str, Any], called: str, *, purpose: str, level: int = logging.INFO
) -> str:
    """The key of the server declaring a step's ``called`` tool or its kind, ``""`` for none.

    The in-process step stands in for that server's tool whether the server
    is switched on or not, so a switched-off server still lends its ``env``.
    Among several, enabled servers come first: those declaring ``called`` by
    name, then those declaring a tool of the same declared kind, each in
    ``mcp.servers`` order; switched-off servers follow in the same order, a
    last resort. When more than one qualifies, or the one read is switched
    off, the choice is logged at ``level``, info by default (the node resolves
    each purpose once per run; a status read asks for debug).
    """
    kind = _declared_kind(called)
    by_name: dict[bool, list[str]] = {True: [], False: []}
    by_kind: dict[bool, list[str]] = {True: [], False: []}
    for key, server in servers.items():
        enabled = bool(getattr(server, "enabled", True))
        facts = getattr(server, "tool_facts", None) or {}
        if called in facts:
            by_name[enabled].append(str(key))
        elif kind and any(getattr(f, "kind", None) == kind for f in facts.values()):
            by_kind[enabled].append(str(key))
    qualified = by_name[True] + by_kind[True] + by_name[False] + by_kind[False]
    if not qualified:
        return ""
    chosen = qualified[0]
    switched_off = chosen in by_name[False] or chosen in by_kind[False]
    if len(qualified) > 1 or switched_off:
        declared = repr(called)
        if by_kind[True] or by_kind[False]:
            declared = f"{called!r} or its kind {kind!r}"
        also = ""
        if len(qualified) > 1:
            also = f"; {', '.join(repr(k) for k in qualified[1:])} also declare {declared}"
        off = " (switched off; its env is still read)" if switched_off else ""
        # ``info`` itself at the default: the worker's line is exactly what it was.
        say = logger.info if level == logging.INFO else partial(logger.log, level)
        say("triage pack: %s reads server %r%s%s.", purpose, chosen, off, also)
    return chosen


def _decoder_server_key(servers: Mapping[str, Any], steps: Sequence[Any]) -> str:
    """The key of the server the pack's decoded-strings step declares, ``""`` for none.

    The step's own ``server`` when it is enabled, else the server declaring
    the tool the step calls (:func:`_declaring_server_key`): the
    server whose tool the in-process step stands in for. With the step left
    out of ``steps`` (switched off), its shipped declaration is read.
    """
    return _step_server_key(servers, steps, _DECODER_RENDERER, purpose="the decoder")


def _step_server_key(
    servers: Mapping[str, Any], steps: Sequence[Any], renderer: str, *, purpose: str
) -> str:
    """The key of the server the pack's ``renderer`` step declares, ``""`` for none.

    Read as :func:`_decoder_server_key` says, for any in-process step.
    """
    step = _pack_step_of(renderer, steps)
    if step is None:
        return ""
    if step.server:
        named = servers.get(step.server)
        if named is not None and getattr(named, "enabled", True):
            return str(step.server)
    return _declaring_server_key(servers, step.called, purpose=purpose)


def _carve_server_key(servers: Mapping[str, Any]) -> str:
    """The key of the server whose file tools read what the pack's UPX carve writes.

    The carve is the platform's own step, so its shipped declaration names
    the tool it stands in for; the server declaring that tool or its kind
    (:func:`_declaring_server_key`) is the one whose staging base the
    carve writes under. Independent of the decoded-strings step: an operator
    who moves that step to another server leaves the carve where it was.
    """
    step = _pack_step_of(_CARVE_RENDERER, ())
    if step is None:
        return ""
    return _declaring_server_key(servers, step.called, purpose="the unpack carve")
