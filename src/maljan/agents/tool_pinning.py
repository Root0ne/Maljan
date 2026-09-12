"""Correct a model that calls a tool with the sample's bare file name.

BUG 11, live 2026-09-07. The prompt tells the model the absolute path; a 7-9B
local model told the path will still send the file name, and there is no
recovering from that downstream — the tool answers "File not found" and the
agent spends its whole step budget retrying. So when an argument that is
*named* like a path arrives holding exactly the sample's own base name, it is
replaced with the pinned absolute path before the call, and the substitution
is logged.

Deliberately narrow. Only the sample's own basename is rewritten, and only when
it arrives bare: a model that supplied a directory meant that directory, and a
tool reading a dropped file or a rule file keeps the name it was given.

``path_by_server`` is the second half, and the reason this moved out of
``ConfigurableAnalyst``: a remote tool server does not see the worker's
filesystem, so the path its tools must be given is the one
``agents.sample_staging`` uploaded the sample to — a different string per
server. ``ServerRegistry.merge_tools`` stamps each tool with the server it came
from, which is what lets one wrapper pick the right path per tool.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

# The metadata key ``ServerRegistry`` stamps a tool with. Read here, written
# there, and named once so the two cannot drift.
SERVER_METADATA_KEY = "maljan_server"

# An argument whose *name* looks like it takes a file. Substring matches cover
# ``file``, ``file_path``, ``filepath``, ``filename``, ``path``, ``target_file``;
# the exact set covers the few path arguments that are named for what they hold
# rather than for being a path.
#
# The name test is the narrowing half of the rule, not an extra: value equality
# on its own would rewrite ``{"query": "<sha>.exe"}`` too, turning a model that
# legitimately names the file in prose into one that passes a path. ``input``
# was dropped from the exact set for the same reason — a lookup tool taking free
# text as ``input`` is the one plausible false positive here.
_PATH_ARG_SUBSTRINGS = ("path", "file")
_PATH_ARG_NAMES = frozenset({"binary", "sample", "target", "program"})


def is_path_argument(name: str) -> bool:
    """Whether an argument's name says it holds a file or a path."""
    lowered = name.lower()
    return any(s in lowered for s in _PATH_ARG_SUBSTRINGS) or lowered in _PATH_ARG_NAMES


def server_of(tool: Any) -> str:
    """The server key a tool came from, or ``""`` for an in-process tool."""
    metadata = getattr(tool, "metadata", None) or {}
    return str(metadata.get(SERVER_METADATA_KEY, "") or "")


def pin_paths(
    tools: list[Any],
    *,
    default_path: str | None,
    path_by_server: dict[str, str] | None = None,
    agent_name: str = "",
) -> list[BaseTool]:
    """Every tool, each guarded against the bare-filename call.

    With no pinned path and no per-server map the tools are returned exactly as
    they are, unwrapped: the guard costs nothing when there is nothing to
    correct, and an unwrapped tool is one less thing between the model and the
    server.
    """
    per_server = dict(path_by_server or {})
    if not default_path and not per_server:
        return list(tools)
    out: list[Any] = []
    for tool in tools:
        pinned = per_server.get(server_of(tool)) or default_path
        out.append(_pin_tool(tool, pinned, agent_name) if pinned else tool)
    return out


def _pin_tool(tool: Any, pinned: str, agent_name: str) -> Any:
    """Rebuild one tool with its path arguments corrected.

    A fresh tool is built rather than mutating the original: the resolved tool
    object is shared with the server registry, and an in-place wrap would leak
    this sample's path into the next agent that borrows it. Fail-safe —
    anything unexpected keeps the original tool.
    """
    from langchain_core.tools import StructuredTool

    func = getattr(tool, "func", None)
    coroutine = getattr(tool, "coroutine", None)
    if func is None and coroutine is None:
        return tool
    args_schema = getattr(tool, "args_schema", None)
    if args_schema is None:
        # Rebuilding with ``infer_schema=False`` and no schema does not raise —
        # the non-empty description short-circuits the only ValueError — it
        # silently yields a schema-less tool that binds badly. A tool the guard
        # cannot rebuild faithfully is better left exactly as it is.
        return tool

    name = getattr(tool, "name", "")
    base = os.path.basename(pinned)

    def _correct(kwargs: dict[str, Any]) -> dict[str, Any]:
        out = dict(kwargs)
        for key, value in kwargs.items():
            if value == base and isinstance(value, str) and is_path_argument(key):
                logger.warning(
                    "%s: tool '%s' was called with the bare sample name %r for "
                    "argument '%s'; substituting the known absolute path %r.",
                    agent_name or "agent",
                    name,
                    value,
                    key,
                    pinned,
                )
                out[key] = pinned
        return out

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> Any:  # noqa: F811
            return func(**_correct(kwargs))

    if coroutine is not None:

        async def wrapped_coroutine(**kwargs: Any) -> Any:  # noqa: F811
            return await coroutine(**_correct(kwargs))

    try:
        return StructuredTool.from_function(
            func=wrapped_func,
            coroutine=wrapped_coroutine,
            name=name,
            description=getattr(tool, "description", ""),
            args_schema=args_schema,
            infer_schema=False,
            metadata=getattr(tool, "metadata", None),
        )
    except Exception as exc:  # noqa: BLE001 — a guardrail never costs a tool
        logger.warning("%s: path guard skipped for tool '%s': %s", agent_name or "agent", name, exc)
        return tool
