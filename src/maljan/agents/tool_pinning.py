"""Correct a model that calls a tool with the wrong spelling of the sample path.

The prompt tells the model the absolute path; a 7-9B local model told the path
will still send the bare file name, and there is no recovering from that
downstream — the tool answers "File not found" and the agent spends its whole
step budget retrying. So when an argument that is *named* like a path arrives
holding a name that can only mean this sample, it is replaced with the path
the tool's own server can open, and the substitution is logged.

What counts as "can only mean this sample" is three spellings, and getting the
set wrong is how the guard silently stops guarding:

* the worker path's own basename — what the prompt header showed the model;
* the target path's basename — different from the first whenever a server was
  handed the sample under a name of its own;
* the worker path in full — correct for a local sidecar and unopenable by a
  remote server, so it has to be rewritten there.

Deliberately narrow otherwise. A model that supplied some other directory meant
that directory, and a tool reading a dropped file or a rule file keeps the name
it was given.

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

# The argument names that mean "the file under analysis" and nothing else.
# These are the platform's to fill and are not advertised to the model at all:
# a model that cannot see the argument cannot mistype it, and one live run
# spent a static analyst's whole step budget on a sample path with three
# characters missing and then on guessing directories.
#
# A *qualified* path name is not here and stays the model's to give:
# ``pcap_path`` names a capture, ``rule_path`` a rule file, ``member_path`` a
# member inside an archive or an APK. Those are choices, and the sample is not.
SAMPLE_ARG_NAMES = frozenset(
    {
        "path",
        "file",
        "file_path",
        "filepath",
        "file_name",
        "filename",
        "input_file",
        "target_file",
        "binary",
        "sample",
        "sample_path",
        "target",
        "program",
    }
)

# The servers whose path-taking tools read the sample the platform staged for
# them. The other built-ins take a hash or a name, and a server an operator
# added is theirs: this project does not narrow what its tools advertise.
PINNED_SERVERS = frozenset({"analysis", "knowledge", "network"})

# How the worker hands a server that cannot see this filesystem the sample's
# bytes. It is the platform's delivery primitive and never an analysis step, so
# it is not in the toolbox the model is shown — a live run called it with
# ``{"sha256": "null", "content_b64": ""}`` and was told, correctly, that the
# empty string's digest is not the sample's.
DELIVERY_TOOLS = frozenset(
    {"put_sample", "put_sample_begin", "put_sample_chunk", "put_sample_finish"}
)


def is_path_argument(name: str) -> bool:
    """Whether an argument's name says it holds a file or a path."""
    lowered = name.lower()
    return any(s in lowered for s in _PATH_ARG_SUBSTRINGS) or lowered in _PATH_ARG_NAMES


def names_the_sample(argument: str) -> bool:
    """Whether this argument's name means the file under analysis."""
    return argument.strip().lower() in SAMPLE_ARG_NAMES


def server_of(tool: Any) -> str:
    """The server key a tool came from, or ``""`` for an in-process tool."""
    metadata = getattr(tool, "metadata", None) or {}
    return str(metadata.get(SERVER_METADATA_KEY, "") or "")


def _spellings(default_path: str | None, target: str) -> frozenset[str]:
    """The argument values that can only mean this sample, for one tool.

    Separating the values matched from the value substituted is the whole
    point. Matching only on the basename of the *target* leaves the guard
    watching for a name the model was never shown: a server handed the sample
    as ``<sha16>_evil.exe`` would only be corrected if the model volunteered
    that name, while the prompt header told it ``evil.exe``.
    """
    return frozenset(
        value
        for value in (
            os.path.basename(default_path) if default_path else "",
            os.path.basename(target),
            default_path or "",
        )
        if value and value != target
    )


def _basenames(default_path: str | None, target: str) -> frozenset[str]:
    """The file names that can only be this sample, wherever they are written.

    The third spelling a local model produces, after the bare name and the
    worker path: the right file name under a directory that does not exist. A
    live run sent ``/home/user/Belleges/.../<sample>`` -- one letter wrong in a
    directory the model half-remembered from the prompt -- and the tool
    answered "no such file" for the rest of the loop.
    """
    return frozenset(
        name
        for name in (
            os.path.basename(default_path) if default_path else "",
            os.path.basename(target),
        )
        if name
    )


def pin_paths(
    tools: list[Any],
    *,
    default_path: str | None,
    path_by_server: dict[str, str] | None = None,
    agent_name: str = "",
) -> list[BaseTool]:
    """Every tool, each guarded against a path argument this sample's own name.

    With no pinned path and no per-server map the tools are returned exactly as
    they are, unwrapped: the guard costs nothing when there is nothing to
    correct, and an unwrapped tool is one less thing between the model and the
    server.
    """
    per_server = dict(path_by_server or {})
    offered = [tool for tool in tools if getattr(tool, "name", "") not in DELIVERY_TOOLS]
    if not default_path and not per_server:
        return list(offered)
    out: list[Any] = []
    for tool in offered:
        server = server_of(tool)
        target = per_server.get(server) or default_path
        if not target:
            out.append(tool)
            continue
        hidden = _sample_arguments(tool) if server in PINNED_SERVERS else ()
        out.append(
            _pin_tool(
                tool,
                target,
                _spellings(default_path, target),
                _basenames(default_path, target),
                agent_name,
                hidden,
            )
        )
    return out


def _sample_arguments(tool: Any) -> tuple[str, ...]:
    """The arguments of ``tool`` that name the sample, in its declared order."""
    fields = getattr(getattr(tool, "args_schema", None), "model_fields", None)
    if not isinstance(fields, dict):
        return ()
    return tuple(name for name in fields if names_the_sample(name))


def _schema_without(args_schema: Any, hidden: tuple[str, ...]) -> Any:
    """``args_schema`` with ``hidden`` gone, or ``None`` when it cannot be rebuilt.

    The model binds to this, so a field that is not in it is a field the model
    never sees and cannot get wrong. The original schema is untouched: it is
    shared with the server registry, and the platform's own calls still go
    through the unwrapped tool.
    """
    from pydantic import create_model

    fields = getattr(args_schema, "model_fields", None)
    if not isinstance(fields, dict):
        return None
    kept = {name: (field.annotation, field) for name, field in fields.items() if name not in hidden}
    try:
        return create_model(getattr(args_schema, "__name__", "Args"), **kept)  # type: ignore[call-overload]
    except Exception as exc:  # noqa: BLE001 — a guardrail never costs a tool
        logger.warning("tool_pinning: the schema for a pinned tool could not be narrowed: %s", exc)
        return None


def _pin_tool(
    tool: Any,
    pinned: str,
    spellings: frozenset[str],
    basenames: frozenset[str],
    agent_name: str,
    hidden: tuple[str, ...] = (),
) -> Any:
    """Rebuild one tool with its path arguments corrected.

    ``hidden`` is the arguments that name the sample on a built-in server.
    They are taken out of the schema the model binds to and filled here, so the
    model neither sees nor types them; everything else keeps the narrow
    correction below, which is all a tool naming some other file needs.

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
    # The schema the model binds to, minus the arguments it has no business
    # naming. A schema that cannot be rebuilt leaves the arguments where they
    # are and falls back to the correction alone, which is what this did for
    # every tool before.
    narrowed = _schema_without(args_schema, hidden) if hidden else None
    if hidden and narrowed is None:
        hidden = ()
    args_schema = narrowed or args_schema

    def _means_this_sample(value: str) -> bool:
        """Whether a path argument can only be the sample, spelled wrongly.

        Two ways: one of the spellings the model was shown, or the sample's own
        file name under a directory that holds no such file. The second stays
        narrow because of the existence check -- a model that named a real file
        elsewhere named a real file, and only a path that leads nowhere is
        worth second-guessing.
        """
        if value in spellings:
            return True
        if value == pinned or os.path.basename(value) not in basenames:
            return False
        return not os.path.exists(value)

    def _correct(kwargs: dict[str, Any]) -> dict[str, Any]:
        out = dict(kwargs)
        # The sample's own path, supplied rather than asked for.
        for key in hidden:
            out[key] = pinned
        for key, value in kwargs.items():
            if isinstance(value, str) and is_path_argument(key) and _means_this_sample(value):
                logger.warning(
                    "%s: tool '%s' was called with %r for argument '%s'; "
                    "substituting the path this server can open, %r.",
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
