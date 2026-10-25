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
# And the workflow text the server declares (its ``prompt_fragment``), carried
# with each of its tools so a prompt built from the tool list shows it exactly
# where the server's tools are (``prompt_fragments.tools_statement``).
SERVER_FRAGMENT_METADATA_KEY = "maljan_server_fragment"
# What a server that declares no workflow text says about itself and its tools
# (``prompt_fragments.undeclared_server_text``), carried the same way: shown
# only while the server's tools are in the request, and never read as a
# template, being the server's words and not a declaration.
SERVER_OWN_WORDS_METADATA_KEY = "maljan_server_own_words"
# The name a server declares a tool under, set on a tool the request offers
# renamed (``<server>__<tool>``): the declaration is read by it, never by
# taking a prefix off the offered name.
DECLARED_NAME_METADATA_KEY = "maljan_declared_name"
# Set on a tool its own server marks read-only (MCP ``readOnlyHint`` true).
READ_ONLY_METADATA_KEY = "maljan_read_only"
# The MCP hints its own server gave a tool when it was attached
# (``core.declared_reading.SERVER_HINTS``), kept on each of its entries for
# the run's tool-effects part (``analysis.tool_effects``).
SERVER_HINTS_METADATA_KEY = "maljan_server_hints"

# An argument whose *name* looks like it takes a file. Substring matches cover
# ``file``, ``file_path``, ``filepath``, ``filename``, ``path``, ``target_file``;
# the exact set covers the few path arguments that are named for what they hold
# rather than for being a path.
#
# The name test is the narrowing half of the rule, not an extra: value equality
# on its own would rewrite ``{"query": "<sha>.exe"}`` too, turning a model that
# legitimately names the file in prose into one that passes a path. ``input``
# was dropped from the exact set for the same reason — a lookup tool taking free
# text as ``input`` is the one plausible false positive here. ``program`` is not
# in it either: a decompiler names a program in its project with it (Ghidra's
# ``program`` is "Program name (default: current program)"), and rewriting the
# name the model gave into the file path made every such call fail.
_PATH_ARG_SUBSTRINGS = ("path", "file")
_PATH_ARG_NAMES = frozenset({"binary", "sample", "target"})

# The argument names that mean "the file under analysis" and nothing else.
# These are the platform's to fill and are not advertised to the model at all:
# a model that cannot see the argument cannot mistype it, and one live run
# spent a static analyst's whole step budget on a sample path with three
# characters missing and then on guessing directories.
#
# A *qualified* path name is not here and stays the model's to give:
# ``pcap_path`` names a capture, ``rule_path`` a rule file, ``member_path`` a
# member inside an archive or an APK. Those are choices, and the sample is not
# — except a capture when the job has exactly one, which leaves nothing to
# choose and is filled the same way (``CAPTURE_ARG_NAMES``).
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
    }
)


# How the worker hands a server that cannot see this filesystem the sample's
# bytes, reads back a file the server wrote (``get_artefact``, for the job's
# artefact store, ``pipeline.artefacts``), and runs one of the platform's own
# readings of the sample there (``run_reader``, ``tools.readers``). They are
# the platform's delivery primitives and never an analysis step, so they are
# not in the toolbox the model is shown — a live run called ``put_sample`` with
# ``{"sha256": "null", "content_b64": ""}`` and was told, correctly, that the
# empty string's digest is not the sample's.
DELIVERY_TOOLS = frozenset(
    {
        "put_sample",
        "put_sample_begin",
        "put_sample_chunk",
        "put_sample_finish",
        "get_artefact",
        "run_reader",
    }
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


def declared_source_of(tool: Any) -> str | None:
    """Where a tool's declaration lives (``core.tool_declarations``), as the tool was built.

    A registry server's tool is ``mcp:<key>``; a provider's or the sandbox
    report's tool carries the source it was stamped with when it was attached
    (``prompt_fragments.stamp_source``). A team ``ask_`` tool, or a tool
    nothing stamped, has none: it is never guessed from the tool's name.
    """
    from maljan.agents.delegation import TEAM_SERVER
    from maljan.agents.prompt_fragments import DECLARED_SOURCE_METADATA_KEY

    metadata = getattr(tool, "metadata", None) or {}
    stamped = str(metadata.get(DECLARED_SOURCE_METADATA_KEY, "") or "")
    if stamped:
        return stamped
    server = server_of(tool)
    if server and server != TEAM_SERVER:
        return f"mcp:{server}"
    return None


def reads_staged_sample(tool: Any) -> bool:
    """Whether ``tool``'s source declares that its tools read the sample the platform staged.

    The declaration's ``reads_staged_sample`` (``core.tool_declarations``),
    read by the source the tool was built under (:func:`declared_source_of`)
    from the live declarations. Such a source's sample argument is hidden from
    the model and filled, and its capture argument filled when the job has one
    capture; any other source's tools advertise what they advertise. A tool
    nothing stamped, or whose source declares nothing, reads no staged sample.
    """
    source = declared_source_of(tool)
    if source is None:
        return False
    try:
        from maljan.core.declared_reading import declarations

        held = declarations().source(source)
    except Exception as exc:  # noqa: BLE001 — an unreadable declaration declares nothing
        logger.debug("staged-sample declaration of a tool not read (%s).", type(exc).__name__)
        return False
    return bool(held is not None and held.reads_staged_sample)


def declared_name_of(tool: Any) -> str:
    """The name a tool's source declares it under: its original when it was renamed, else its own."""
    metadata = getattr(tool, "metadata", None) or {}
    return str(metadata.get(DECLARED_NAME_METADATA_KEY) or getattr(tool, "name", "") or "")


def declared_facts_of(tool: Any) -> Any:
    """What a tool declares about itself (``core.tool_declarations.ToolFacts``), or ``None``.

    Read by the source the tool was built under (:func:`declared_source_of`)
    and the name it is declared under (:func:`declared_name_of`), from the live declarations: what the
    request is about to offer, never a persisted record. A tool nothing
    stamped, or whose source declares nothing for it, has none; it is never
    guessed from the tool's name.
    """
    source = declared_source_of(tool)
    if source is None:
        return None
    try:
        from maljan.core.declared_reading import declarations

        return declarations().declaration_for((source, declared_name_of(tool)), exact=True)
    except Exception as exc:  # noqa: BLE001 — an unreadable declaration declares nothing
        logger.debug("declared facts of a tool not read (%s).", type(exc).__name__)
        return None


def _spellings(
    default_path: str | None, target: str, staged_path: str | None = None
) -> frozenset[str]:
    """The argument values that can only mean this sample, for one tool.

    Separating the values matched from the value substituted is the whole
    point. Matching only on the basename of the *target* leaves the guard
    watching for a name the model was never shown: a server handed the sample
    as ``<sha16>_evil.exe`` would only be corrected if the model volunteered
    that name, while the prompt header told it ``evil.exe``.

    ``staged_path`` is the worker's own copy of the sample, in full: a real
    file on this host, so the existence check never corrects it, and one a
    server reading its own mirror may refuse. radare2 will not open a path
    with a ``/.`` segment, and an r2 analyst sent the staging path beside the
    mirror it had been given.
    """
    return frozenset(
        value
        for value in (
            os.path.basename(default_path) if default_path else "",
            os.path.basename(target),
            default_path or "",
            staged_path or "",
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
    captures: tuple[str, ...] | list[str] = (),
    staged_path: str | None = None,
) -> list[BaseTool]:
    """Every tool, each guarded against a path argument this sample's own name.

    ``captures`` is the job's packet captures. With exactly one, the capture
    argument of a server that declares it reads the staged sample
    (:func:`reads_staged_sample`) is hidden from the model and filled with it, the
    way the sample's own path is: the network analyst of one live run spent
    eight of its twenty calls on capture names it had to invent, because
    nothing it was shown named the capture. With several the argument stays
    the model's to give, and a refusal lists them.

    ``staged_path`` is the worker's copy of the sample, which can only mean
    this sample and is replaced with the path each tool's server opens.

    With no pinned path, no per-server map and no single capture the tools are
    returned exactly as they are, unwrapped: the guard costs nothing when there
    is nothing to correct, and an unwrapped tool is one less thing between the
    model and the server.
    """
    per_server = dict(path_by_server or {})
    capture = captures[0] if len(captures) == 1 else ""
    offered = [tool for tool in tools if getattr(tool, "name", "") not in DELIVERY_TOOLS]
    if not default_path and not per_server and not capture:
        return list(offered)
    out: list[Any] = []
    for tool in offered:
        server = server_of(tool)
        target = per_server.get(server) or default_path or ""
        pinned_server = reads_staged_sample(tool)
        hidden = _sample_arguments(tool) if pinned_server and target else ()
        filled = (
            dict.fromkeys(_capture_arguments(tool), capture) if pinned_server and capture else {}
        )
        if not target and not filled:
            out.append(tool)
            continue
        out.append(
            _pin_tool(
                tool,
                target,
                _spellings(default_path, target, staged_path) if target else frozenset(),
                _basenames(default_path, target) if target else frozenset(),
                agent_name,
                hidden,
                filled,
            )
        )
    return out


# The argument names that mean "the job's packet capture". Qualified, so they
# are never the sample; hidden and filled only when the job has one capture.
CAPTURE_ARG_NAMES = frozenset({"pcap_path"})


# What a caller is told when the capture the platform filled in could not be
# read. The argument is hidden, so the server's own advice — pass another
# capture — names a call the model cannot make.
UNREADABLE_FILLED_CAPTURE = (
    "the platform filled {argument} with this run's capture, {capture}, and the server "
    "could not read it: {message}"
)
UNREADABLE_FILLED_CAPTURE_REMEDIATION = (
    "the capture argument is filled by the platform and is not yours to give; read the "
    "sandbox's network view instead, and the failure stays on the run's record for the operator"
)


def _unreadable_filled_capture(tool: str, reply: Any, supplied: dict[str, str]) -> Any:
    """``reply``, or, when it is a path failure, the failure of the capture the platform filled."""
    import json

    from maljan.tools.errors import (
        NO_SUCH_FILE,
        PATH_OUTSIDE_ROOTS,
        error_parts,
        tool_error,
    )
    from maljan.tools.staging import job_relative

    parts = error_parts(reply)
    if parts is None or parts[0] not in (PATH_OUTSIDE_ROOTS, NO_SUCH_FILE):
        return reply
    argument, capture = next(iter(supplied.items()))
    failure = tool_error(
        parts[0],
        UNREADABLE_FILLED_CAPTURE.format(
            argument=argument, capture=job_relative(capture), message=parts[1]
        ),
        tool=tool,
        remediation=UNREADABLE_FILLED_CAPTURE_REMEDIATION,
    )
    return failure if isinstance(reply, dict) else json.dumps(failure)


def _capture_arguments(tool: Any) -> tuple[str, ...]:
    """The arguments of ``tool`` that name a packet capture, in its declared order."""
    from maljan.agents.server_names import server_names

    names = server_names(getattr(tool, "args_schema", None))
    return tuple(name for name in names if name.strip().lower() in CAPTURE_ARG_NAMES)


def _sample_arguments(tool: Any) -> tuple[str, ...]:
    """The arguments of ``tool`` that name the sample, in its declared order."""
    from maljan.agents.server_names import server_names

    names = server_names(getattr(tool, "args_schema", None))
    return tuple(name for name in names if names_the_sample(name))


def _schema_without(args_schema: Any, hidden: tuple[str, ...]) -> Any:
    """``args_schema`` with ``hidden`` gone, or ``None`` when it cannot be rebuilt.

    The model binds to this, so a field that is not in it is a field the model
    never sees and cannot get wrong. The original schema is untouched: it is
    shared with the server registry, and the platform's own calls still go
    through the unwrapped tool.
    """
    from maljan.agents.null_arguments import argument_model, rules_of, without_fields

    fields = getattr(args_schema, "model_fields", None)
    if not isinstance(fields, dict):
        return None
    # ``hidden`` names the server's arguments (``agents.server_names``).
    kept = {
        name: (field.annotation, field)
        for name, field in fields.items()
        if (name if field.alias is None else field.alias) not in hidden
    }
    try:
        # What the tool does with a ``null`` goes with the fields it keeps
        # (``agents.null_arguments``): a hidden field is the platform's to
        # fill, so a ``null`` the model wrote for it is neither dropped nor
        # withheld.
        return argument_model(
            getattr(args_schema, "__name__", "Args"),
            kept,
            without_fields(rules_of(args_schema), hidden),
        )
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
    filled: dict[str, str] | None = None,
) -> Any:
    """Rebuild one tool with its path arguments corrected.

    ``hidden`` is the arguments that name the sample on a server that declares
    it reads the staged sample (:func:`reads_staged_sample`), and
    ``filled`` the other arguments the platform supplies, each with its value
    (the job's one capture). Both are taken out of the schema the model binds
    to and filled here, so the model neither sees nor types them; everything
    else keeps the narrow correction below, which is all a tool naming some
    other file needs.

    A fresh tool is built rather than mutating the original: the resolved tool
    object is shared with the server registry, and an in-place wrap would leak
    this sample's path into the next agent that borrows it. Fail-safe —
    anything unexpected keeps the original tool.
    """
    from maljan.agents.server_names import ServerNamedTool, to_server_names

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
    supplied = dict(filled or {})
    # The schema the model binds to, minus the arguments it has no business
    # naming. A schema that cannot be rebuilt leaves the arguments where they
    # are and falls back to the correction alone, which is what this did for
    # every tool before.
    taken = (*hidden, *supplied)
    narrowed = _schema_without(args_schema, taken) if taken else None
    if taken and narrowed is None:
        hidden = ()
        supplied = {}
    args_schema = narrowed or args_schema

    def _means_this_sample(value: str) -> bool:
        """Whether a path argument can only be the sample, spelled wrongly.

        Two ways: one of the spellings the model was shown, or the sample's own
        file name under a directory that holds no such file. The second stays
        narrow because of the existence check -- a model that named a real file
        elsewhere named a real file, and only a path that leads nowhere is
        worth second-guessing.
        """
        if not pinned:
            return False
        if value in spellings:
            return True
        if value == pinned or os.path.basename(value) not in basenames:
            return False
        return not os.path.exists(value)

    held = args_schema

    def _correct(kwargs: dict[str, Any]) -> dict[str, Any]:
        # By the server's names, as ``hidden`` and ``supplied`` are.
        kwargs = to_server_names(held, kwargs)
        out = dict(kwargs)
        # The sample's own path, supplied rather than asked for.
        for key in hidden:
            out[key] = pinned
        # And the job's one capture, the same way.
        out.update(supplied)
        for key, value in kwargs.items():
            if key in supplied:
                continue
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

    def _told(reply: Any) -> Any:
        """The reply, or the failure of a capture the platform filled in, said as one."""
        return _unreadable_filled_capture(name, reply, supplied) if supplied else reply

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> Any:  # noqa: F811
            return _told(func(**_correct(kwargs)))

    if coroutine is not None:

        async def wrapped_coroutine(**kwargs: Any) -> Any:  # noqa: F811
            return _told(await coroutine(**_correct(kwargs)))

    try:
        return ServerNamedTool.from_function(
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


def answers_again(tool: Any) -> bool:
    """Whether an identical call of ``tool`` answers the same: it changes nothing.

    True for a tool its own server marks read-only (MCP ``readOnlyHint``,
    carried as ``metadata["maljan_read_only"]``) or whose declaration marks it
    read-only or idempotent (``ToolFacts.read_only``). Any other tool, and one
    nothing says anything about, may change state or answer differently later
    (a rename, a status poll), so it is not.
    """
    metadata = getattr(tool, "metadata", None) or {}
    if metadata.get(READ_ONLY_METADATA_KEY) is True:
        return True
    facts = declared_facts_of(tool)
    return bool(facts is not None and getattr(facts, "read_only", False) is True)
