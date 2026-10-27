"""A server's declared error patterns, applied to its answers by one function.

Many MCP servers answer an error as ordinary text ("No file is currently
open.", "Invalid params: ...") rather than as an MCP error, and the ledger
would file such an answer as a successful call. A server's declaration says
how its answers say "error" (``MCPServerConfig.error_patterns``,
``core.tool_declarations.ErrorPattern``); :func:`declared_error` holds an
answer against those patterns, and :func:`with_declared_errors` rebuilds a
tool so a matching answer comes back as the structured failure every reader
files as one (``schemas.evidence.build_entry``). Every server's tools pass
through it: the registry's servers in ``ServerHandle.tools``, the static
providers' in their own ``get_tools``. An adapter that adds a step of its
own around a failure (radare2 analysing the function at an address and
asking again) reads the same function and keeps only its own step.

A server that declares no pattern keeps its tools as they are, the same
objects, so nothing changes for it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from maljan.core.logger import logger
from maljan.core.tool_declarations import ErrorPattern
from maljan.tools.errors import error_parts, tool_error

PROTOCOL_ERROR = "protocol_error"
ANSWER = "answer"


def declared_error(
    patterns: Sequence[ErrorPattern], tool: str, reply: Any
) -> tuple[ErrorPattern, str, str] | None:
    """``(pattern, message, target)`` for the first declared pattern ``reply`` is, else ``None``.

    A reply that is the client's failure marker (an MCP protocol error, or any
    structured failure) is held against the patterns that apply to protocol
    errors, by its message; any text reply, a marker no such pattern matched
    included, against the patterns that apply to answers. Patterns are held
    in their declared order.
    """
    if not patterns:
        return None
    if isinstance(reply, dict) or (isinstance(reply, str) and reply.lstrip().startswith("{")):
        parts = error_parts(reply)
        if parts is not None:
            _code, message, _remediation = parts
            for pattern in patterns:
                if pattern.message(tool, message, target=PROTOCOL_ERROR) is not None:
                    return pattern, message, PROTOCOL_ERROR
    if not isinstance(reply, str):
        return None
    text = reply.strip()
    for pattern in patterns:
        said = pattern.message(tool, text)
        if said is not None:
            return pattern, said, ANSWER
    return None


def declared_failure(
    patterns: Sequence[ErrorPattern], tool: str, reply: Any, sample_path: str | None = None
) -> dict[str, Any] | None:
    """The structured failure ``reply`` is by the declared patterns, else ``None``.

    Filed under the pattern's code, with its remediation naming
    ``sample_path`` where the pattern has a form for it.
    """
    found = declared_error(patterns, tool, reply)
    if found is None:
        return None
    pattern, message, _target = found
    remediation = pattern.remediation_for(sample_path) or None
    return tool_error(pattern.code, message, tool=tool, remediation=remediation)


def with_declared_errors(
    tools: list[Any],
    patterns: Sequence[ErrorPattern],
    sample_path: Callable[[], str | None] | None = None,
) -> list[Any]:
    """``tools``, each rebuilt so an answer a declared pattern matches is its structured failure.

    ``sample_path`` answers, at call time, the path the server can open for
    the job's sample, which a remediation may name. No pattern: the tools as
    they are. A tool that cannot be rebuilt faithfully is kept as it is.
    """
    if not patterns:
        return tools
    return [_rebuilt(tool, tuple(patterns), sample_path) for tool in tools]


def _rebuilt(
    tool: Any, patterns: tuple[ErrorPattern, ...], sample_path: Callable[[], str | None] | None
) -> Any:
    from maljan.agents.server_names import ServerNamedTool

    coroutine = getattr(tool, "coroutine", None)
    args_schema = getattr(tool, "args_schema", None)
    if coroutine is None or args_schema is None:
        return tool
    name = str(getattr(tool, "name", "") or "")

    async def _call(**kwargs: Any) -> Any:
        reply = await coroutine(**kwargs)
        failure = declared_failure(
            patterns, name, reply, sample_path() if sample_path is not None else None
        )
        return json.dumps(failure) if failure is not None else reply

    try:
        return ServerNamedTool.from_function(
            func=None,
            coroutine=_call,
            name=name,
            description=getattr(tool, "description", ""),
            args_schema=args_schema,
            infer_schema=False,
            metadata=dict(getattr(tool, "metadata", None) or {}),
        )
    except Exception as exc:  # noqa: BLE001 — the tool as it was beats no tool
        logger.warning("declared errors: tool '%s' kept as it is (%s).", name, exc)
        return tool
