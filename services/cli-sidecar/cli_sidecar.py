"""One command-line analysis program, served over MCP from a container of its own.

Shared by the sidecars that each wrap one program (``die-mcp``, ``ilspy-mcp``,
``goresym-mcp``, ``yarax-mcp``, ``oletools-mcp``, ``webcrack-mcp``). It imports
nothing of the platform: each image holds this module, its server and the
program, and nothing else, so a sidecar holds no platform code, credential or
setting beyond its own token.

What every such server does the same way:

* **The sample is read where the deployment put it.** A path argument is
  resolved with ``realpath`` and must name a regular file under one of the
  directories ``MALJAN_SAMPLE_ROOTS`` lists (the container's read-only sample
  mount); anything else is refused, and the refusal names no host path.
* **The program reads the file; nothing runs it.** The program is started
  with the path as an argument, its standard input closed, a scratch working
  directory of its own and only the variables it needs. Nothing here writes,
  copies or changes the mode of a sample.
* **A failure is an answer in one shape.** ``{"error": {"code", "message",
  "remediation"}, "tool"}``, with the codes the platform's own tool servers
  use: a program that is not installed is ``missing_dependency`` with the
  install hint, a program that ran past ``TOOL_TIMEOUT_SECONDS`` is
  ``timeout``, a path outside the roots is ``path_outside_roots``.
* **No bound of its own on the answer.** The program's whole output is read
  and parsed in one pass; the time bound is the operator's
  (``TOOL_TIMEOUT_SECONDS``, unset for none) and the caller's call timeout.
* **The capabilities tool says what the host can run**, in the shape the
  platform's registry reads: each tool with whether its program is present
  and, when it is not, why and how to install it.

``serve`` runs the server over streamable HTTP (``MCP_BIND_ADDRESS``,
``MCP_PORT``, ``MCP_AUTH_TOKEN``; a bind beyond loopback is refused without a
token) or, with ``--stdio``, over standard input and output for an operator
who installs the program on the worker's host instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
import shutil
import signal
import sys
import tempfile
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("cli_sidecar")

# The codes, as the platform's tool servers write them (``maljan.tools.errors``).
MISSING_DEPENDENCY = "missing_dependency"
TIMEOUT = "timeout"
BAD_ARGUMENT = "bad_argument"
NO_SUCH_FILE = "no_such_file"
PATH_OUTSIDE_ROOTS = "path_outside_roots"
UNSUPPORTED_FORMAT = "unsupported_format"
TOOL_FAILED = "tool_failed"

REMEDIATIONS: dict[str, str] = {
    TIMEOUT: (
        "raise TOOL_TIMEOUT_SECONDS on this server, or the call timeout of its block, or ask "
        "for less"
    ),
    BAD_ARGUMENT: (
        "check the argument names and types against the tool's manifest and call it again"
    ),
    NO_SUCH_FILE: (
        "the file this call named is not there; leave the path argument out to read the file "
        "this call was given"
    ),
    PATH_OUTSIDE_ROOTS: (
        "this server reads the files under the sample directories it was given; leave the "
        "path argument out to read the file this call was given"
    ),
    UNSUPPORTED_FORMAT: "this tool reads another format; use a tool for the format the file is",
    TOOL_FAILED: (
        "read the message; if it names nothing you can change, report it with the server log"
    ),
}

# The variables a sidecar reads.
SAMPLE_ROOTS_ENV = "MALJAN_SAMPLE_ROOTS"
TIMEOUT_ENV = "TOOL_TIMEOUT_SECONDS"
BIND_ENV = "MCP_BIND_ADDRESS"
PORT_ENV = "MCP_PORT"
TOKEN_ENV = "MCP_AUTH_TOKEN"

# What the refusal of a path says. No path in it: the argument it is about is
# the one part of the answer the sample's author may have written.
OUTSIDE_ROOTS_MESSAGE = "the path argument is outside the directories this server may read"

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def tool_error(
    code: str, message: str, *, tool: str, remediation: str | None = None
) -> dict[str, Any]:
    """The structured failure for ``code``, with its remediation."""
    hint = remediation or REMEDIATIONS.get(code, REMEDIATIONS[TOOL_FAILED])
    return {"error": {"code": code, "message": message, "remediation": hint}, "tool": tool}


class ToolFailure(Exception):
    """A tool's answer is a failure: raised inside a tool, answered by :func:`answering`."""

    def __init__(self, code: str, message: str, remediation: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation


# ---------------------------------------------------------------------------
# The program
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """The command-line program a sidecar serves, and how it is found and installed.

    ``command`` is what is started before the tool's own arguments: the
    program's name on ``PATH``, or an interpreter and the file it runs.
    ``files`` are files the command needs besides its first word (a .NET
    tool's assembly). ``install`` is the sentence a missing program's answer
    and the capabilities tool give as the remedy.
    """

    name: str
    command: tuple[str, ...]
    install: str
    files: tuple[str, ...] = ()
    # Variables the program needs, by value; nothing else of this process's
    # environment reaches it but ``PATH``.
    env: Mapping[str, str] = field(default_factory=dict)

    def absent(self) -> str | None:
        """``None`` when the program can be started, else why it cannot."""
        if not shutil.which(self.command[0]):
            return f"{self.command[0]} is not on PATH"
        for name in self.files:
            if not Path(name).is_file():
                return f"{Path(name).name} is not installed"
        return None


@dataclass(frozen=True)
class Ran:
    """What one run of the program left: its exit status and both streams, whole."""

    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def said(self) -> str:
        """The program's own words about a failure: its standard error, else its output."""
        text = self.stderr.decode("utf-8", "replace").strip()
        return text or self.stdout.decode("utf-8", "replace").strip()


def timeout_seconds() -> float | None:
    """The operator's bound on one run, from ``TOOL_TIMEOUT_SECONDS``; ``None`` for none."""
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number of seconds; runs have no bound.", TIMEOUT_ENV, raw)
        return None
    return value if value > 0 else None


async def run(program: Program, arguments: Sequence[str]) -> Ran:
    """Run ``program`` with ``arguments`` and wait for it; raises :class:`ToolFailure`.

    Missing, it is ``missing_dependency`` with the install hint; past the
    operator's bound, ``timeout``. A caller that gives up (a cancelled call)
    kills it, so no run outlives the call that started it.
    """
    absent = program.absent()
    if absent:
        raise ToolFailure(MISSING_DEPENDENCY, absent, program.install)
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        **program.env,
    }
    with tempfile.TemporaryDirectory(prefix=f"{program.name}-") as scratch:
        env.setdefault("HOME", scratch)
        env.setdefault("TMPDIR", scratch)
        try:
            process = await asyncio.create_subprocess_exec(
                *program.command,
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=scratch,
                env=env,
                # A process group of its own, so stopping the run stops every
                # process the program started, and none keeps its output open.
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ToolFailure(
                MISSING_DEPENDENCY, f"{program.command[0]} could not be started", program.install
            ) from exc
        bound = timeout_seconds()
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), bound)
        except TimeoutError as exc:
            await _stop(process)
            raise ToolFailure(
                TIMEOUT, f"{program.name} did not finish within {bound:g} s ({TIMEOUT_ENV})"
            ) from exc
        except asyncio.CancelledError:
            await _stop(process)
            raise
    return Ran(int(process.returncode or 0), stdout, stderr)


async def _stop(process: asyncio.subprocess.Process) -> None:
    """Kill the run's whole process group and reap the program."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        process.kill()
    with contextlib.suppress(Exception):
        await process.wait()


async def run_ok(program: Program, arguments: Sequence[str]) -> Ran:
    """:func:`run`, with a non-zero exit status a ``tool_failed`` naming the program's words."""
    ran = await run(program, arguments)
    if ran.returncode != 0:
        said = ran.said or "no output"
        raise ToolFailure(TOOL_FAILED, f"{program.name} exited with {ran.returncode}: {said}")
    return ran


def option_value(name: str, value: str) -> str:
    """``value`` for a program option, refused where the program would read it as an option."""
    text = str(value or "").strip()
    if not text:
        raise ToolFailure(BAD_ARGUMENT, f"{name} is empty")
    if "\0" in text:
        raise ToolFailure(BAD_ARGUMENT, f"{name} holds a NUL character")
    if text.startswith("-"):
        raise ToolFailure(BAD_ARGUMENT, f"{name} may not start with '-'")
    return text


def json_document(text: str, program: str) -> Any:
    """The JSON document ``text`` holds, read from its first ``{`` or else its first ``[``.

    A program that writes a line of its own before its document (a banner, a
    warning, even one with a bracket in it) still answers; one that wrote none
    is a ``tool_failed``. At most two reads, each in one pass.
    """
    starts = sorted(at for at in (text.find("{"), text.find("[")) if at >= 0)
    if not starts:
        raise ToolFailure(TOOL_FAILED, f"{program} wrote no JSON document")
    said = ""
    for at in starts:
        try:
            value, _end = json.JSONDecoder().raw_decode(text, at)
        except ValueError as exc:
            said = said or str(exc)
            continue
        return value
    raise ToolFailure(TOOL_FAILED, f"{program} wrote JSON that does not parse: {said}")


# ---------------------------------------------------------------------------
# The sample
# ---------------------------------------------------------------------------


def sample_roots() -> list[Path]:
    """The directories a path argument may be under, from ``MALJAN_SAMPLE_ROOTS``.

    Empty when the variable is unset: such a server reads nothing.
    """
    raw = os.environ.get(SAMPLE_ROOTS_ENV, "")
    return [Path(os.path.realpath(part)) for part in raw.split(os.pathsep) if part.strip()]


def sample_file(path: str) -> str:
    """``path`` resolved, when it names a regular file under a sample root; else a failure."""
    if not isinstance(path, str) or not path.strip():
        raise ToolFailure(BAD_ARGUMENT, "path names no file")
    if "\0" in path:
        raise ToolFailure(BAD_ARGUMENT, "path holds a NUL character")
    resolved = Path(os.path.realpath(path))
    if not any(resolved == root or root in resolved.parents for root in sample_roots()):
        raise ToolFailure(PATH_OUTSIDE_ROOTS, OUTSIDE_ROOTS_MESSAGE)
    if not resolved.is_file():
        raise ToolFailure(NO_SUCH_FILE, "the file the path argument names is not there")
    return str(resolved)


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


async def answering(tool: str, work: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
    """``work``'s answer, or its failure in the one shape; a tool server answers, never raises."""
    try:
        return await work()
    except ToolFailure as failure:
        return tool_error(failure.code, failure.message, tool=tool, remediation=failure.remediation)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        logger.exception("%s failed", tool)
        return tool_error(TOOL_FAILED, f"{type(exc).__name__}: {exc}", tool=tool)


def capabilities(
    server: str, program: Program, tools: Iterable[str], version: str = "unknown"
) -> dict[str, Any]:
    """The capability manifest the platform's registry reads (``capabilities`` tool).

    Probed now: each of ``tools`` needs ``program``, so each is available
    exactly when the program can be started, and says why not and how to
    install it when it cannot.
    """
    absent = program.absent()
    cells = []
    for name in tools:
        cell: dict[str, Any] = {
            "name": name,
            "optional_dependency": program.name,
            "available": absent is None,
            "reason": absent,
            "timeout_s": timeout_seconds(),
        }
        if absent:
            cell["remediation"] = program.install
        cells.append(cell)
    return {"server": server, "version": version, "tools": cells}


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


class BearerGate:
    """An ASGI wrapper that answers 401 to an HTTP request without the server's token."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            given = dict(scope.get("headers") or ()).get(b"authorization", b"")
            if not hmac.compare_digest(given, self._expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"text/plain")],
                    }
                )
                await send({"type": "http.response.body", "body": b"unauthorized\n"})
                return
        await self.app(scope, receive, send)


def bind_refusal(bind: str, token: str) -> str:
    """Why the server may not listen on ``bind`` with ``token``; ``""`` when it may."""
    if bind not in _LOOPBACK and not token:
        return (
            f"{BIND_ENV}={bind} listens beyond loopback, and {TOKEN_ENV} is empty: set the "
            "token (and the same token as this server's auth_token in the console)"
        )
    return ""


def serve(mcp: Any, argv: Sequence[str] | None = None) -> None:
    """Run ``mcp`` over streamable HTTP, or over stdio when ``--stdio`` is given."""
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    args = list(sys.argv[1:] if argv is None else argv)
    if "--stdio" in args:
        mcp.run(transport="stdio")
        return
    import uvicorn

    bind = os.environ.get(BIND_ENV, "127.0.0.1").strip() or "127.0.0.1"
    token = os.environ.get(TOKEN_ENV, "").strip()
    refused = bind_refusal(bind, token)
    if refused:
        logger.error("%s", refused)
        raise SystemExit(1)
    port = int(os.environ.get(PORT_ENV, "8080"))
    app = mcp.streamable_http_app()
    uvicorn.run(BearerGate(app, token) if token else app, host=bind, port=port, log_level="info")
