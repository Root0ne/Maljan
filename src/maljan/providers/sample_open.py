"""A sample a server opens once per job: the open tool answered from the job's note.

Some analysis servers reset what they have analysed when their "open the
sample" tool is called again: Ghidra's ``load_program`` imports the file afresh
in the place of the analysed program, and a disassembler's open may drop its
analysis the same way. A model that opens the sample again before each question
then reads a program with no call or code reference. Which tool opens a sample,
which selects one already open and which runs the analysis is the server's own
fact, so each server declares it as data (``MCPServerConfig.sample_open``) and
nothing here names a server or a tool.

Per job and per server the platform keeps a note of each path once it has been
opened (and analysed, where an analysis tool is declared). A later open of the
same path with the same options is answered from the note with the first open's
own answer; where a select tool is declared it is sent first, and only a select
the server refuses (it restarted, the program is gone) opens and analyses the
path afresh and writes the note again. An open the server refused, or an
analysis it did not confirm, is not noted, so the next open tries again. A lock
per path makes concurrent first opens import once.

The note is keyed by one reading of the path, and the opener sends that same
string: nothing is tidied that the server might read another way. A path the
opener cannot key safely is not refused: it is forwarded to the server as the
model wrote it and never noted, so there is no note to borrow or poison. The
job's own copy of the sample (the held path) is platform data and is compared
exactly; a relative name is read against it only where the job holds one.

The same opener serves a model's tool call (``wrap_open_tool``) and the
platform's own passes that speak to the server another way: each hands it a
function that calls one tool by name.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import posixpath
import threading
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from maljan.core.logger import logger

__all__ = [
    "REMOTE_TRANSPORTS",
    "SELECT_REFUSED_AFTER_OPEN",
    "OpenedSample",
    "SampleNotes",
    "SampleOpener",
    "answer_field",
    "answer_object",
    "declared",
    "is_refusal",
    "long_running_tools",
    "new_instance",
    "open_key",
    "path_refusal",
    "server_note_key",
    "wrap_open_tool",
]

# How much of a server's own words a refusal handed on carries, each.
SAID_LIMIT = 500

# How often a coroutine waiting for another's first open of the same path looks again.
LOCK_POLL_SECONDS = 0.05

# The marker of a select the server refused right after a fresh open.
SELECT_REFUSED_AFTER_OPEN = "select_refused_after_open"

# Said in the log when an open is answered from the note.
ANSWERED_FROM_NOTE = (
    "%s: %s of %s answered from the job's note (opened as %r); the server was not asked to open it"
)


@dataclass(frozen=True)
class OpenedSample:
    """A path one job opened on one server: the name the server gave it, and the open's answer."""

    name: str
    answer: str


def _options_key(arguments: dict[str, Any] | None) -> str:
    """The open tool's other arguments in one canonical JSON spelling, part of the note's key."""
    return json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), default=str)


class SampleNotes:
    """The paths one job has opened on each server, with a lock per path.

    Keyed by the server, the path exactly as the opener keyed and sent it, and
    the open's other arguments: an open with other options is another note.
    One per job (the job's container holds it), never shared between jobs, and
    safe across the job's threads and loops.
    """

    def __init__(self) -> None:
        self._opened: dict[tuple[str, str, str], OpenedSample] = {}
        self._locks: dict[tuple[str, str, str], threading.Lock] = {}
        self._guard = threading.Lock()

    def get(
        self, server: str, path: str, arguments: dict[str, Any] | None = None
    ) -> OpenedSample | None:
        with self._guard:
            return self._opened.get((server, path, _options_key(arguments)))

    def note(
        self,
        server: str,
        path: str,
        name: str,
        answer: str,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Note ``path`` as opened under ``name``.

        Any other note of the same server under the same name is dropped: the
        server's open of this path replaced the program it named, so a select
        of that name would now read this one.
        """
        if not path:
            return
        named = name or path
        key = (server, path, _options_key(arguments))
        with self._guard:
            for other in [
                k
                for k, v in self._opened.items()
                if k[0] == server and k != key and v.name == named
            ]:
                del self._opened[other]
            self._opened[key] = OpenedSample(name=named, answer=answer)

    def forget(self, server: str, path: str, arguments: dict[str, Any] | None = None) -> None:
        with self._guard:
            self._opened.pop((server, path, _options_key(arguments)), None)

    def lock(
        self, server: str, path: str, arguments: dict[str, Any] | None = None
    ) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault((server, path, _options_key(arguments)), threading.Lock())


# The transports that reach a running server at an address: every handle that
# names the same address speaks to the same server, and to what it opened.
REMOTE_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})

# The hosts that name this machine itself, read as one.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Each handle or provider that starts a local server process gets one of these:
# a process holds only what it opened, and a number never reused names it.
_INSTANCES = itertools.count(1)


def new_instance() -> str:
    """A name for one local server process, never reused in this process's life."""
    return f"process {next(_INSTANCES)}"


def server_note_key(config: Any, instance: str = "") -> str:
    """The server a note belongs to: its address, or its command and the process ``instance``.

    A remote server is keyed by its scheme, host, port and path, the host read
    as one name for this machine whichever loopback spelling names it, the
    default port written, and the transport left out: every handle to one
    server (a registry handle, a static provider's, a handle for another
    loop) shares a note. A local server is a process per handle, which holds
    only what that process opened, so ``instance`` (``new_instance``) names
    the process.
    """
    transport = str(getattr(config, "transport", "") or "stdio")
    url = str(getattr(config, "url", "") or "").strip()
    if transport in REMOTE_TRANSPORTS and url:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return f"remote {url.rstrip('/')}"
        scheme = (parts.scheme or "http").lower()
        host = (parts.hostname or "").lower()
        host = "loopback" if host in _LOOPBACK_HOSTS else host
        port = port or _DEFAULT_PORTS.get(scheme, 0)
        return f"remote {scheme}://{host}:{port}{parts.path.rstrip('/')}"
    parts_ = [str(getattr(config, "command", "") or "")]
    parts_ += [str(a) for a in getattr(config, "args", None) or []]
    return f"stdio {' '.join(parts_).strip()} ({instance})"


def declared(spec: Any) -> bool:
    """Whether ``spec`` (a ``SampleOpenConfig`` or ``None``) declares an open tool."""
    return bool(spec is not None and getattr(spec, "open_tool", "") and spec.path_argument)


def is_refusal(answer: Any) -> bool:
    """Whether a tool's answer is a failure, by the one rule the ledger reads failures with."""
    from maljan.tools.errors import error_parts

    return error_parts(answer) is not None


def path_refusal(path: Any) -> str | None:
    """Why a model's ``path`` cannot key a note, or ``None`` when it can.

    Only for a path that is not the job's own copy of the sample. Nothing is
    rewritten that the server might read another way: a spelling with a
    backslash, a percent sign, a control character, surrounding blanks, a
    doubled separator, a ``.`` or ``..`` segment, a trailing slash, or a
    relative one, is not keyed, because the server resolves its own symlinks,
    case and mounts and may land somewhere a lexical tidy-up does not. Such a
    path is forwarded as written and never noted.
    """
    if not isinstance(path, str) or not path:
        return "no path was given"
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in path):
        return "the path holds a control character"
    if path != path.strip():
        return "the path has blanks around it"
    if "\\" in path:
        return "the path holds a backslash"
    if "%" in path:
        return "the path holds a percent sign, which may be read as an encoding"
    if not path.startswith("/"):
        return "the path is relative"
    if path != "/" and path.endswith("/"):
        return "the path ends in a separator"
    segments = path.split("/")[1:]
    if "" in segments:
        return "the path holds a doubled separator"
    if any(segment in (".", "..") for segment in segments):
        return "the path holds a . or .. segment"
    return None


def open_key(path: Any, held: str | None = None) -> str | None:
    """The one spelling an open of ``path`` is keyed by and sent as, or ``None`` when it is
    forwarded as written and not noted.

    ``held`` is the job's own copy of the sample on this server: platform
    data, compared exactly and never held to the spelling rules. ``path``
    equal to it, or a relative name that read against its directory is it,
    keys as ``held``. Any other path, with a held copy, is another file (a
    carved payload, say) and is forwarded. With no held copy, a path the
    spelling rules accept keys as itself.
    """
    if held:
        if path == held:
            return held
        if (
            isinstance(path, str)
            and path
            and not path.startswith("/")
            and path_refusal("/" + path) is None
            and posixpath.dirname(held).rstrip("/") + "/" + path == held
        ):
            return held
        return None
    return path if path_refusal(path) is None else None


def answer_object(answer: Any) -> dict[str, Any] | None:
    """A tool's answer as a JSON object, or ``None``: the one reader of answer fields."""
    if isinstance(answer, dict):
        return answer
    try:
        payload = json.loads(str(answer))
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def answer_field(answer: Any, field: str) -> str | None:
    """A text field of a tool's JSON answer, non-blank, or ``None``."""
    payload = answer_object(answer) if field else None
    value = payload.get(field) if payload is not None else None
    return value if isinstance(value, str) and value.strip() else None


def _opened_name(answer: str, field: str, path: str) -> str:
    """The name the server gave what it opened, for the select and analysis tools.

    Read from the declared field of the open's answer, else the path. It is
    what those tools are given, and the name under which an older note of the
    same server is dropped; the note answering an open is found by its path
    and options alone.
    """
    return answer_field(answer, field) or path


class SampleOpener:
    """Opens one server's sample through its declared tools, once per path per job."""

    def __init__(self, server: str, spec: Any, notes: SampleNotes) -> None:
        self.server = server
        self.spec = spec
        self.notes = notes

    def _select_args(self, name: str) -> dict[str, Any]:
        argument = self.spec.select_argument
        return {argument: name} if argument else {}

    def _analyse_args(self, name: str) -> dict[str, Any]:
        argument = self.spec.analyse_argument
        return {argument: name} if argument else {}

    def _open_args(self, path: Any, arguments: dict[str, Any] | None) -> dict[str, Any]:
        return {**(arguments or {}), self.spec.path_argument: path}

    def _forwarded(self, path: Any) -> None:
        logger.info(
            "%s: %s of %r forwarded as written and not noted: %s",
            self.server,
            self.spec.open_tool,
            path,
            path_refusal(path) or "it is not the job's own sample",
        )

    def _from_note(self, path: str, noted: OpenedSample) -> str:
        logger.info(ANSWERED_FROM_NOTE, self.server, self.spec.open_tool, path, noted.name)
        return noted.answer

    def _refused_select(self, path: str, answer: Any, arguments: dict[str, Any] | None) -> None:
        logger.info(
            "%s: %s of the noted %s was refused (%s); opening it afresh",
            self.server,
            self.spec.select_tool,
            path,
            str(answer)[:160],
        )
        self.notes.forget(self.server, path, arguments)

    def _refused_after_open(self, name: str, opened: str, selected: Any) -> str | None:
        """The answer for a select refused right after a fresh open, or ``None`` when it answered.

        What the server reads next is then not known to be what it opened, so
        neither analysis nor note follows, and the open is handed on as failed:
        the select's refusal, with the open's own answer beside it, so the
        ledger and the model see that the open did not take.
        """
        if not is_refusal(selected):
            return None
        logger.warning(
            "%s: %s of %s after opening it was refused (%s); the open is not noted",
            self.server,
            self.spec.select_tool,
            name,
            str(selected)[:160],
        )
        return json.dumps(
            {
                "tool_error": SELECT_REFUSED_AFTER_OPEN,
                "tool": self.spec.select_tool,
                "detail": f"{self.spec.select_tool} refused what {self.spec.open_tool} opened: "
                f"{str(selected)[:SAID_LIMIT]}; {self.spec.open_tool} answered: "
                f"{str(opened)[:SAID_LIMIT]}",
            }
        )

    def _after_analysis(
        self,
        path: str,
        name: str,
        opened: str,
        analysed: Any,
        arguments: dict[str, Any] | None,
    ) -> str:
        if analysed is not None and is_refusal(analysed):
            logger.warning(
                "%s: %s of %s was not confirmed (%s); the open is not noted",
                self.server,
                self.spec.analyse_tool,
                name,
                str(analysed)[:160],
            )
            return opened
        self.notes.note(self.server, path, name, opened, arguments)
        return opened

    async def aopen(
        self,
        path: Any,
        call: Callable[[str, dict[str, Any]], Awaitable[Any]],
        arguments: dict[str, Any] | None = None,
        held: str | None = None,
    ) -> str:
        """Open ``path`` with ``call`` (one tool by name, awaited), or answer from the note.

        ``path`` is read once (``open_key``, against the job's ``held`` copy
        when there is one); that one spelling is the note's key and the
        argument every declared tool is sent. A path it cannot key is
        forwarded as written and not noted.
        """
        key = open_key(path, held)
        if key is None:
            self._forwarded(path)
            return str(await call(self.spec.open_tool, self._open_args(path, arguments)))
        lock = self.notes.lock(self.server, key, arguments)
        # Taken without blocking the loop, and so that a call cancelled while
        # it waits never holds the lock: the holder may be another coroutine
        # of this same loop, or a pass on another thread.
        while not lock.acquire(blocking=False):
            await asyncio.sleep(LOCK_POLL_SECONDS)
        try:
            noted = self.notes.get(self.server, key, arguments)
            if noted is not None:
                if not self.spec.select_tool:
                    return self._from_note(key, noted)
                selected = await call(self.spec.select_tool, self._select_args(noted.name))
                if not is_refusal(selected):
                    return self._from_note(key, noted)
                self._refused_select(key, selected, arguments)
            opened = str(await call(self.spec.open_tool, self._open_args(key, arguments)))
            if is_refusal(opened):
                return opened
            name = _opened_name(opened, self.spec.name_field, key)
            if self.spec.select_tool:
                selected = await call(self.spec.select_tool, self._select_args(name))
                refused = self._refused_after_open(name, opened, selected)
                if refused is not None:
                    return refused
            analysed = (
                await call(self.spec.analyse_tool, self._analyse_args(name))
                if self.spec.analyse_tool
                else None
            )
            return self._after_analysis(key, name, opened, analysed, arguments)
        finally:
            lock.release()

    def open(
        self,
        path: Any,
        call: Callable[[str, dict[str, Any]], Any],
        arguments: dict[str, Any] | None = None,
        held: str | None = None,
    ) -> str:
        """Open ``path`` with ``call`` (one tool by name), or answer from the note; ``path``
        read once, as :meth:`aopen` reads it."""
        key = open_key(path, held)
        if key is None:
            self._forwarded(path)
            return str(call(self.spec.open_tool, self._open_args(path, arguments)))
        with self.notes.lock(self.server, key, arguments):
            noted = self.notes.get(self.server, key, arguments)
            if noted is not None:
                if not self.spec.select_tool:
                    return self._from_note(key, noted)
                selected = call(self.spec.select_tool, self._select_args(noted.name))
                if not is_refusal(selected):
                    return self._from_note(key, noted)
                self._refused_select(key, selected, arguments)
            opened = str(call(self.spec.open_tool, self._open_args(key, arguments)))
            if is_refusal(opened):
                return opened
            name = _opened_name(opened, self.spec.name_field, key)
            if self.spec.select_tool:
                selected = call(self.spec.select_tool, self._select_args(name))
                refused = self._refused_after_open(name, opened, selected)
                if refused is not None:
                    return refused
            analysed = (
                call(self.spec.analyse_tool, self._analyse_args(name))
                if self.spec.analyse_tool
                else None
            )
            return self._after_analysis(key, name, opened, analysed, arguments)

    def name_of(self, path: str, arguments: dict[str, Any] | None = None) -> str | None:
        """The name the noted open of ``path`` gave it, or ``None`` when it is not noted."""
        noted = self.notes.get(self.server, path, arguments)
        return noted.name if noted is not None else None


def wrap_open_tool(
    tools: Sequence[Any],
    every_tool: Sequence[Any],
    *,
    server: str,
    spec: Any,
    notes: SampleNotes | None,
    held_path: Callable[[], str | None] | None = None,
) -> list[Any]:
    """``tools`` with the declared open tool answered through the job's note.

    ``every_tool`` is the server's whole manifest, allow-list aside: a select
    or analysis tool the model is not offered is still the server's to call.
    ``held_path``, when given, answers the job's own copy of the sample on this
    server (``open_key``). With no declaration, no note store, or no open tool
    among ``tools``, ``tools`` come back as they were.
    """
    from langchain_core.tools import StructuredTool

    if not declared(spec) or notes is None:
        return list(tools)
    by_name = {str(getattr(t, "name", "")): t for t in every_tool}
    raw = by_name.get(spec.open_tool)
    if raw is None or not any(getattr(t, "name", "") == spec.open_tool for t in tools):
        return list(tools)
    missing = [t for t in (spec.select_tool, spec.analyse_tool) if t and t not in by_name]
    if missing:
        # A declaration naming a tool the server does not offer is said, and
        # the open is offered as it is rather than failing every open.
        logger.warning(
            "%s: sample_open names %s, which the server does not offer; %s is offered as it is",
            server,
            ", ".join(missing),
            spec.open_tool,
        )
        return list(tools)
    opener = SampleOpener(server, spec, notes)

    async def call(tool: str, arguments: dict[str, Any]) -> Any:
        found = by_name.get(tool)
        if found is None:
            return json.dumps({"error": f"{server} offers no tool {tool!r}"})
        return await found.ainvoke(arguments)

    async def open_once(**kwargs: Any) -> str:
        path = kwargs.get(spec.path_argument)
        held = held_path() if held_path is not None else None
        rest = {k: v for k, v in kwargs.items() if k != spec.path_argument and v is not None}
        return await opener.aopen(path, call, rest, held=held or None)

    try:
        wrapped = StructuredTool.from_function(
            func=None,
            coroutine=open_once,
            name=raw.name,
            description=raw.description,
            args_schema=raw.args_schema,
            metadata=dict(getattr(raw, "metadata", None) or {}),
        )
    except Exception as exc:  # noqa: BLE001 - a tool that cannot be rebuilt is offered as it is
        logger.warning("%s: %s offered as it is (%s).", server, spec.open_tool, exc)
        return list(tools)
    return [wrapped if getattr(t, "name", "") == spec.open_tool else t for t in tools]


def long_running_tools(spec: Any) -> frozenset[str]:
    """The tools a server's ``sample_open`` declares to open and to analyse a sample.

    Treated as tools the server's own manifest marks long-running
    (``server_guard.ServerGuard``): an import of a large file and its analysis
    take as long as they take, and a client deadline would only abandon a call
    the server is still working on, to be made again by the next open.
    """
    if not declared(spec):
        return frozenset()
    return frozenset(t for t in (spec.open_tool, spec.analyse_tool) if t)
