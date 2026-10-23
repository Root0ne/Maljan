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
import hashlib
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
    "ANALYSIS_REFUSED_AFTER_OPEN",
    "FOREIGN_PROGRAM",
    "NO_JOB_PROGRAM",
    "REMOTE_TRANSPORTS",
    "is_shared_address",
    "SELECT_REFUSED_AFTER_OPEN",
    "OpenedSample",
    "SampleNotes",
    "SampleOpener",
    "answer_field",
    "aclose_job_programs",
    "answer_object",
    "close_job_programs",
    "declared",
    "is_refusal",
    "long_running_tools",
    "new_instance",
    "open_key",
    "open_path_arguments",
    "path_refusal",
    "pin_program_argument",
    "program_argument",
    "program_arguments",
    "refused_after_open",
    "server_note_key",
    "wrap_open_tool",
]

# How much of a server's own words a refusal handed on carries, each.
SAID_LIMIT = 500

# How often a coroutine waiting for another's first open of the same path looks again.
LOCK_POLL_SECONDS = 0.05

# The marker of a select the server refused right after a fresh open.
SELECT_REFUSED_AFTER_OPEN = "select_refused_after_open"

# The marker of a declared analysis step the server refused right after a fresh open.
ANALYSIS_REFUSED_AFTER_OPEN = "analysis_refused_after_open"

# The code of a call that named a program this job did not open on the server.
FOREIGN_PROGRAM = "foreign_program"

# The code of a call that names no program, on a shared server, before the job opened one.
NO_JOB_PROGRAM = "no_job_program"

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
        # Per server: every program name this job opened there, and the one it
        # opened or selected last (the job's own current program).
        self._owned: dict[str, set[str]] = {}
        self._current: dict[str, str] = {}
        self._guard = threading.Lock()

    def make_current(self, server: str, name: str | None) -> None:
        """Note ``name`` as the program this job opened or selected last on ``server``."""
        if not name:
            return
        with self._guard:
            self._owned.setdefault(server, set()).add(name)
            self._current[server] = name

    def own(self, server: str, name: str | None) -> None:
        """Note ``name`` as a program this job opened on ``server``, not as its current one.

        For an open whose select or analysis did not follow: the program is
        open on the server all the same, and the job's teardown closes it.
        """
        if not name:
            return
        with self._guard:
            self._owned.setdefault(server, set()).add(name)

    def take_owned(self, server: str) -> list[str]:
        """Every program name this job opened on ``server``, sorted, forgotten as they are taken."""
        with self._guard:
            names = sorted(self._owned.pop(server, set()))
            self._current.pop(server, None)
        self.drop_named(server, None)
        return names

    def current(self, server: str) -> str | None:
        """The program this job opened or selected last on ``server``, or ``None``."""
        with self._guard:
            return self._current.get(server)

    def owns(self, server: str, name: Any) -> bool:
        """Whether this job opened a program named ``name`` on ``server``."""
        with self._guard:
            return isinstance(name, str) and name in self._owned.get(server, set())

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
        self.make_current(server, named)

    def drop_named(self, server: str, name: str | None) -> None:
        """Drop the server's notes under ``name``, or all of its notes when ``name`` is ``None``.

        For an open the opener forwarded: the server opened something under
        that name and replaced the program a note of it named, so the note
        would answer for a program the server no longer holds. With the name
        unread, every note of the server may be stale.
        """
        with self._guard:
            for key in [
                k
                for k, v in self._opened.items()
                if k[0] == server and (name is None or v.name == name)
            ]:
                del self._opened[key]

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

_DEFAULT_PORTS = {"http": 80, "https": 443}


def is_shared_address(config: Any) -> bool:
    """Whether a server's block reaches it at an address, where other jobs share its programs.

    The one reading of that fact, used by the runtime pins (``pin_program_argument``'s
    ``shared``) and by the declaration proposals alike.
    """
    return str(getattr(config, "transport", "") or "") in REMOTE_TRANSPORTS


# Each handle or provider that starts a local server process gets one of these:
# a process holds only what it opened, and a number never reused names it.
_INSTANCES = itertools.count(1)

# What selects a backend behind one address besides the address itself (the
# query, the userinfo, the credential sent), each distinct combination named
# by an opaque number for this process's life. The note's key carries only the
# number: a key is written into log lines, so neither a secret nor any digest
# of one is ever part of it. The map is held in memory only, keyed by digests.
_BACKENDS: dict[tuple[str, ...], int] = {}
_BACKENDS_LOCK = threading.Lock()


def new_instance() -> str:
    """A name for one local server process, never reused in this process's life."""
    return f"process {next(_INSTANCES)}"


def _backend_ordinal(*selectors: str) -> int:
    """The opaque number of one combination of backend selectors, or ``0`` for none."""
    if not any(selectors):
        return 0
    digest = tuple(hashlib.sha256(s.encode("utf-8")).hexdigest() for s in selectors)
    with _BACKENDS_LOCK:
        if digest not in _BACKENDS:
            _BACKENDS[digest] = len(_BACKENDS) + 1
        return _BACKENDS[digest]


def _secret_text(value: Any) -> str:
    getter = getattr(value, "get_secret_value", None)
    return str(getter() if callable(getter) else value or "")


def server_note_key(config: Any, instance: str = "") -> str:
    """The server a note belongs to: its address, or its command and the process ``instance``.

    A remote server is keyed by its scheme, host, port and path, the host
    lower-cased and the default port written, and the transport left out:
    every handle to one server (a registry handle, a static provider's, a
    handle for another loop) shares a note. Loopback spellings are kept apart
    (``localhost``, ``127.0.0.1`` and ``::1`` may be three listeners), at the
    cost of at most one more open. What may select another backend behind one
    address (the query, the userinfo, the credential sent) adds an opaque
    number (``_backend_ordinal``), never the value. A local server is a
    process per handle, which holds only what that process opened, so
    ``instance`` (``new_instance``) names the process.
    """
    transport = str(getattr(config, "transport", "") or "stdio")
    url = str(getattr(config, "url", "") or "").strip()
    credential = _secret_text(getattr(config, "auth_token", ""))
    if transport in REMOTE_TRANSPORTS and url:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return f"remote (an address not read, backend {_backend_ordinal(url, credential)})"
        scheme = (parts.scheme or "http").lower()
        host = (parts.hostname or "").lower()
        port = port or _DEFAULT_PORTS.get(scheme, 0)
        userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
        address = f"remote {scheme}://{host}:{port}{parts.path.rstrip('/')}"
        ordinal = _backend_ordinal(parts.query, userinfo, credential)
        return f"{address} (backend {ordinal})" if ordinal else address
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


def refused_after_open(
    marker: str, step_tool: str, open_tool: str, refusal: Any, opened: Any
) -> str:
    """The answer for a declared step the server refused right after a fresh open.

    The open is handed on as failed, under ``marker``: the step's refusal
    with the open's own answer beside it, so the ledger and the model see
    that the open did not take as declared.
    """
    return json.dumps(
        {
            "tool_error": marker,
            "tool": step_tool,
            "detail": f"{step_tool} refused what {open_tool} opened: "
            f"{str(refusal)[:SAID_LIMIT]}; {open_tool} answered: {str(opened)[:SAID_LIMIT]}",
        }
    )


class SampleOpener:
    """Opens one server's sample through its declared tools, once per path per job."""

    def __init__(self, server: str, spec: Any, notes: SampleNotes, *, shared: bool = False) -> None:
        self.server = server
        self.spec = spec
        self.notes = notes
        # A server other jobs share: a forwarded open's name is never taken as
        # this job's, since the path it opened may be another job's.
        self.shared = shared

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

    def _after_forward(self, answer: str) -> str:
        """After a forwarded open the server answered, drop the notes it may have replaced."""
        if not is_refusal(answer):
            name = answer_field(answer, self.spec.name_field) if self.spec.name_field else None
            self.notes.drop_named(self.server, name)
            if not self.shared:
                self.notes.make_current(self.server, name)
        return answer

    def _from_note(self, path: str, noted: OpenedSample) -> str:
        logger.info(ANSWERED_FROM_NOTE, self.server, self.spec.open_tool, path, noted.name)
        self.notes.make_current(self.server, noted.name)
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
        return refused_after_open(
            SELECT_REFUSED_AFTER_OPEN, self.spec.select_tool, self.spec.open_tool, selected, opened
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
            # The declared analysis did not run on what was opened, so the
            # open did not take as declared: handed on as failed, never as the
            # open's own success, and not noted.
            logger.warning(
                "%s: %s of %s was not confirmed (%s); the open is not noted",
                self.server,
                self.spec.analyse_tool,
                name,
                str(analysed)[:160],
            )
            return refused_after_open(
                ANALYSIS_REFUSED_AFTER_OPEN,
                self.spec.analyse_tool,
                self.spec.open_tool,
                analysed,
                opened,
            )
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
            return self._after_forward(
                str(await call(self.spec.open_tool, self._open_args(path, arguments)))
            )
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
            return self._after_forward(
                str(call(self.spec.open_tool, self._open_args(path, arguments)))
            )
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
    shared: bool = False,
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
    opener = SampleOpener(server, spec, notes, shared=shared)

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


def _names_to_close(server: str, spec: Any, notes: SampleNotes | None) -> list[str]:
    """The programs this job opened on ``server``, when its block declares how to close one."""
    if not declared(spec) or not spec.close_tool or not spec.close_argument or notes is None:
        return []
    return notes.take_owned(server)


def _close_answered(server: str, spec: Any, name: str, answer: Any) -> bool:
    if is_refusal(answer):
        logger.warning("%s: %s of %r was refused", server, spec.close_tool, name)
        return False
    return True


def close_job_programs(
    server: str, spec: Any, notes: SampleNotes | None, call: Callable[[str, dict[str, Any]], Any]
) -> list[str]:
    """Close each program this job opened on ``server``, through the tool its block declares.

    ``call(tool, arguments)`` makes one call in the caller's own way. Only a
    block that declares ``close_tool`` and ``close_argument`` is closed through;
    with none, nothing is called and the programs stay where they are. A close
    the server refuses or that raises is logged and the rest go on. Returns the
    names whose close was answered without a refusal.
    """
    closed: list[str] = []
    for name in _names_to_close(server, spec, notes):
        try:
            answer = call(spec.close_tool, {spec.close_argument: name})
        except Exception as exc:  # noqa: BLE001 - a close never fails the job
            logger.warning("%s: closing %r failed (%s)", server, name, type(exc).__name__)
            continue
        if _close_answered(server, spec, name, answer):
            closed.append(name)
    return closed


async def aclose_job_programs(
    server: str,
    spec: Any,
    notes: SampleNotes | None,
    call: Callable[[str, dict[str, Any]], Awaitable[Any]],
) -> list[str]:
    """:func:`close_job_programs` with a ``call`` that is awaited."""
    closed: list[str] = []
    for name in _names_to_close(server, spec, notes):
        try:
            answer = await call(spec.close_tool, {spec.close_argument: name})
        except Exception as exc:  # noqa: BLE001 - a close never fails the job
            logger.warning("%s: closing %r failed (%s)", server, name, type(exc).__name__)
            continue
        if _close_answered(server, spec, name, answer):
            closed.append(name)
    return closed


def program_argument(spec: Any) -> str:
    """The argument a server's tools name the job's opened program by, as declared.

    The argument its select tool is given the opened program's name in, else
    its analysis tool's; ``""`` when the server declares neither. It is the
    one a call that names no program is given the job's program in.
    """
    if not declared(spec):
        return ""
    return str(spec.select_argument or spec.analyse_argument or "")


def program_arguments(spec: Any) -> frozenset[str]:
    """Every argument the declaration says names an opened program (``program_arguments``)."""
    if not declared(spec):
        return frozenset()
    named = (spec.select_argument, spec.analyse_argument, *spec.program_arguments)
    return frozenset(str(a) for a in named if a)


def open_path_arguments(spec: Any) -> frozenset[str]:
    """Every argument the declaration says names a file a tool opens (``open_path_arguments``)."""
    if not declared(spec):
        return frozenset()
    return frozenset(str(a) for a in (spec.path_argument, *spec.open_path_arguments) if a)


def _input_names(tool: Any) -> set[str] | None:
    """The argument names ``tool``'s own input schema declares; ``None`` when it cannot be read."""
    try:
        args = getattr(tool, "args", None)
    except Exception:  # noqa: BLE001 - a schema not read is said by the caller
        return None
    return {str(name) for name in args} if isinstance(args, dict) else None


def _program_refusal(code: str, message: str, tool: str, remediation: str) -> str:
    from maljan.tools.errors import tool_error

    logger.warning("%s: %s", tool, message)
    return json.dumps(tool_error(code, message, tool=tool, remediation=remediation))


def withheld_unpinned(server: str, tool: str, why: str) -> str:
    """Why ``tool`` is withheld on a shared server: ``why`` it cannot be held to the job."""
    return (
        f"{server}: {tool} is withheld: {why}, and on this server other jobs share it "
        "could read or change another job's program"
    )


# Why a tool is withheld, by what its schema declares.
UNCOVERED = (
    "its input schema declares no program or path argument the server's sample_open names, "
    "and sample_open.job_safe_tools does not list it"
)
UNREAD_SCHEMA = "its input schema could not be read"
NO_NOTE = "the job keeps no note of the programs it opened on this server"
LISTED_SHARED_WITHHELD = (
    "sample_open.shared_withheld_tools lists it: what it runs or changes reaches past "
    "the job's own program"
)


def pin_program_argument(
    tools: Sequence[Any],
    *,
    server: str,
    spec: Any,
    notes: SampleNotes | None,
    shared: bool,
    held_path: Callable[[], str | None] | None = None,
    withheld: dict[str, str] | None = None,
) -> list[Any]:
    """``tools`` held to the job's own programs and path, on a server other jobs share.

    A server that holds programs keeps one current program for every client,
    so on a shared server (``shared``: one reached at an address) a call that
    names no program reads whichever sample was opened last, by any job, and
    a call that names another job's program or path reads or replaces it.
    Every rule comes from the server's ``sample_open``:

    * every declared program argument (:func:`program_arguments`) a call
      carries must name a program this job opened there, and one the tool's
      schema takes that the call leaves out is given the program the job
      opened or selected last (``SampleNotes.current``); a call before the
      job opened anything is refused;
    * every declared path argument (:func:`open_path_arguments`) a call
      carries must be the job's own copy of the sample (``held_path``);
    * a tool whose schema takes none of these, or whose schema cannot be
      read, is withheld unless ``job_safe_tools`` lists it, and a tool
      ``shared_withheld_tools`` lists is withheld whatever it takes.

    The arguments checked are the ones the call carries, not the ones the
    schema names, so an argument the schema does not declare is checked too,
    on a job-safe tool as on any other.

    A refusal is answered before the server is asked, with a sentence naming
    what was refused and the job's own. A withheld tool's reason goes in
    ``withheld`` (tool name to reason) and the log; so does a tool that could
    not be wrapped. A path that passes is sent as the held path itself. On a
    server no other job shares, or one that declares no ``sample_open``,
    ``tools`` come back as they were; a shared, declared server with no note
    store (``notes``) has every tool withheld.
    """
    from langchain_core.tools import StructuredTool

    if not shared or not declared(spec):
        return list(tools)
    programs = program_arguments(spec)
    fill = program_argument(spec)
    # Read by the wrappers; with no note store every tool is withheld below.
    ledger = notes if notes is not None else SampleNotes()
    paths = open_path_arguments(spec)
    safe = frozenset(str(t) for t in spec.job_safe_tools)
    barred = frozenset(str(t) for t in spec.shared_withheld_tools)

    def refuse_path(name: str, argument: str, given: Any) -> tuple[str | None, str | None]:
        """The held path ``given`` names, or the refusal of a path that is not it."""
        held = held_path() if held_path is not None else None
        if held and open_key(given, held) == held:
            return held, None
        return None, _program_refusal(
            FOREIGN_PROGRAM,
            f"{argument}={given!r} is not this job's sample on {server}, which other jobs "
            "share; the call was not sent",
            name,
            f"call {name} with {argument}={held!r}, the job's own sample"
            if held
            else "this job holds no copy of its sample on this server",
        )

    def guarded(tool: Any, takes: set[str]) -> Any:
        name = str(getattr(tool, "name", ""))
        # The program arguments the schema takes: given the job's program when
        # a call leaves them out.
        filled = programs & takes

        async def call(**kwargs: Any) -> Any:
            own = ledger.current(server)
            # Every declared argument the call carries, whether or not its
            # schema names it.
            sent = dict(kwargs)
            for argument in sorted(paths & set(kwargs)):
                given = kwargs.get(argument)
                if given not in (None, ""):
                    held, refused = refuse_path(name, argument, given)
                    if refused is not None:
                        return refused
                    # Sent as the one spelling the job holds, never a
                    # relative name the server might read another way.
                    sent[argument] = held
            for argument in sorted(filled | (programs & set(kwargs))):
                given = kwargs.get(argument)
                if given not in (None, ""):
                    if not ledger.owns(server, given):
                        return _program_refusal(
                            FOREIGN_PROGRAM,
                            f"{argument}={given!r} is not a program this job opened on "
                            f"{server}; the call was not sent",
                            name,
                            f"call {name} with {argument}={own!r}, the job's own program, "
                            f"or without {argument}"
                            if own
                            else f"open the job's sample with {spec.open_tool} first",
                        )
                elif own is not None:
                    sent[argument] = own
                else:
                    return _program_refusal(
                        NO_JOB_PROGRAM,
                        f"{name} names no {argument}, and this job has opened no program on "
                        f"{server}, which other jobs share: its current program may be "
                        "another job's; the call was not sent",
                        name,
                        f"open the job's sample with {spec.open_tool} first",
                    )
            answer = await tool.ainvoke(sent)
            if name == spec.select_tool and fill and not is_refusal(answer):
                ledger.make_current(server, sent.get(fill))
            return answer

        return StructuredTool.from_function(
            func=None,
            coroutine=call,
            name=name,
            description=getattr(tool, "description", ""),
            args_schema=tool.args_schema,
            infer_schema=False,
            metadata=dict(getattr(tool, "metadata", None) or {}),
        )

    def withhold(name: str, why: str) -> None:
        reason = withheld_unpinned(server, name, why)
        logger.error("%s", reason)
        if withheld is not None:
            withheld[name] = reason

    if notes is None:
        # No note of what this job opened: nothing can be held to it.
        for tool in tools:
            withhold(str(getattr(tool, "name", "")), NO_NOTE)
        return []
    out: list[Any] = []
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        if name in barred:
            withhold(name, LISTED_SHARED_WITHHELD)
            continue
        takes = _input_names(tool)
        if name in safe:
            # Job-safe: offered, with any declared argument a call carries
            # still held to the job.
            takes = set() if takes is None else takes - programs
        elif takes is None:
            withhold(name, UNREAD_SCHEMA)
            continue
        elif not (takes & (programs | paths)):
            withhold(name, UNCOVERED)
            continue
        try:
            out.append(guarded(tool, takes))
        except Exception as exc:  # noqa: BLE001 - withheld, and said
            why = f"it could not be wrapped to carry the job's program ({type(exc).__name__})"
            withhold(name, why)
    return out


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


def load_line(tool: str, argument: str, path: str) -> str:
    """The line telling an agent to open the sample with a declared open tool first."""
    return (
        f'LOAD THIS BINARY FIRST: call ``{tool}({argument}="{path}")``.\n'
        "All subsequent analysis tools operate on the program loaded by "
        "that call. Do not invent a path — use the one above verbatim.\n\n"
    )


# The metadata key an offered open tool carries its server's declaration
# under, so an agent given the tool can say how to open the sample with it.
OPEN_METADATA_KEY = "maljan_sample_open"


def mark_open_tool(
    tools: Sequence[Any], spec: Any, every_tool: Sequence[Any] | None = None
) -> list[Any]:
    """``tools`` with the declared open tool marked by its declaration (``OPEN_METADATA_KEY``).

    The mark is on a copy of the tool, so a tool object shared with another
    agent is left as it was. With no declaration, or one naming a select or
    analysis tool the server's whole manifest (``every_tool``) lacks, ``tools``
    come back as they were, as :func:`wrap_open_tool` offers them.
    """
    if not declared(spec):
        return list(tools)
    if every_tool is not None:
        names = {str(getattr(t, "name", "")) for t in every_tool}
        if any(t and t not in names for t in (spec.select_tool, spec.analyse_tool)):
            return list(tools)
    mark = {"open_tool": str(spec.open_tool), "path_argument": str(spec.path_argument)}
    out: list[Any] = []
    for tool in tools:
        if getattr(tool, "name", "") == spec.open_tool:
            metadata = {**(getattr(tool, "metadata", None) or {}), OPEN_METADATA_KEY: mark}
            try:
                tool = tool.model_copy(update={"metadata": metadata})
            except Exception as exc:  # noqa: BLE001 - an unmarked tool is offered as it is
                logger.warning("%s offered unmarked (%s).", spec.open_tool, type(exc).__name__)
        out.append(tool)
    return out


def declared_open(tools: Sequence[Any]) -> Any:
    """The open declaration an offered tool carries (``open_tool``, ``path_argument``), or ``None``.

    The first marked tool among ``tools`` gives it, as a namespace the load
    line reads.
    """
    from types import SimpleNamespace

    for tool in tools:
        mark = (getattr(tool, "metadata", None) or {}).get(OPEN_METADATA_KEY)
        if isinstance(mark, dict) and mark.get("open_tool") and mark.get("path_argument"):
            return SimpleNamespace(**mark)
    return None
