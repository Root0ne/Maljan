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
same path is answered from the note with the first open's own answer; where a
select tool is declared it is sent first, and only a select the server refuses
(it restarted, the program is gone) opens and analyses the path afresh and
writes the note again. An open the server refused, or an analysis it did not
confirm, is not noted, so the next open tries again. A lock per path makes
concurrent first opens import once.

The same opener serves a model's tool call (``wrap_open_tool``) and the
platform's own passes that speak to the server another way: each hands it a
function that calls one tool by name.
"""

from __future__ import annotations

import asyncio
import json
import posixpath
import threading
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.core.logger import logger

__all__ = [
    "REMOTE_TRANSPORTS",
    "OpenedSample",
    "SampleNotes",
    "SampleOpener",
    "declared",
    "is_refusal",
    "long_running_tools",
    "answer_field",
    "canonical_path",
    "path_refusal",
    "server_note_key",
    "wrap_open_tool",
]

# How much of a server's own words a refusal handed on carries, each.
SAID_LIMIT = 500

# How often a coroutine waiting for another's first open of the same path looks again.
LOCK_POLL_SECONDS = 0.05

# Said in the log when an open is answered from the note.
ANSWERED_FROM_NOTE = (
    "%s: %s of %s answered from the job's note (opened as %r); the server was not asked to open it"
)


@dataclass(frozen=True)
class OpenedSample:
    """A path one job opened on one server: the name the server gave it, and the open's answer."""

    name: str
    answer: str


class SampleNotes:
    """The paths one job has opened on each server, with a lock per path.

    One per job (the job's container holds it), never shared between jobs, and
    safe across the job's threads and loops.
    """

    def __init__(self) -> None:
        self._opened: dict[tuple[str, str], OpenedSample] = {}
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._guard = threading.Lock()

    def get(self, server: str, path: str) -> OpenedSample | None:
        key = canonical_path(path)
        if key is None:
            return None
        with self._guard:
            return self._opened.get((server, key))

    def note(self, server: str, path: str, name: str, answer: str) -> None:
        key = canonical_path(path)
        if key is None:
            return
        with self._guard:
            self._opened[(server, key)] = OpenedSample(name=name or key, answer=answer)

    def forget(self, server: str, path: str) -> None:
        key = canonical_path(path)
        with self._guard:
            self._opened.pop((server, key or ""), None)

    def lock(self, server: str, path: str) -> threading.Lock:
        key = canonical_path(path) or ""
        with self._guard:
            return self._locks.setdefault((server, key), threading.Lock())


# The transports that reach a running server at an address: every handle that
# names the same address speaks to the same server, and to what it opened.
REMOTE_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})


def path_refusal(path: Any, held: str | None = None) -> str | None:
    """Why ``path`` is refused as the sample a server opens, or ``None`` when it is not.

    The one reading of a path the opener makes, for the note's key, the check
    against the job's held sample and the argument sent to the declared tools
    alike (``canonical_path``). Nothing is rewritten that the server might read
    another way: a spelling with a backslash, a percent sign, a control
    character, surrounding blanks, a doubled separator, a ``.`` or ``..``
    segment or a trailing slash is refused, not tidied, because the server
    resolves its own symlinks, case and mounts and may land somewhere a
    lexical tidy-up does not. A relative path is joined to the held sample's
    directory, and refused where there is none. Where the job holds a sample,
    any path that is not exactly that sample is refused.
    """
    if not isinstance(path, str) or not path:
        return "no path was given"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        return "the path holds a control character"
    if path != path.strip():
        return "the path has blanks around it"
    if "\\" in path:
        return "the path holds a backslash"
    if "%" in path:
        return "the path holds a percent sign, which may be read as an encoding"
    candidate = path
    held_path: str | None = None
    if held is not None:
        if path_refusal(held) is not None:
            return "the job's own sample path is not one this reading accepts"
        held_path = held
    if not candidate.startswith("/"):
        if held_path is None:
            return "the path is relative and this server holds no sample to resolve it against"
        candidate = posixpath.dirname(held_path).rstrip("/") + "/" + candidate
    if candidate != "/" and candidate.endswith("/"):
        return "the path ends in a separator"
    segments = candidate.split("/")[1:]
    if "" in segments:
        return "the path holds a doubled separator"
    if any(segment in (".", "..") for segment in segments):
        return "the path holds a . or .. segment"
    if held_path is not None and candidate != held_path:
        return "the path is not the job's own sample"
    return None


def canonical_path(path: Any, held: str | None = None) -> str | None:
    """``path`` in its one spelling (a relative path joined to the held sample's
    directory), or ``None`` when ``path_refusal`` refuses it."""
    if path_refusal(path, held) is not None:
        return None
    text = str(path)
    if held is not None and not text.startswith("/"):
        return held
    return text


def server_note_key(config: Any, instance: str = "") -> str:
    """The server a note belongs to: its address, or its command and the process ``instance``.

    Two handles to one remote server (a registry handle, a static provider's,
    a handle for another loop) name the same address and share a note. A
    local server is a process per handle, which holds only what that process
    opened, so ``instance`` names the process.
    """
    transport = str(getattr(config, "transport", "") or "stdio")
    url = str(getattr(config, "url", "") or "").strip().rstrip("/")
    if transport in REMOTE_TRANSPORTS and url:
        return f"{transport} {url}"
    command = " ".join(
        [str(getattr(config, "command", "") or ""), *map(str, getattr(config, "args", None) or [])]
    )
    return f"stdio {command.strip()} ({instance})"


def declared(spec: Any) -> bool:
    """Whether ``spec`` (a ``SampleOpenConfig`` or ``None``) declares an open tool."""
    return bool(spec is not None and getattr(spec, "open_tool", "") and spec.path_argument)


def is_refusal(answer: Any) -> bool:
    """Whether a tool's answer is a failure, by the one rule the ledger reads failures with."""
    from maljan.tools.errors import error_parts

    return error_parts(answer) is not None


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
    what those tools are given and nothing more: the note is keyed by the
    path alone, so no answer decides which note answers.
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

    def _from_note(self, path: str, noted: OpenedSample) -> str:
        logger.info(ANSWERED_FROM_NOTE, self.server, self.spec.open_tool, path, noted.name)
        return noted.answer

    def _refused_select(self, path: str, answer: Any) -> None:
        logger.info(
            "%s: %s of the noted %s was refused (%s); opening it afresh",
            self.server,
            self.spec.select_tool,
            path,
            str(answer)[:160],
        )
        self.notes.forget(self.server, path)

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
                "tool_error": "select_refused_after_open",
                "tool": self.spec.select_tool,
                "detail": f"{self.spec.select_tool} refused what {self.spec.open_tool} opened: "
                f"{str(selected)[:SAID_LIMIT]}; {self.spec.open_tool} answered: "
                f"{str(opened)[:SAID_LIMIT]}",
            }
        )

    def _after_analysis(self, path: str, name: str, opened: str, analysed: Any) -> str:
        if analysed is not None and is_refusal(analysed):
            logger.warning(
                "%s: %s of %s was not confirmed (%s); the open is not noted",
                self.server,
                self.spec.analyse_tool,
                name,
                str(analysed)[:160],
            )
            return opened
        self.notes.note(self.server, path, name, opened)
        return opened

    def refused(self, path: Any, why: str) -> str:
        """The structured refusal for a path the opener does not open."""
        logger.warning("%s: %s of %r refused: %s", self.server, self.spec.open_tool, path, why)
        return json.dumps(
            {
                "error": {
                    "code": "sample_path_refused",
                    "message": f"{self.spec.open_tool} was not called: {why}",
                    "remediation": "open the job's own sample by its path exactly as it was given",
                }
            }
        )

    async def aopen(
        self,
        path: Any,
        call: Callable[[str, dict[str, Any]], Awaitable[Any]],
        arguments: dict[str, Any] | None = None,
        held: str | None = None,
    ) -> str:
        """Open ``path`` with ``call`` (one tool by name, awaited), or answer from the note.

        ``path`` is read once (``canonical_path``, against the job's ``held``
        sample when there is one); that one spelling is the note's key and the
        argument every declared tool is sent, and a refused path calls nothing.
        """
        why = path_refusal(path, held)
        canonical = canonical_path(path, held)
        if why is not None or canonical is None:
            return self.refused(path, why or "the path could not be read")
        path = canonical
        lock = self.notes.lock(self.server, path)
        # Taken without blocking the loop, and so that a call cancelled while
        # it waits never holds the lock: the holder may be another coroutine
        # of this same loop, or a pass on another thread.
        while not lock.acquire(blocking=False):
            await asyncio.sleep(LOCK_POLL_SECONDS)
        try:
            noted = self.notes.get(self.server, path)
            if noted is not None:
                if not self.spec.select_tool:
                    return self._from_note(path, noted)
                selected = await call(self.spec.select_tool, self._select_args(noted.name))
                if not is_refusal(selected):
                    return self._from_note(path, noted)
                self._refused_select(path, selected)
            opened = str(
                await call(
                    self.spec.open_tool, {**(arguments or {}), self.spec.path_argument: path}
                )
            )
            if is_refusal(opened):
                return opened
            name = _opened_name(opened, self.spec.name_field, path)
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
            return self._after_analysis(path, name, opened, analysed)
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
        why = path_refusal(path, held)
        canonical = canonical_path(path, held)
        if why is not None or canonical is None:
            return self.refused(path, why or "the path could not be read")
        path = canonical
        with self.notes.lock(self.server, path):
            noted = self.notes.get(self.server, path)
            if noted is not None:
                if not self.spec.select_tool:
                    return self._from_note(path, noted)
                selected = call(self.spec.select_tool, self._select_args(noted.name))
                if not is_refusal(selected):
                    return self._from_note(path, noted)
                self._refused_select(path, selected)
            opened = str(
                call(self.spec.open_tool, {**(arguments or {}), self.spec.path_argument: path})
            )
            if is_refusal(opened):
                return opened
            name = _opened_name(opened, self.spec.name_field, path)
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
            return self._after_analysis(path, name, opened, analysed)

    def name_of(self, path: str) -> str | None:
        """The name the noted open of ``path`` gave it, or ``None`` when it is not noted."""
        noted = self.notes.get(self.server, path)
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
    ``held_path``, when given, answers the job's own sample: the opener
    refuses any other path (``path_refusal``), and a relative one is read
    against it. With no declaration, no
    note store, or no open tool among ``tools``, ``tools`` come back as they
    were.
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
