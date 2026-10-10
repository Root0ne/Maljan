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
import threading
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.core.logger import logger

__all__ = [
    "OpenedSample",
    "SampleNotes",
    "SampleOpener",
    "declared",
    "is_refusal",
    "wrap_open_tool",
]

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
        with self._guard:
            return self._opened.get((server, path))

    def note(self, server: str, path: str, name: str, answer: str) -> None:
        if path:
            with self._guard:
                self._opened[(server, path)] = OpenedSample(name=name or path, answer=answer)

    def forget(self, server: str, path: str) -> None:
        with self._guard:
            self._opened.pop((server, path), None)

    def lock(self, server: str, path: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault((server, path), threading.Lock())


def declared(spec: Any) -> bool:
    """Whether ``spec`` (a ``SampleOpenConfig`` or ``None``) declares an open tool."""
    return bool(spec is not None and getattr(spec, "open_tool", "") and spec.path_argument)


def is_refusal(answer: Any) -> bool:
    """Whether a tool's answer is a failure, by the one rule the ledger reads failures with."""
    from maljan.tools.errors import error_parts

    return error_parts(answer) is not None


def _opened_name(answer: str, field: str, path: str) -> str:
    """The name the server gave what it opened: the declared field of its answer, else the path."""
    if not field:
        return path
    try:
        payload = json.loads(answer)
    except (TypeError, ValueError):
        return path
    value = payload.get(field) if isinstance(payload, dict) else None
    return str(value) if isinstance(value, (str, int)) and str(value).strip() else path


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

    def _selected_after_open(self, name: str, selected: Any) -> bool:
        """Whether the select after a fresh open answered; a refused one is said and not noted.

        What the server reads next is then not known to be what it opened, so
        neither analysis nor note follows; the open's own answer is still
        handed on, and the next open tries again.
        """
        if not is_refusal(selected):
            return True
        logger.warning(
            "%s: %s of %s after opening it was refused (%s); the open is not noted",
            self.server,
            self.spec.select_tool,
            name,
            str(selected)[:160],
        )
        return False

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

    async def aopen(
        self,
        path: str,
        call: Callable[[str, dict[str, Any]], Awaitable[Any]],
        arguments: dict[str, Any] | None = None,
    ) -> str:
        """Open ``path`` with ``call`` (one tool by name, awaited), or answer from the note."""
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
                if not self._selected_after_open(name, selected):
                    return opened
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
        path: str,
        call: Callable[[str, dict[str, Any]], Any],
        arguments: dict[str, Any] | None = None,
    ) -> str:
        """Open ``path`` with ``call`` (one tool by name), or answer from the note."""
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
                if not self._selected_after_open(name, selected):
                    return opened
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
    ``held_path``, when given, answers the path the server must open for this
    job, and a model's own path is replaced with it. With no declaration, no
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
    opener = SampleOpener(server, spec, notes)

    async def call(tool: str, arguments: dict[str, Any]) -> Any:
        found = by_name.get(tool)
        if found is None:
            return json.dumps({"error": f"{server} offers no tool {tool!r}"})
        return await found.ainvoke(arguments)

    async def open_once(**kwargs: Any) -> str:
        path = str(kwargs.get(spec.path_argument) or "")
        held = held_path() if held_path is not None else None
        if held and path != held:
            logger.warning(
                "%s: %s path %r replaced with the job's path %r.",
                server,
                spec.open_tool,
                path,
                held,
            )
            path = held
        rest = {k: v for k, v in kwargs.items() if k != spec.path_argument and v is not None}
        return await opener.aopen(path, call, rest)

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
