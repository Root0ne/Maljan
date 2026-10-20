"""At job end the programs a job opened on a shared server are closed where a block says how."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import SampleOpenConfig
from maljan.providers.sample_open import (
    SampleNotes,
    aclose_job_programs,
    close_job_programs,
    is_shared_address,
)

SERVER = "remote http://ghidra.test:8080"


def _spec(**over: Any) -> SampleOpenConfig:
    return SampleOpenConfig(
        open_tool="import_it",
        path_argument="file",
        close_tool="drop",
        close_argument="name",
        **over,
    )


def _notes() -> SampleNotes:
    notes = SampleNotes()
    notes.note(SERVER, "/m/a.bin", "a.bin", "{}")
    notes.note(SERVER, "/m/b.bin", "b.bin", "{}")
    notes.note("another", "/m/c.bin", "c.bin", "{}")
    return notes


def test_each_program_the_job_opened_is_closed_through_the_declared_tool() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    notes = _notes()

    closed = close_job_programs(
        SERVER, _spec(), notes, lambda tool, args: calls.append((tool, args)) or "{}"
    )

    assert closed == ["a.bin", "b.bin"]
    assert calls == [("drop", {"name": "a.bin"}), ("drop", {"name": "b.bin"})]
    # Once taken they are not closed twice, and another server's are not touched.
    assert close_job_programs(SERVER, _spec(), notes, lambda *_: "{}") == []
    assert notes.owns("another", "c.bin")


def test_without_a_declared_close_nothing_is_called() -> None:
    spec = SampleOpenConfig(open_tool="import_it", path_argument="file")
    calls: list[Any] = []

    assert close_job_programs(SERVER, spec, _notes(), lambda *a: calls.append(a)) == []
    assert close_job_programs(SERVER, None, _notes(), lambda *a: calls.append(a)) == []
    assert calls == []


def test_a_refused_or_failed_close_never_stops_the_rest() -> None:
    def call(tool: str, args: dict[str, Any]) -> str:
        if args["name"] == "a.bin":
            raise RuntimeError("down")
        return json.dumps({"tool_error": "http_status", "tool": tool, "status": "500"})

    assert close_job_programs(SERVER, _spec(), _notes(), call) == []


def test_the_awaited_form_closes_the_same_programs() -> None:
    seen: list[str] = []

    async def call(tool: str, args: dict[str, Any]) -> str:
        seen.append(args["name"])
        return "{}"

    closed = asyncio.run(aclose_job_programs(SERVER, _spec(), _notes(), call))

    assert closed == seen == ["a.bin", "b.bin"]


def test_a_close_tool_and_its_argument_are_declared_together() -> None:
    with pytest.raises(ValidationError):
        SampleOpenConfig(open_tool="import_it", path_argument="file", close_tool="drop")
    with pytest.raises(ValidationError):
        SampleOpenConfig(close_tool="drop", close_argument="name")


@pytest.mark.parametrize(
    ("transport", "shared"),
    [("http", True), ("sse", True), ("streamable-http", True), ("stdio", False), ("", False)],
)
def test_a_server_at_an_address_is_the_shared_one(transport: str, shared: bool) -> None:
    assert is_shared_address(SimpleNamespace(transport=transport)) is shared
