"""A server's sample is opened once per job, through the tools the server declares.

Some analysis servers reset what they analysed when their open tool is called
again. Each server declares as data which tool opens a sample, and optionally
which selects one already open and which runs its analysis
(``MCPServerConfig.sample_open``); the platform notes each path a job opened
on a server and answers a later open of it from the note, after the declared
select. No server or tool name is known to the mechanism: the server here is
an invented one, with invented tool names.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ValidationError

from maljan.core.config import (
    GHIDRA_SAMPLE_OPEN,
    MCPServerConfig,
    SampleOpenConfig,
    Settings,
    StaticConfig,
)
from maljan.providers.sample_open import SampleNotes, SampleOpener, wrap_open_tool
from maljan.providers.servers import ServerHandle

PATH = "/samples/a.bin"
SPEC = SampleOpenConfig(
    open_tool="open_thing",
    path_argument="where",
    name_field="handle",
    select_tool="pick",
    select_argument="handle",
    analyse_tool="study",
    analyse_argument="handle",
)


class _Where(BaseModel):
    where: str = ""


class _Handle(BaseModel):
    handle: str = ""


class _Server:
    """An invented analysis server: its tools, the calls they got, and what each answers."""

    def __init__(self, *, pick_refused: bool = False, study_refused: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.pick_refused = pick_refused
        self.study_refused = study_refused
        self.open_delay = 0.0

    def tools(self) -> list[Any]:
        async def open_thing(where: str = "") -> str:
            self.calls.append(("open_thing", {"where": where}))
            if self.open_delay:
                await asyncio.sleep(self.open_delay)
            if where == "/nowhere":
                return json.dumps({"error": "no such file"})
            return json.dumps({"opened": True, "handle": "h1"})

        async def pick(handle: str = "") -> str:
            self.calls.append(("pick", {"handle": handle}))
            if self.pick_refused:
                # Refused once, as a server that restarted refuses the handle
                # it no longer holds; the fresh open's select then answers.
                self.pick_refused = False
                return json.dumps({"error": f"not open: {handle}"})
            return json.dumps({"picked": handle})

        async def study(handle: str = "") -> str:
            self.calls.append(("study", {"handle": handle}))
            if self.study_refused:
                return json.dumps({"error": "analysis failed"})
            return json.dumps({"studied": handle})

        async def look() -> str:
            self.calls.append(("look", {}))
            return "{}"

        def tool(fn: Any, schema: Any) -> Any:
            return StructuredTool.from_function(
                coroutine=fn,
                name=fn.__name__,
                description=fn.__name__,
                args_schema=schema,
                infer_schema=False,
            )

        return [
            tool(open_thing, _Where),
            tool(pick, _Handle),
            tool(study, _Handle),
            tool(look, BaseModel),
        ]

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _handle(server: _Server, spec: Any = SPEC, *, offered: list[str] | None = None) -> Any:
    handle = ServerHandle("invented", MCPServerConfig(sample_open=spec, tools=offered))
    handle._all_tools = server.tools()
    handle.sample_notes = SampleNotes()
    return handle


def _open(handle: Any, path: str = PATH) -> str:
    (tool,) = [t for t in handle.tools() if t.name == "open_thing"]
    return str(asyncio.run(tool.ainvoke({"where": path})))


class TestTheDeclaration:
    def test_nothing_declared_offers_the_tools_as_they_are(self) -> None:
        server = _Server()
        handle = _handle(server, SampleOpenConfig())
        assert handle.tools() == handle._all_tools

    def test_an_open_tool_needs_its_path_argument(self) -> None:
        with pytest.raises(ValidationError):
            SampleOpenConfig(open_tool="open_thing")

    def test_a_select_or_analysis_tool_needs_an_open_tool(self) -> None:
        with pytest.raises(ValidationError):
            SampleOpenConfig(select_tool="pick")

    def test_ghidra_s_block_declares_its_tools_as_data(self) -> None:
        assert StaticConfig().ghidra.sample_open == GHIDRA_SAMPLE_OPEN
        stored = StaticConfig.model_validate({"ghidra": {"url": "http://g:8089"}})
        assert stored.ghidra.sample_open == GHIDRA_SAMPLE_OPEN

    def test_an_operator_s_own_declaration_is_kept(self) -> None:
        stored = StaticConfig.model_validate({"ghidra": {"sample_open": {}}})
        assert stored.ghidra.sample_open == SampleOpenConfig()

    def test_a_registry_server_carries_its_declaration(self) -> None:
        cfg = Settings.model_validate(
            {"mcp": {"servers": {"mine": {"sample_open": SPEC.model_dump()}}}}
        )
        assert cfg.mcp.servers["mine"].sample_open == SPEC


class TestOnceAPath:
    def test_the_first_open_opens_selects_and_analyses_and_is_noted(self) -> None:
        server = _Server()
        handle = _handle(server)
        said = _open(handle)
        assert server.calls == [
            ("open_thing", {"where": PATH}),
            ("pick", {"handle": "h1"}),
            ("study", {"handle": "h1"}),
        ]
        assert json.loads(said) == {"opened": True, "handle": "h1"}
        assert handle.sample_notes.get("invented", PATH).name == "h1"

    def test_a_later_open_is_a_select_answered_from_the_note(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        server = _Server()
        handle = _handle(server)
        first = _open(handle)
        with caplog.at_level(logging.INFO):
            again = [_open(handle) for _ in range(4)]
        assert server.names() == ["open_thing", "pick", "study", *["pick"] * 4]
        assert again == [first] * 4
        assert "answered from the job's note" in caplog.text

    def test_with_no_select_declared_the_note_answers_alone(self) -> None:
        server = _Server()
        spec = SPEC.model_copy(update={"select_tool": "", "select_argument": ""})
        handle = _handle(server, spec)
        _open(handle)
        _open(handle)
        assert server.names() == ["open_thing", "study"]

    def test_a_refused_select_opens_and_analyses_afresh(self) -> None:
        server = _Server()
        handle = _handle(server)
        _open(handle)
        server.pick_refused = True
        _open(handle)
        assert server.names() == [
            "open_thing",
            "pick",
            "study",
            "pick",
            "open_thing",
            "pick",
            "study",
        ]

    def test_a_select_refused_right_after_the_open_is_not_noted(self) -> None:
        server = _Server()
        handle = _handle(server)
        server.pick_refused = True
        said = _open(handle)
        assert json.loads(said) == {"opened": True, "handle": "h1"}
        assert server.names() == ["open_thing", "pick"]
        assert handle.sample_notes.get("invented", PATH) is None

    def test_an_analysis_the_server_refused_is_not_noted(self) -> None:
        server = _Server(study_refused=True)
        handle = _handle(server)
        _open(handle)
        _open(handle)
        assert server.names().count("open_thing") == 2
        assert handle.sample_notes.get("invented", PATH) is None

    def test_a_refused_open_is_answered_and_not_noted(self) -> None:
        server = _Server()
        handle = _handle(server)
        said = _open(handle, "/nowhere")
        assert json.loads(said) == {"error": "no such file"}
        assert server.names() == ["open_thing"]
        assert handle.sample_notes.get("invented", "/nowhere") is None

    def test_a_select_and_analysis_tool_the_model_is_not_offered_are_still_called(self) -> None:
        server = _Server()
        handle = _handle(server, offered=["open_thing"])
        assert [t.name for t in handle.tools()] == ["open_thing"]
        _open(handle)
        assert server.names() == ["open_thing", "pick", "study"]

    def test_each_path_is_noted_apart(self) -> None:
        server = _Server()
        handle = _handle(server)
        _open(handle, "/samples/a.bin")
        _open(handle, "/samples/b.bin")
        assert server.names().count("open_thing") == 2


class TestConcurrentFirstOpens:
    def test_two_first_opens_at_once_import_once(self) -> None:
        server = _Server()
        server.open_delay = 0.2
        handle = _handle(server)
        (tool,) = [t for t in handle.tools() if t.name == "open_thing"]

        async def both() -> list[Any]:
            return list(
                await asyncio.gather(tool.ainvoke({"where": PATH}), tool.ainvoke({"where": PATH}))
            )

        first, second = asyncio.run(both())
        assert server.names().count("open_thing") == 1
        assert first == second

    def test_a_pass_on_another_thread_waits_for_the_first_open(self) -> None:
        notes = SampleNotes()
        opener = SampleOpener("invented", SPEC, notes)
        calls: list[str] = []

        def call(tool: str, arguments: dict[str, Any]) -> str:
            calls.append(tool)
            if tool == "open_thing":
                time.sleep(0.2)
                return json.dumps({"handle": "h1"})
            return "{}"

        threads = [threading.Thread(target=opener.open, args=(PATH, call)) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert calls.count("open_thing") == 1


class TestTheHeldPath:
    def test_a_model_s_own_path_is_replaced_with_the_job_s(self) -> None:
        server = _Server()
        tools = server.tools()
        wrapped = wrap_open_tool(
            tools,
            tools,
            server="invented",
            spec=SPEC,
            notes=SampleNotes(),
            held_path=lambda: PATH,
        )
        (tool,) = [t for t in wrapped if t.name == "open_thing"]
        asyncio.run(tool.ainvoke({"where": "/invented/path"}))
        assert server.calls[0] == ("open_thing", {"where": PATH})


class TestTheNoteIsTheJobs:
    def test_a_registry_gives_its_handles_one_note(self) -> None:
        from maljan.providers.servers import ServerRegistry

        notes = SampleNotes()
        registry = ServerRegistry(Settings(), sample_notes=notes)
        assert {id(h.sample_notes) for h in registry._all_handles()} == {id(notes)}

    def test_two_jobs_have_two_notes(self) -> None:
        from maljan.providers.servers import ServerRegistry

        first, second = ServerRegistry(Settings()), ServerRegistry(Settings())
        assert first.sample_notes is not second.sample_notes
