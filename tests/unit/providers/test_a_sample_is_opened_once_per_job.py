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
        assert handle.sample_notes.get(handle.note_key, PATH).name == "h1"

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

    def test_a_select_refused_right_after_the_open_hands_on_the_refusal(self) -> None:
        from maljan.providers.sample_open import is_refusal

        server = _Server()
        handle = _handle(server)
        server.pick_refused = True
        said = _open(handle)
        # The open did not take: the select's refusal, with the open's answer beside it.
        assert is_refusal(said)
        answer = json.loads(said)
        assert answer["tool"] == "pick" and '"handle": "h1"' in answer["detail"]
        assert "not open: h1" in answer["detail"]
        assert server.names() == ["open_thing", "pick"]
        assert handle.sample_notes.get(handle.note_key, PATH) is None

    def test_a_declaration_naming_a_tool_the_server_lacks_offers_the_open_as_it_is(
        self,
    ) -> None:
        server = _Server()
        spec = SPEC.model_copy(update={"analyse_tool": "absent_tool"})
        handle = _handle(server, spec)
        (tool,) = [t for t in handle.tools() if t.name == "open_thing"]
        assert tool is next(t for t in handle._all_tools if t.name == "open_thing")

    def test_an_analysis_the_server_refused_is_not_noted(self) -> None:
        server = _Server(study_refused=True)
        handle = _handle(server)
        _open(handle)
        _open(handle)
        assert server.names().count("open_thing") == 2
        assert handle.sample_notes.get(handle.note_key, PATH) is None

    def test_a_refused_open_is_answered_and_not_noted(self) -> None:
        server = _Server()
        handle = _handle(server)
        said = _open(handle, "/nowhere")
        assert json.loads(said) == {"error": "no such file"}
        assert server.names() == ["open_thing"]
        assert handle.sample_notes.get(handle.note_key, "/nowhere") is None

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
    def _wrapped(self, server: _Server) -> Any:
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
        return tool

    def test_a_path_other_than_the_job_s_sample_is_forwarded_and_not_noted(self) -> None:
        """Another file (a carved payload, say) is the server's to open, never noted."""
        server = _Server()
        tool = self._wrapped(server)
        asyncio.run(tool.ainvoke({"where": "/invented/path"}))
        asyncio.run(tool.ainvoke({"where": "/invented/path"}))
        assert server.calls == [("open_thing", {"where": "/invented/path"})] * 2

    def test_a_relative_path_is_read_against_the_held_sample(self) -> None:
        server = _Server()
        asyncio.run(self._wrapped(server).ainvoke({"where": "a.bin"}))
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


class TestOneServerOneNote:
    """The note belongs to the server and the sample, whichever handle or spelling asks."""

    def _remote(self) -> MCPServerConfig:
        return MCPServerConfig(
            transport="streamable-http", url="http://decompiler.invalid:9000/mcp/", sample_open=SPEC
        )

    def test_two_handles_to_one_remote_server_share_a_note(self) -> None:
        server = _Server()
        notes = SampleNotes()
        first = ServerHandle("invented", self._remote())
        second = ServerHandle("invented-too", self._remote())
        for handle in (first, second):
            handle._all_tools = server.tools()
            handle.sample_notes = notes
            # The job's own copy of the sample: on a server other jobs share,
            # the only path an open may name.
            handle.error_sample_path = lambda: PATH
        assert first.note_key == second.note_key == "remote http://decompiler.invalid:9000/mcp"
        _open(first)
        _open(second)
        assert server.names() == ["open_thing", "pick", "study", "pick"]

    def test_two_local_processes_keep_their_own_notes(self) -> None:
        cfg = MCPServerConfig(command="decompiler-mcp", args=["--stdio"], sample_open=SPEC)
        first, second = ServerHandle("a", cfg), ServerHandle("a", cfg)
        assert first.note_key != second.note_key
        assert first.note_key.startswith("stdio decompiler-mcp --stdio")

    def test_a_second_spelling_of_a_noted_path_is_forwarded_not_answered(self) -> None:
        server = _Server()
        handle = _handle(server)
        _open(handle, "/samples/a.bin")
        _open(handle, "/samples//sub/../a.bin")
        assert server.names() == ["open_thing", "pick", "study", "open_thing"]
        assert server.calls[-1] == ("open_thing", {"where": "/samples//sub/../a.bin"})

    def test_transports_to_one_address_name_one_server(self) -> None:
        from maljan.providers.sample_open import server_note_key

        keys = {
            server_note_key(MCPServerConfig(transport=transport, url=url))
            for transport, url in (
                ("http", "http://127.0.0.1:8089"),
                ("streamable-http", "http://127.0.0.1:8089/"),
                ("sse", "HTTP://127.0.0.1:8089"),
            )
        }
        assert keys == {"remote http://127.0.0.1:8089"}

    def test_loopback_spellings_are_kept_apart(self) -> None:
        """Three listeners may answer them; keeping them apart costs one more open at most."""
        from maljan.providers.sample_open import server_note_key

        keys = {
            server_note_key(MCPServerConfig(transport="http", url=url))
            for url in ("http://localhost:8089", "http://127.0.0.1:8089", "http://[::1]:8089")
        }
        assert len(keys) == 3

    def test_what_selects_a_backend_is_an_opaque_number_never_the_secret(self) -> None:
        from pydantic import SecretStr

        from maljan.providers.sample_open import server_note_key

        token_a = "tenant-a-" + "x" * 20
        token_b = "tenant-b-" + "y" * 20

        def key(url: str, token: str = "") -> str:
            return server_note_key(
                MCPServerConfig(transport="http", url=url, auth_token=SecretStr(token))
            )

        base = "http://gateway.invalid:9000/mcp"
        a, b = key(base, token_a), key(base, token_b)
        assert a != b and a == key(base, token_a)
        assert key(base + "?server=one") != key(base + "?server=two")
        assert key("http://alice:pw@gateway.invalid:9000/mcp") != key(base)
        assert key(base) == "remote http://gateway.invalid:9000/mcp"
        import hashlib

        for said in (a, b, key("http://alice:pw@gateway.invalid:9000/mcp?server=one")):
            assert "tenant" not in said and "alice" not in said and "pw" not in said
            assert "server=one" not in said
            for secret in (token_a, token_b):
                assert hashlib.sha256(secret.encode()).hexdigest()[:8] not in said

    def test_a_default_port_is_written(self) -> None:
        from maljan.providers.sample_open import server_note_key

        assert server_note_key(MCPServerConfig(transport="http", url="http://g")) == (
            server_note_key(MCPServerConfig(transport="http", url="http://g:80"))
        )

    def test_a_local_process_is_named_by_a_number_never_reused(self) -> None:
        import gc

        cfg = MCPServerConfig(command="decompiler-mcp", sample_open=SPEC)
        seen = set()
        for _ in range(50):
            handle = ServerHandle("a", cfg)
            seen.add(handle.note_key)
            del handle
            gc.collect()
        assert len(seen) == 50


class TestTheDeclaredToolsHaveNoClientDeadline:
    """An open or analysis the block declares is held long-running, as a manifest's own is.

    The deployment's derived budget (capa's) would cut a long analysis, the
    opener would note nothing, and every later open would import and analyse
    again, to be cut again.
    """

    def _guard(self, explicit: float = 0.0) -> Any:
        from maljan.providers.server_guard import guard_from_settings

        cfg = Settings.model_validate(
            {
                "static": {"capa": {"timeout_seconds": 1}},
                "mcp": {"breaker": {"call_timeout_seconds": explicit}},
            }
        )
        return guard_from_settings("invented", cfg, sample_open=SPEC)

    def test_the_declared_open_and_analysis_wait_as_long_as_they_take(self) -> None:
        guard = self._guard()
        assert guard.call_timeout("study") is None
        assert guard.call_timeout("open_thing") is None
        assert guard.call_timeout("look") is not None
        assert guard.call_timeout("pick") is not None

    def test_an_operator_s_own_budget_bounds_them(self) -> None:
        guard = self._guard(explicit=5.0)
        assert guard.call_timeout("study") is not None

    def test_an_analysis_that_outlasts_the_deployment_budget_is_noted(self) -> None:
        """The analysis takes longer than the derived budget and its grace, and still answers."""
        from maljan.providers import server_guard

        guard = self._guard()
        budget = guard.call_timeout("look")
        assert budget is not None
        server = _Server()
        clock = {"now": 0.0}

        async def slow_study(handle: str = "") -> str:
            server.calls.append(("study", {"handle": handle}))
            clock["now"] += budget * 3  # three times what any other call may take
            deadline = guard.call_timeout("study")
            if deadline is not None and clock["now"] > deadline:
                return json.dumps({"tool_error": "timeout", "detail": "cut at the deadline"})
            return json.dumps({"studied": handle})

        tools = [t for t in server.tools() if t.name != "study"]
        tools.append(
            StructuredTool.from_function(
                coroutine=slow_study,
                name="study",
                description="study",
                args_schema=_Handle,
                infer_schema=False,
            )
        )
        handle = ServerHandle("invented", MCPServerConfig(sample_open=SPEC))
        handle._all_tools = tools
        handle.sample_notes = SampleNotes()
        handle.guard = guard
        _open(handle)
        assert handle.sample_notes.get(handle.note_key, PATH) is not None
        assert server_guard.CALL_TIMEOUT_GRACE_SECONDS > 0
