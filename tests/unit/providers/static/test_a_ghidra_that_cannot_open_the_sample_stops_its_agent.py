"""A Ghidra that cannot open the job's sample stops its agent, and says so.

With the worker's ``GHIDRA_CONTAINER_SAMPLES_PATH`` set to a host path the
container cannot see, Ghidra's ``load_program`` answered HTTP 200 with
``{"error": "File not found: ..."}``, no exception was raised, and every call
after it answered "No program loaded". With no default loop limits a reverser
would have kept calling a Ghidra with nothing loaded until the job's spend
ceiling. Four claims, tested apart:

* a Ghidra error reply is a failed call on the ledger, in the server's words;
* the load made before the loop is a precondition: a failure raises before any
  model turn, and the provider remembers it;
* the pinned load inside a loop that fails ends the loop at once, filed as a
  failed call, with no further Ghidra call and no salvage;
* the failure travels as a failed agent with the sentence, not as a thinner
  report, and an agent that asked the stopped one carries on.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, SecretStr, create_model

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.ghidra_http_client import GhidraHTTPClient
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.core.exceptions import SampleNotOpened
from maljan.pipeline.events import describe_exception
from maljan.providers.static.ghidra import (
    GhidraStaticProvider,
    load_error_words,
    prepare_sample,
    sample_not_opened,
)
from maljan.schemas.evidence import EvidenceCounter

CONTAINER_PATH = "/data/samples/.work/abc.exe"
HOST_PATH = "/home/someone/Maljan/data/samples/.work/abc.exe"
NOT_FOUND = json.dumps({"error": f"File not found: {HOST_PATH}"})
NO_PROGRAM = json.dumps({"error": "No program loaded."})
LOADED = json.dumps({"success": True, "program": "abc.exe"})


# ---------------------------------------------------------------------------
# A Ghidra error reply is a failed call
# ---------------------------------------------------------------------------

SCHEMA = {
    "tools": [
        {"path": "/get_function_count", "method": "GET", "params": []},
        {"path": "/list_exports", "method": "GET", "params": []},
        {"path": "/get_current_program_info", "method": "GET", "params": []},
    ]
}


def _client(answers: dict[str, httpx.Response]) -> GhidraHTTPClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/mcp/schema":
            return httpx.Response(200, json=SCHEMA)
        return answers[request.url.path]

    client = GhidraHTTPClient(base_url="http://ghidra.invalid")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def _recorded(client: GhidraHTTPClient, tool: str) -> Any:
    async def go() -> Any:
        await client.initialize()
        recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
        tools = {t.name: t for t in record_tools(client.get_tools(), recorder)}
        await tools[tool].coroutine()
        await client.aclose()
        return recorder.entries[-1]

    return asyncio.run(go())


class TestAGhidraErrorReplyIsAFailedCall:
    def test_the_json_no_program_reply(self) -> None:
        entry = _recorded(
            _client({"/get_function_count": httpx.Response(200, text=NO_PROGRAM)}),
            "get_function_count",
        )
        assert entry.ok is False
        assert entry.error == "No program loaded."

    def test_a_file_not_found_reply(self) -> None:
        entry = _recorded(
            _client({"/list_exports": httpx.Response(200, text=NOT_FOUND)}), "list_exports"
        )
        assert entry.ok is False
        assert entry.error == f"File not found: {HOST_PATH}"

    def test_a_bare_no_program_sentence(self) -> None:
        entry = _recorded(
            _client({"/get_current_program_info": httpx.Response(200, text="No program loaded.")}),
            "get_current_program_info",
        )
        assert entry.ok is False
        assert "No program loaded." in (entry.error or "")

    def test_an_http_error_is_json_the_ledger_reads(self) -> None:
        entry = _recorded(
            _client({"/list_exports": httpx.Response(401, text="Unauthorized")}), "list_exports"
        )
        assert entry.ok is False
        assert json.loads(entry.output.split("\n", 1)[-1])["tool_error"] == "http_status"
        assert "Unauthorized" in (entry.error or "")

    def test_an_answer_is_still_an_answer(self) -> None:
        entry = _recorded(
            _client({"/get_function_count": httpx.Response(200, text='{"count": 146}')}),
            "get_function_count",
        )
        assert entry.ok is True


class TestWhatALoadAnswerSays:
    def test_a_program_is_no_error(self) -> None:
        assert load_error_words(LOADED) is None

    def test_an_error_is_its_words(self) -> None:
        assert load_error_words(NOT_FOUND) == f"File not found: {HOST_PATH}"

    def test_prose_is_not_read_as_a_failed_load(self) -> None:
        assert load_error_words("There is no room left for a tool answer.") is None

    def test_the_sentence_names_the_provider_the_words_and_the_check(self) -> None:
        said = str(sample_not_opened(f"File not found: {HOST_PATH}"))
        assert said == (
            f"Ghidra could not open the job's sample: File not found: {HOST_PATH}; "
            "check GHIDRA_CONTAINER_SAMPLES_PATH / the container mount"
        )

    def test_the_published_form_keeps_the_sentence_and_drops_the_host_path(self) -> None:
        published = describe_exception(sample_not_opened(f"File not found: {HOST_PATH}"))
        assert "Ghidra could not open the job's sample" in published
        assert "GHIDRA_CONTAINER_SAMPLES_PATH" in published
        assert "/home/someone" not in published


# ---------------------------------------------------------------------------
# The load before the loop is a precondition
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status

    def raise_for_status(self) -> None:
        return None


class _HttpClient:
    """Stands in for ``httpx.Client`` and records the Ghidra endpoints called."""

    def __init__(self, load_body: str) -> None:
        self.load_body = load_body
        self.paths: list[str] = []

    def __call__(self, **_kwargs: Any) -> _HttpClient:
        return self

    def __enter__(self) -> _HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: Any = None, params: Any = None) -> _Resp:  # noqa: A002
        self.paths.append(url.rsplit("/", 1)[-1])
        return _Resp(self.load_body if url.endswith("/load_program") else "{}")

    def get(self, url: str, params: Any = None) -> _Resp:
        self.paths.append(url.rsplit("/", 1)[-1])
        return _Resp('{"nodes": [], "edges": []}')


def _settings(*, sink: bool = True) -> Any:
    class _G:
        enabled = True
        transport = "http"
        url = "http://ghidra.invalid"
        auth_token = SecretStr("")

    class _P:
        use_sink_reachability = sink
        sink_reachability_max_funcs = 12

    class _S:
        class static:  # noqa: N801
            provider = "ghidra"
            ghidra = _G()

        preprocessing = _P()

    return _S()


def _provider() -> GhidraStaticProvider:
    cfg = _settings().static.ghidra
    return GhidraStaticProvider(cfg, None, None)  # type: ignore[arg-type]


class TestTheLoadIsAPrecondition:
    def test_a_failed_load_raises_before_anything_else(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        http = _HttpClient(NOT_FOUND)
        monkeypatch.setattr("httpx.Client", http)
        with pytest.raises(SampleNotOpened) as stopped:
            prepare_sample(_settings(), "ghidra", CONTAINER_PATH)
        assert http.paths == ["load_program"]
        assert f"File not found: {HOST_PATH}" in str(stopped.value)

    def test_it_holds_with_the_sink_pre_pass_switched_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        http = _HttpClient(NOT_FOUND)
        monkeypatch.setattr("httpx.Client", http)
        with pytest.raises(SampleNotOpened):
            prepare_sample(_settings(sink=False), "ghidra", CONTAINER_PATH)

    def test_an_opened_sample_is_made_current_and_the_pass_is_optional(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        http = _HttpClient(LOADED)
        monkeypatch.setattr("httpx.Client", http)
        assert prepare_sample(_settings(sink=False), "ghidra", CONTAINER_PATH) == ""
        assert http.paths == ["load_program", "switch_program"]

    def test_the_provider_remembers_and_is_not_asked_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        http = _HttpClient(NOT_FOUND)
        monkeypatch.setattr("httpx.Client", http)
        provider = _provider()
        provider.pin_sample(CONTAINER_PATH)
        with pytest.raises(SampleNotOpened):
            prepare_sample(_settings(), "ghidra", CONTAINER_PATH, provider=provider)
        with pytest.raises(SampleNotOpened):
            prepare_sample(_settings(), "ghidra", CONTAINER_PATH, provider=provider)
        assert http.paths == ["load_program"]
        assert provider.sample_failure() is not None

    def test_another_provider_calls_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        http = _HttpClient(NOT_FOUND)
        monkeypatch.setattr("httpx.Client", http)
        assert prepare_sample(_settings(), "r2", CONTAINER_PATH) == ""
        assert http.paths == []


# ---------------------------------------------------------------------------
# The pinned load inside a loop ends it
# ---------------------------------------------------------------------------


class _File(BaseModel):
    file: str = ""


def _ghidra_tools(provider: GhidraStaticProvider, calls: list[str]) -> list[Any]:
    """Ghidra's load, pinned by the provider, and one analysis tool, as the provider's."""

    async def load_program(file: str = "") -> str:
        calls.append("load_program")
        return NOT_FOUND

    async def get_function_count() -> str:
        calls.append("get_function_count")
        return NO_PROGRAM

    load = StructuredTool.from_function(
        coroutine=load_program,
        name="load_program",
        description="load",
        args_schema=_File,
        infer_schema=False,
    )
    count = StructuredTool.from_function(
        coroutine=get_function_count,
        name="get_function_count",
        description="count",
        args_schema=create_model("NoArgs"),
        infer_schema=False,
    )
    return stamp_source(provider._pin_load_program_path([load, count]), PROVIDER_FAMILY)


class _Reverser(BaseChatModel):
    """Asks for ``load_program``, then ``get_function_count``, turn after turn."""

    calls: list[list[BaseMessage]] = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.calls.append(sent)
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        name, args = (
            ("load_program", {"file": "/invented.exe"}) if turn == 0 else ("get_function_count", {})
        )
        asked = AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{turn}"}])
        return ChatResult(generations=[ChatGeneration(message=asked)])

    @property
    def _llm_type(self) -> str:
        return "reverser"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Container:
    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.config = None

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        return None

    def get_context_budget(self) -> Any:
        return None

    def get_server_registry(self) -> Any:
        return None

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self.provider


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


@contextlib.contextmanager
def _loop_settings() -> Iterator[None]:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = None
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = None
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 20
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _reverser(provider: GhidraStaticProvider, calls: list[str]) -> tuple[_Analyst, _Reverser]:
    model = _Reverser(calls=[])
    agent = _Analyst(llm=model, name="reverser")
    agent.logger = logging.getLogger("test.ghidra_open")
    agent._container = _Container(provider)
    agent.tools = _ghidra_tools(provider, calls)
    return agent, model


class TestThePinnedLoadEndsTheLoop:
    def _run(self) -> tuple[_Analyst, _Reverser, list[str], GhidraStaticProvider, Any]:
        provider = _provider()
        provider.pin_sample(CONTAINER_PATH)
        calls: list[str] = []
        agent, model = _reverser(provider, calls)
        with _loop_settings(), pytest.raises(SampleNotOpened) as stopped:
            agent.execute_tool_loop([("system", "reverse it"), ("human", "the sample")])
        return agent, model, calls, provider, stopped.value

    def test_one_model_turn_and_no_ghidra_call_after_the_load(self) -> None:
        _agent, model, calls, _provider_, _exc = self._run()
        assert len(model.calls) == 1
        assert calls == ["load_program"]

    def test_the_load_is_a_failed_entry_in_the_servers_words(self) -> None:
        agent, _model, _calls, _provider_, exc = self._run()
        entries = agent.drain_evidence_entries()
        assert [e.tool for e in entries] == ["load_program"]
        assert entries[0].ok is False
        assert f"File not found: {HOST_PATH}" in (entries[0].error or "")
        assert "Ghidra could not open the job's sample" in (entries[0].error or "")
        assert exc.stopped_agent == "reverser"

    def test_a_later_loop_is_not_started(self) -> None:
        agent, _model, _calls, provider, _exc = self._run()
        calls: list[str] = []
        again, model = _reverser(provider, calls)
        with _loop_settings(), pytest.raises(SampleNotOpened) as stopped:
            again.execute_tool_loop([("system", "reverse it"), ("human", "the sample")])
        assert model.calls == []
        assert calls == []
        assert stopped.value.stopped_agent == "reverser"

    def test_a_new_pin_is_tried_afresh(self) -> None:
        _agent, _model, _calls, provider, _exc = self._run()
        provider.pin_sample("/data/samples/.work/other.exe")
        assert provider.sample_failure() is None


# ---------------------------------------------------------------------------
# The failure is the agent's, and the caller of an ask carries on
# ---------------------------------------------------------------------------


def _generic() -> ConfigurableAnalyst:
    resolved = ResolvedAgent(
        key="all_tools_reverser_ghidra",
        role="generic",
        prompt="reverse it",
        tools=stamp_source(
            [
                StructuredTool.from_function(
                    func=lambda: "x", name="decompile_function", description="d"
                )
            ],
            PROVIDER_FAMILY,
        ),
        static_provider_id="ghidra",
        llm=None,
    )
    agent = ConfigurableAnalyst("all_tools_reverser_ghidra", resolved, llm=None)  # type: ignore[arg-type]
    agent._analysis_file_path = CONTAINER_PATH
    return agent


class TestTheFailureIsTheAgents:
    def test_the_reverser_stops_before_its_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("httpx.Client", _HttpClient(NOT_FOUND))
        monkeypatch.setattr("maljan.core.config.get_settings", lambda: _settings())
        agent = _generic()
        looped: list[Any] = []
        monkeypatch.setattr(agent, "execute_tool_loop", lambda messages: looped.append(messages))

        with pytest.raises(SampleNotOpened):
            agent.analyze_isr(json.dumps({"analysis_file_path": CONTAINER_PATH}))
        assert looped == []

    def test_a_stop_inside_the_loop_is_not_a_thinner_report(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _generic()

        def stops(_messages: Any) -> str:
            raise sample_not_opened("No program loaded.")

        monkeypatch.setattr(agent, "execute_tool_loop", stops)
        with pytest.raises(SampleNotOpened):
            agent.revise_isr("data", "own", {}, "feedback")
        assert agent.degradation_reasons == []

    def test_nothing_is_salvaged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = _generic()

        def stops(_data: str) -> Any:
            raise sample_not_opened("No program loaded.")

        salvaged: list[str] = []
        monkeypatch.setattr(agent, "analyze_isr", stops)
        monkeypatch.setattr(agent, "_salvaged_isr", lambda text: salvaged.append(text))
        monkeypatch.setattr(agent, "_truncate_input", lambda text: text)
        with pytest.raises(SampleNotOpened):
            agent.safe_analyze_isr("data")
        assert salvaged == []

    def test_no_later_chunk_is_tried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

        agent = _generic()
        tried: list[str] = []

        def stops(data: str) -> Any:
            tried.append(data)
            raise sample_not_opened("No program loaded.")

        monkeypatch.setattr(agent, "analyze_isr", stops)
        strategy = next(iter(ChunkStrategy))
        chunks = [TextChunk(i, 3, strategy, f"part {i}", 6, 1, "static") for i in range(3)]
        with pytest.raises(SampleNotOpened):
            agent.safe_analyze_isr_chunked(chunks)
        assert len(tried) == 1

    def test_the_caller_of_an_ask_reads_a_failed_ask(self) -> None:
        def ask(task: str) -> str:
            failure = sample_not_opened("No program loaded.")
            failure.stopped_agent = "all_tools_reverser_ghidra"
            raise failure

        tool = StructuredTool.from_function(func=ask, name="ask_reverser", description="ask")
        recorder = EvidenceRecorder("lead", counter=EvidenceCounter())
        [recorded] = record_tools([tool], recorder)

        said = recorded.func(task="decompile the entry")

        assert "Ghidra could not open the job's sample" in said
        assert recorder.entries[-1].ok is False

    def test_the_stage_records_a_failed_agent_with_the_sentence(self) -> None:
        from maljan.pipeline import events as ev
        from maljan.pipeline.nodes import make_stage_agent_node
        from tests.stages import ANALYSIS_STAGE
        from tests.unit.pipeline.test_a_failure_names_its_type_not_its_message import (
            _container as _node_container,
        )

        published: list[tuple[str, dict[str, Any]]] = []
        container = _node_container(lambda kind, data: published.append((kind, data)))
        container.get_agent.side_effect = sample_not_opened(f"File not found: {HOST_PATH}")

        update = make_stage_agent_node(ANALYSIS_STAGE, "network", container)(
            {"file_hash": "a" * 64}
        )

        report = update["reports"]["network"]
        assert report.startswith("[ERROR]")
        assert "Ghidra could not open the job's sample: File not found: abc.exe" in report
        assert "check GHIDRA_CONTAINER_SAMPLES_PATH / the container mount" in report
        assert "/home/someone" not in report
        (message,) = [data for kind, data in published if kind == ev.AGENT_MESSAGE]
        assert message["status"] == "failed"
        assert "network failed" in json.dumps(update, default=str)
