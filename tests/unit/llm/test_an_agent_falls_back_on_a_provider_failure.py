"""An agent's ordered model list is walked only when a provider fails.

The next model answers a turn the one before could not — a refused
connection, a timeout, a 5xx, a model the server does not have — and never a
turn it answered: what a model said is not a reason to ask another one.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import httpx
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from openai import APIConnectionError, APIStatusError, APITimeoutError
from pydantic import ValidationError

from maljan.core.config import AgentLLMConfig, Settings
from maljan.core.model_assignments import assignments_for, model_label
from maljan.llm.fallback import (
    FALLBACK_KEY,
    MODEL_KEY,
    FallbackChatModel,
    ModelStalled,
    provider_failure,
    restart_models,
    turn_model,
    turn_share_seconds,
)


def _request() -> httpx.Request:
    return httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")


def _status(code: int, body: Any = None) -> APIStatusError:
    response = httpx.Response(code, request=_request())
    return APIStatusError("provider said no", response=response, body=body)


class _Scripted(BaseChatModel):
    """A chat model that raises or answers from a script, and counts its calls."""

    script: list[Any]
    calls: int = 0
    bound: list[Any] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        self.bound.append((tools, kwargs))
        return self.bind(tools=tools)

    def _next(self) -> ChatResult:
        self.calls += 1
        step = self.script[min(self.calls - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        message = AIMessage(
            content=str(step),
            usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        return self._next()

    async def _agenerate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        return self._next()


def _chain(*scripts: list[Any]) -> tuple[FallbackChatModel, list[_Scripted]]:
    models = [_Scripted(script=list(script), bound=[]) for script in scripts]
    labels = [f"openai/model-{i}" for i in range(len(models))]
    return FallbackChatModel(models=models, labels=labels, agent="static"), models


class TestWhatCountsAsAProviderFailure:
    def test_a_refused_connection_is_one(self) -> None:
        assert provider_failure(APIConnectionError(request=_request()))

    def test_a_timeout_is_one(self) -> None:
        assert provider_failure(APITimeoutError(request=_request())) == "the provider timed out"

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    def test_a_server_error_is_one(self, code: int) -> None:
        assert f"HTTP {code}" in (provider_failure(_status(code)) or "")

    def test_a_missing_model_is_one(self) -> None:
        assert "does not serve" in (provider_failure(_status(404)) or "")

    def test_a_refusal_the_provider_reports_as_an_error_is_one(self) -> None:
        assert provider_failure(_status(400, {"code": "content_filter"}))

    def test_a_request_the_provider_found_malformed_is_not_one(self) -> None:
        assert provider_failure(_status(400, {"code": "invalid_request_error"})) is None

    def test_a_socket_refusal_is_one(self) -> None:
        assert provider_failure(ConnectionRefusedError(111, "refused"))

    def test_the_transport_under_a_wrapper_is_read(self) -> None:
        try:
            try:
                raise httpx.ConnectError("refused")
            except httpx.ConnectError as inner:
                raise RuntimeError("the SDK wrapped it") from inner
        except RuntimeError as outer:
            assert provider_failure(outer)

    def test_a_parse_error_is_not_one(self) -> None:
        assert provider_failure(ValueError("the answer did not parse")) is None


class TestTheListIsWalkedOnlyOnAProviderFailure:
    def test_the_first_model_answers_when_it_can(self) -> None:
        chain, (first, second) = _chain(["first says"], ["second says"])
        answer = chain.invoke([HumanMessage(content="go")])
        assert answer.content == "first says"
        assert second.calls == 0
        assert turn_model(answer) == ("openai/model-0", "")

    def test_a_dropped_connection_moves_the_turn_to_the_next_model(self) -> None:
        chain, (first, second) = _chain([APIConnectionError(request=_request())], ["second says"])
        answer = chain.invoke([HumanMessage(content="go")])
        assert answer.content == "second says"
        assert first.calls == 1 and second.calls == 1
        model, reason = turn_model(answer)
        assert model == "openai/model-1"
        assert "openai/model-0" in reason and "could not be reached" in reason

    def test_the_async_path_walks_the_same_way(self) -> None:
        chain, (_first, second) = _chain([_status(503)], ["second says"])
        answer = asyncio.run(chain.ainvoke([HumanMessage(content="go")]))
        assert answer.content == "second says"
        assert "HTTP 503" in answer.response_metadata[FALLBACK_KEY]

    def test_anything_else_reaches_the_caller_and_no_other_model_is_asked(self) -> None:
        chain, (_first, second) = _chain([ValueError("not a provider failure")], ["unused"])
        with pytest.raises(ValueError):
            chain.invoke([HumanMessage(content="go")])
        assert second.calls == 0

    def test_the_last_failure_reaches_the_caller_when_every_model_failed(self) -> None:
        chain, models = _chain([_status(500)], [APIConnectionError(request=_request())])
        with pytest.raises(APIConnectionError):
            chain.invoke([HumanMessage(content="go")])
        assert [m.calls for m in models] == [1, 1]

    def test_the_model_that_took_over_stays_for_the_rest_of_the_loop(self) -> None:
        chain, (first, second) = _chain(
            [APIConnectionError(request=_request()), "first is back"], ["second says"]
        )
        switched = chain.invoke([HumanMessage(content="one")])
        again = chain.invoke([HumanMessage(content="two")])
        assert again.content == "second says"
        assert first.calls == 1 and second.calls == 2
        assert FALLBACK_KEY in switched.response_metadata
        assert FALLBACK_KEY not in again.response_metadata, "the switch is recorded once"
        assert again.response_metadata[MODEL_KEY] == "openai/model-1"

    def test_the_next_loop_starts_at_the_first_model_again(self) -> None:
        chain, (first, second) = _chain(
            [APIConnectionError(request=_request()), "first is back"], ["second says"]
        )
        chain.invoke([HumanMessage(content="one")])
        restart_models(chain)
        again = chain.invoke([HumanMessage(content="two")])
        assert again.content == "first is back"
        assert again.response_metadata[MODEL_KEY] == "openai/model-0"

    def test_tools_are_bound_on_the_model_that_answers(self) -> None:
        chain, (first, second) = _chain([_status(502)], ["called"])

        def pe_info(path: str) -> str:
            """Read a PE header."""
            return path

        bound = chain.bind_tools([pe_info])
        assert bound.kwargs["tools"][0]["function"]["name"] == "pe_info"
        bound.invoke([HumanMessage(content="go")])
        assert first.bound and second.bound
        assert second.bound[0][0][0]["function"]["name"] == "pe_info"

    def test_the_usage_the_answering_model_reported_is_kept(self) -> None:
        chain, _models = _chain([_status(500)], ["second says"])
        answer = chain.invoke([HumanMessage(content="go")])
        assert answer.usage_metadata["input_tokens"] == 10


class TestTheListIsSettings:
    def test_the_single_model_form_is_still_valid(self) -> None:
        entry = AgentLLMConfig(provider="openai", model="qwen")
        assert entry.fallbacks == []
        assert [c.model for c in entry.chain()] == ["qwen"]

    def test_an_entry_names_its_fallbacks_in_order(self) -> None:
        entry = AgentLLMConfig.model_validate(
            {
                "provider": "openai",
                "model": "qwen",
                "base_url": "http://127.0.0.1:8080/v1",
                "fallbacks": [
                    {"provider": "ollama", "model": "gemma"},
                    {"provider": "anthropic", "model": "claude"},
                ],
            }
        )
        assert [c.model for c in entry.chain()] == ["qwen", "gemma", "claude"]

    def test_a_model_named_twice_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="name each model once"):
            AgentLLMConfig.model_validate(
                {
                    "provider": "openai",
                    "model": "qwen",
                    "fallbacks": [{"provider": "openai", "model": "qwen"}],
                }
            )

    def test_a_fallback_endpoint_on_a_vendor_api_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="base_url"):
            AgentLLMConfig.model_validate(
                {
                    "provider": "openai",
                    "model": "qwen",
                    "fallbacks": [{"provider": "anthropic", "model": "c", "base_url": "http://x"}],
                }
            )


def _settings_with_fallbacks() -> Settings:
    settings = Settings()
    settings.llm.agents = {
        "static": AgentLLMConfig.model_validate(
            {
                "provider": "openai",
                "model": "qwen",
                "base_url": "http://127.0.0.1:8080/v1",
                "fallbacks": [{"provider": "ollama", "model": "gemma"}],
            }
        )
    }
    return settings


class TestEveryModelOnTheListIsAModelTheRunCalls:
    def test_the_assignments_carry_each_fallback_in_its_place(self) -> None:
        rows = assignments_for(_settings_with_fallbacks(), ["static", "static"])
        assert [(r.model, r.position) for r in rows] == [("qwen", 0), ("gemma", 1)]
        assert rows[1].provider == "ollama"

    def test_the_label_keeps_the_host_and_drops_what_the_url_carries(self) -> None:
        label = model_label("openai", "qwen", "http://user:secret@box:8080/v1")
        assert label == "openai/qwen @ http://box:8080"
        assert model_label("anthropic", "claude", "the Anthropic API") == "anthropic/claude"

    def test_the_window_is_asked_of_the_fallback_too(self) -> None:
        from maljan.llm.context_window import _questions

        asked = _questions(_settings_with_fallbacks(), ["static"])
        assert {q["model"] for q in asked} == {"qwen", "gemma"}

    def test_the_salvage_is_sized_for_the_smallest_declared_window(self) -> None:
        from maljan.agents.base_agent import _model_context_tokens

        settings = _settings_with_fallbacks()
        settings.llm.openai.context_size = 131072
        settings.llm.ollama.num_ctx = 8192
        assert _model_context_tokens(settings, "static") == 8192


class TestTheRegistryBuildsTheList:
    def test_an_entry_with_fallbacks_is_one_model_that_holds_them_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.llm import registry as reg

        built: list[tuple[str, str]] = []

        class _Provider:
            def __init__(self, config: Any) -> None:
                self.name = ""

            def build_model(self, model: str, temperature: float, **kwargs: Any) -> Any:
                built.append((model, str(kwargs.get("base_url") or "")))
                return _Scripted(script=["ok"], bound=[])

        monkeypatch.setitem(reg._PROVIDER_REGISTRY, "openai", _Provider)
        monkeypatch.setitem(reg._PROVIDER_REGISTRY, "ollama", _Provider)
        registry = reg.LLMProviderRegistry.__new__(reg.LLMProviderRegistry)
        registry._config = _settings_with_fallbacks()
        model = registry.build_model_for_agent("static")
        assert isinstance(model, FallbackChatModel)
        assert built == [("qwen", "http://127.0.0.1:8080/v1"), ("gemma", "")]
        assert model.labels == [
            "openai/qwen @ http://127.0.0.1:8080",
            "ollama/gemma @ http://localhost:11434",
        ]

    def test_an_entry_without_fallbacks_is_the_plain_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.llm import registry as reg

        class _Provider:
            def __init__(self, config: Any) -> None:
                pass

            def build_model(self, model: str, temperature: float, **kwargs: Any) -> Any:
                return _Scripted(script=["ok"], bound=[])

        monkeypatch.setitem(reg._PROVIDER_REGISTRY, "openai", _Provider)
        settings = Settings()
        settings.llm.agents = {"static": AgentLLMConfig(provider="openai", model="qwen")}
        registry = reg.LLMProviderRegistry.__new__(reg.LLMProviderRegistry)
        registry._config = settings
        assert isinstance(registry.build_model_for_agent("static"), _Scripted)


class _Stalling(_Scripted):
    """A model that stops answering: it sleeps well past any deadline."""

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        self.calls += 1
        time.sleep(2)
        return self._next()

    async def _agenerate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        self.calls += 1
        await asyncio.sleep(30)
        return self._next()


class TestAStallReachesTheFallback:
    def _chain(self) -> tuple[FallbackChatModel, _Scripted]:
        second = _Scripted(script=["second says"], bound=[])
        chain = FallbackChatModel(
            models=[_Stalling(script=["never"], bound=[]), second],
            labels=["openai/stalls", "ollama/answers"],
            agent="static",
            turn_deadline=0.2,
        )
        return chain, second

    def test_a_model_that_stops_answering_is_a_provider_failure_inside_the_list(self) -> None:
        chain, second = self._chain()
        answer = asyncio.run(chain.ainvoke([HumanMessage(content="go")]))
        assert answer.content == "second says"
        reason = answer.response_metadata[FALLBACK_KEY]
        assert reason.startswith(
            "openai/stalls: did not answer within its turn deadline of 200 ms"
        ), reason
        assert reason.count("openai/stalls") == 1, "the model is named once"
        assert provider_failure(ModelStalled("x did not answer")) == "x did not answer"

    def test_the_blocking_path_is_bounded_the_same_way(self) -> None:
        chain, second = self._chain()
        started = time.monotonic()
        answer = chain.invoke([HumanMessage(content="go")])
        assert answer.content == "second says"
        assert time.monotonic() - started < 1.5

    def test_the_last_model_has_no_deadline_of_its_own(self) -> None:
        chain, _second = self._chain()
        assert chain._deadline(0) == 0.2
        assert chain._deadline(1) is None

    def test_the_deadline_is_a_share_of_the_agent_loop_budget(self) -> None:
        settings = Settings()
        settings.react_agent_timeout = 180
        assert turn_share_seconds(settings, "an_agent_with_no_budget") == 90.0
        settings.llm.fallback_turn_share = 0.25
        assert turn_share_seconds(settings, "an_agent_with_no_budget") == 45.0
        settings.react_agent_timeout_overrides = {"strings": 600}
        assert turn_share_seconds(settings, "strings") == 150.0, "the agent's own budget first"


class TestAShortRetryAfterIsWaitedOutOnTheSameModel:
    def test_a_429_asking_for_a_moment_is_asked_again_before_the_list_moves(self) -> None:
        response = httpx.Response(429, request=_request(), headers={"retry-after": "0.01"})
        limited = APIStatusError("slow down", response=response, body=None)
        chain, (first, second) = _chain([limited, "first says"], ["second says"])
        answer = chain.invoke([HumanMessage(content="go")])
        assert answer.content == "first says"
        assert first.calls == 2 and second.calls == 0

    def test_a_long_retry_after_moves_on(self) -> None:
        response = httpx.Response(429, request=_request(), headers={"retry-after": "120"})
        limited = APIStatusError("slow down", response=response, body=None)
        chain, (_first, second) = _chain([limited], ["second says"])
        assert chain.invoke([HumanMessage(content="go")]).content == "second says"


class TestOnlyTheProviderSaysItFailed:
    def test_an_error_raised_while_handling_a_provider_failure_is_that_error(self) -> None:
        from langchain_core.exceptions import OutputParserException

        try:
            try:
                raise APITimeoutError(request=_request())
            except APITimeoutError:
                raise OutputParserException("the answer did not parse") from None
        except OutputParserException as exc:
            assert provider_failure(exc) is None

    def test_an_integer_code_on_something_that_is_not_a_provider_says_nothing(self) -> None:
        class _Local(Exception):
            code = 404

        assert provider_failure(_Local("not found locally")) is None


class TestAWrappedLocalServerIsNotSentStructuredOutput:
    def _models(self) -> tuple[Any, Any]:
        from langchain_openai import ChatOpenAI

        key = "sk-" + "x" * 20
        local = ChatOpenAI(model="qwen", api_key=key, base_url="http://127.0.0.1:9/v1")
        hosted = ChatOpenAI(model="gpt", api_key=key)
        return local, hosted

    def test_either_order_answers_as_the_local_server_would(self) -> None:
        from maljan.llm.registry import structured_output_supported

        settings = Settings()
        settings.llm.provider = "anthropic"
        local, hosted = self._models()
        assert structured_output_supported(settings, local) is False
        for models in ([local, hosted], [hosted, local]):
            chain = FallbackChatModel(models=models, labels=["a", "b"], agent="judge")
            assert structured_output_supported(settings, chain) is False

    def test_a_list_of_hosted_models_keeps_structured_output(self) -> None:
        from maljan.llm.registry import structured_output_supported

        _local, hosted = self._models()
        chain = FallbackChatModel(models=[hosted, hosted], labels=["a", "b"], agent="judge")
        assert structured_output_supported(None, chain) is True


def test_an_ollama_model_is_built_with_a_request_timeout() -> None:
    from maljan.llm.ollama_provider import OllamaProvider
    from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

    model = OllamaProvider(Settings()).build_model("gemma", 0.1)
    assert model.client_kwargs["timeout"] == PROVIDER_REQUEST_TIMEOUT_SECONDS


class TestTheDeadlineIsTheLoopsOwn:
    def test_a_stall_inside_an_ask_reaches_the_fallback_and_is_recorded(self) -> None:
        """An ask's clock, far shorter than the agent's own budget, sets the deadline."""
        from unittest.mock import MagicMock

        from maljan.agents.base_agent import BaseAnalyst, BudgetCeiling
        from maljan.core.token_ledger import TokenLedger

        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
                return ""

        second = _Scripted(script=["CLAIM: x\nEVIDENCE: ev_0001"], bound=[])
        chain = FallbackChatModel(
            models=[_Stalling(script=["never"], bound=[]), second],
            labels=["openai/stalls", "ollama/answers"],
            agent="static",
            # What the build time gave it from static's own budget: longer
            # than the whole ask.
            turn_deadline=750.0,
        )
        agent = _Analyst(llm=chain, name="static", tools=[])
        agent.pipeline_stage = "analysis"
        agent._container = MagicMock()
        agent.token_ledger = TokenLedger()
        agent._budget_ceiling = BudgetCeiling(steps=4, seconds=2.0)

        started = time.monotonic()
        answer = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert "CLAIM: x" in answer
        assert chain.turn_deadline == 1.0, "a share of the ask's two seconds"
        assert time.monotonic() - started < 2.0
        (switch,) = agent.token_ledger.snapshot()["fallbacks"]
        assert switch["model"] == "ollama/answers"
        assert re.search(
            r"openai/stalls: did not answer within its turn deadline of (9\d\d ms|1 s)",
            switch["reason"],
        ), switch["reason"]

    def test_a_loop_start_sets_the_deadline_from_that_loops_budget(self) -> None:
        chain, _models = _chain(["a"], ["b"])
        restart_models(chain, loop_seconds=300.0, share=0.5)
        assert chain.turn_deadline == 150.0
        restart_models(chain, loop_seconds=None)
        assert chain.turn_deadline == 150.0, "no budget named leaves the deadline as it was"

    def test_a_stall_late_in_a_loop_is_replaced_before_the_loop_ends(self) -> None:
        """A share of what is left, not of the whole: a stall at 70 % of the loop."""
        second = _Scripted(script=["second says"], bound=[])
        chain = FallbackChatModel(
            models=[_Stalling(script=["never"], bound=[]), second],
            labels=["openai/stalls", "ollama/answers"],
            agent="static",
        )
        loop = 4.0
        restart_models(chain, loop_seconds=loop, share=0.5)
        started = time.monotonic()
        time.sleep(0.7 * loop)
        answer = asyncio.run(chain.ainvoke([HumanMessage(content="late")]))
        assert answer.content == "second says"
        assert time.monotonic() - started < loop, "the loop would have cancelled it first"

    def test_the_deadline_never_falls_below_its_floor(self) -> None:
        chain, _models = _chain(["a"], ["b"])
        restart_models(chain, loop_seconds=10.0, share=0.5)
        chain._loop_ends = time.monotonic() - 5
        assert chain._deadline(0) == 1.0
        assert chain._deadline(1) is None, "the last model is bounded by the loop"

    def test_a_deadline_with_a_fraction_prints_it(self) -> None:
        from maljan.llm.fallback import _duration

        assert _duration(1.5) == "1.5 s"
        assert _duration(90.0) == "90 s"
        assert _duration(0.2) == "200 ms"


def test_an_abandoned_stall_does_not_hold_up_the_process_exit() -> None:
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import time
        from typing import Any
        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.language_models.fake_chat_models import FakeListChatModel
        from langchain_core.messages import HumanMessage
        from maljan.llm.fallback import FallbackChatModel

        class Stalls(BaseChatModel):
            @property
            def _llm_type(self) -> str:
                return "stalls"

            def _generate(self, *a: Any, **k: Any) -> Any:
                time.sleep(8)
                raise RuntimeError("never reached")

        chain = FallbackChatModel(
            models=[Stalls(), FakeListChatModel(responses=["answered"])],
            labels=["a", "b"],
            turn_deadline=0.2,
        )
        print(chain.invoke([HumanMessage(content="go")]).content)
        """
    )
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.stdout.strip().splitlines()[-1] == "answered", done.stderr
    assert time.monotonic() - started < 6.0, "the stalled thread held the exit"


class TestRetryAfter:
    def test_the_http_date_form_is_read(self) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        from maljan.llm.fallback import retry_after_seconds

        when = format_datetime(datetime.now(UTC) + timedelta(seconds=10), usegmt=True)
        response = httpx.Response(503, request=_request(), headers={"retry-after": when})
        wait = retry_after_seconds(APIStatusError("busy", response=response, body=None))
        assert wait is not None and 5 < wait <= 10

    def test_a_date_past_thirty_seconds_moves_on(self) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        from maljan.llm.fallback import retry_after_seconds

        when = format_datetime(datetime.now(UTC) + timedelta(minutes=5), usegmt=True)
        response = httpx.Response(503, request=_request(), headers={"retry-after": when})
        assert retry_after_seconds(APIStatusError("busy", response=response, body=None)) is None
