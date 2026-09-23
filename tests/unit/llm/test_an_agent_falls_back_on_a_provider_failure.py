"""An agent's ordered model list is walked only when a provider fails.

The next model answers a turn the one before could not — a refused
connection, a timeout, a 5xx, a model the server does not have — and never a
turn it answered: what a model said is not a reason to ask another one.
"""

from __future__ import annotations

import asyncio
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
    provider_failure,
    turn_model,
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

    def test_every_turn_starts_at_the_first_model(self) -> None:
        chain, (first, second) = _chain(
            [APIConnectionError(request=_request()), "first is back"], ["second says"]
        )
        chain.invoke([HumanMessage(content="one")])
        again = chain.invoke([HumanMessage(content="two")])
        assert again.content == "first is back"
        assert again.response_metadata[MODEL_KEY] == "openai/model-0"
        assert second.calls == 1

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
