"""A reasoning model on Ollama can be probed, and can be told not to think.

Every reasoning model on Ollama failed the probe: the eight tokens it is given
were spent in the model's thinking channel, `response` came back empty, and
`core.llm.require_probe` then refused to create any job at all — a healthy
model the deployment could not select. The probe reads the thinking channel as
an answer now (the OpenAI-compatible one already reads `reasoning_content`),
and `core.llm.ollama.disable_thinking` spends the budget on the answer instead,
for the agents' calls and for the probe alike.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.services.settings_probes import _said_something
from maljan.core.config import Settings
from maljan.llm.ollama_provider import OllamaProvider
from maljan.llm.provider_base import facts_of


def _answer(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=payload)


def _body(*, disable_thinking: bool = False) -> dict[str, Any]:
    settings = Settings()
    settings.llm.ollama.disable_thinking = disable_thinking
    return OllamaProvider.one_turn_request(settings, "", "qwen3:8b").body


class TestWhatCountsAsAnAnswer:
    def test_a_plain_completion_counts(self) -> None:
        assert _said_something(facts_of("ollama"), _answer({"response": "OK"}))

    def test_thinking_alone_counts(self) -> None:
        """The reproduced case: the whole budget spent in the thinking channel."""
        assert _said_something(
            facts_of("ollama"),
            _answer({"response": "", "thinking": 'The user wants the single word "ready"'}),
        )

    def test_the_chat_shape_counts_too(self) -> None:
        """``/api/chat`` puts both under ``message``; a proxy may answer either."""
        assert _said_something(facts_of("ollama"), _answer({"message": {"content": "OK"}}))
        assert _said_something(
            facts_of("ollama"), _answer({"message": {"thinking": "considering"}})
        )

    def test_an_empty_answer_is_still_nothing(self) -> None:
        assert not _said_something(facts_of("ollama"), _answer({"response": "", "thinking": "   "}))
        assert not _said_something(facts_of("ollama"), _answer({"message": {"content": ""}}))


class TestTheRequestTheProbeSends:
    def test_thinking_is_left_alone_by_default(self) -> None:
        """A model that does not know the field must not be sent it."""
        assert "think" not in _body()

    def test_the_setting_turns_thinking_off_in_the_request(self) -> None:
        body = _body(disable_thinking=True)
        assert body["think"] is False
        assert body["options"]["num_predict"] > 0

    def test_the_openai_switch_is_not_sent_to_ollama(self) -> None:
        """The two providers spell it differently; only the right one travels."""
        body = _body(disable_thinking=True)
        assert "chat_template_kwargs" not in body
        assert "extra_body" not in body


class TestTheSettingReachesTheAgents:
    def test_the_config_carries_it_and_leaves_it_off(self) -> None:
        assert Settings().llm.ollama.disable_thinking is False

    def test_the_provider_forwards_it_as_the_reasoning_switch(self) -> None:
        """``ChatOllama(reasoning=False)`` is Ollama's ``think: false``."""
        built: dict[str, Any] = {}

        class _ChatOllama:
            def __init__(self, **kwargs: Any) -> None:
                built.update(kwargs)

        import sys
        import types

        module = types.ModuleType("langchain_ollama")
        module.ChatOllama = _ChatOllama  # type: ignore[attr-defined]
        original = sys.modules.get("langchain_ollama")
        sys.modules["langchain_ollama"] = module
        try:
            from maljan.llm.ollama_provider import OllamaProvider

            settings = Settings()
            settings.llm.ollama.disable_thinking = True
            OllamaProvider(settings).build_model("qwen3:8b", 0.1)
            assert built["reasoning"] is False

            built.clear()
            settings.llm.ollama.disable_thinking = False
            OllamaProvider(settings).build_model("qwen3:8b", 0.1)
            assert "reasoning" not in built, "a model that does not think is not told to stop"
        finally:
            if original is not None:
                sys.modules["langchain_ollama"] = original
            else:
                del sys.modules["langchain_ollama"]


class TestItIsConfigurable:
    def test_the_catalogue_offers_it(self) -> None:
        from maljan.core.settings_catalog import core_catalog

        entry = next((e for e in core_catalog() if e.path == "llm.ollama.disable_thinking"), None)
        assert entry is not None, "the setting is not in the catalogue"
        assert entry.type == "bool"
        assert entry.title and entry.description

    @pytest.mark.asyncio
    async def test_the_probe_sends_it_when_the_deployment_asked_for_it(self) -> None:
        """Staging it in the console changes the probe, not only the run."""
        import app.services.settings_probes as probes

        sent: list[dict[str, Any]] = []

        async def _tags(url: str, headers: Any = None) -> tuple[bool, str, Any]:
            return True, "ok", httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

        class _Client:
            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def post(self, url: str, headers: Any = None, json: Any = None) -> Any:
                sent.append(json)
                return httpx.Response(200, json={"response": "OK"})

        original_get, original_client = probes._get, probes._client
        probes._get = _tags  # type: ignore[assignment]
        probes._client = lambda timeout=0: _Client()  # type: ignore[assignment]
        try:
            settings = probes.candidate_settings(
                {
                    "core.llm.provider": "ollama",
                    "core.llm.ollama.expert_model": "qwen3:8b",
                    "core.llm.ollama.judge_model": "qwen3:8b",
                    "core.llm.ollama.disable_thinking": True,
                },
                {},
            )
            result = await probes.probe_llm(settings)
        finally:
            probes._get = original_get  # type: ignore[assignment]
            probes._client = original_client  # type: ignore[assignment]

        assert result.ok
        assert sent, "the probe asked nothing"
        assert all(body.get("think") is False for body in sent)
