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

from app.services.settings_probes import _completion_request, _said_something
from maljan.core.config import Settings


def _answer(payload: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=payload)


class TestWhatCountsAsAnAnswer:
    def test_a_plain_completion_counts(self) -> None:
        assert _said_something("ollama", _answer({"response": "OK"}))

    def test_thinking_alone_counts(self) -> None:
        """The reproduced case: the whole budget spent in the thinking channel."""
        assert _said_something(
            "ollama",
            _answer({"response": "", "thinking": 'The user wants the single word "ready"'}),
        )

    def test_the_chat_shape_counts_too(self) -> None:
        """``/api/chat`` puts both under ``message``; a proxy may answer either."""
        assert _said_something("ollama", _answer({"message": {"content": "OK"}}))
        assert _said_something("ollama", _answer({"message": {"thinking": "considering"}}))

    def test_an_empty_answer_is_still_nothing(self) -> None:
        assert not _said_something("ollama", _answer({"response": "", "thinking": "   "}))
        assert not _said_something("ollama", _answer({"message": {"content": ""}}))


class TestTheRequestTheProbeSends:
    def test_thinking_is_left_alone_by_default(self) -> None:
        """A model that does not know the field must not be sent it."""
        _url, _headers, body = _completion_request("ollama", "", "qwen3:8b", "")
        assert "think" not in body

    def test_the_setting_turns_thinking_off_in_the_request(self) -> None:
        _url, _headers, body = _completion_request(
            "ollama", "", "qwen3:8b", "", disable_thinking=True
        )
        assert body["think"] is False
        assert body["options"]["num_predict"] > 0

    def test_the_openai_switch_is_not_sent_to_ollama(self) -> None:
        """The two providers spell it differently; only the right one travels."""
        _url, _headers, body = _completion_request(
            "ollama", "", "qwen3:8b", "", disable_thinking=True
        )
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

    def test_the_probe_reads_the_staged_value(self) -> None:
        """Staging it in the console changes the probe, not only the run."""
        from app.services.settings_probes import _INPUTS

        assert _INPUTS["llm"]["core.llm.ollama.disable_thinking"] == "ollama_disable_thinking"

    @pytest.mark.asyncio
    async def test_the_probe_sends_it_when_the_deployment_asked_for_it(self) -> None:
        from app.services.settings_probes import _probe_llm_ollama

        seen: list[dict[str, Any]] = []

        async def _complete(provider: str, **kwargs: Any) -> tuple[bool, str]:
            seen.append(kwargs)
            return True, "answered"

        import app.services.settings_probes as probes

        async def _tags(url: str, headers: Any = None) -> tuple[bool, str, Any]:
            return True, "ok", httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})

        original_get = probes._get
        original_complete = probes.complete_one_turn
        probes._get = _tags  # type: ignore[assignment]
        probes.complete_one_turn = _complete  # type: ignore[assignment]
        try:
            result = await _probe_llm_ollama(
                {
                    "ollama_base_url": "http://localhost:11434",
                    "ollama_expert_model": "qwen3:8b",
                    "ollama_judge_model": "qwen3:8b",
                    "ollama_disable_thinking": True,
                }
            )
        finally:
            probes._get = original_get  # type: ignore[assignment]
            probes.complete_one_turn = original_complete  # type: ignore[assignment]

        assert result.ok
        assert seen, "the probe asked nothing"
        assert all(call.get("disable_thinking") is True for call in seen)
