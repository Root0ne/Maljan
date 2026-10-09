"""An Anthropic model's window, output cap and effort levels come from the Models API.

``GET /v1/models/{model_id}`` answers ``max_input_tokens``, ``max_tokens`` and
``capabilities`` for free (https://platform.claude.com/docs/en/api/models/retrieve).
The window probe asks it, as it asks an OpenAI-compatible server's model list,
and says where each figure came from; when it cannot be asked, the vendored
table answers, and says so. The answer below has the shape the API gave for
``claude-haiku-5-5``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm import context_window as cw
from maljan.llm import model_capabilities, model_output_limits
from maljan.llm.anthropic_provider import AnthropicProvider

MODEL = "claude-haiku-5-5"

DESCRIPTION: dict[str, Any] = {
    "type": "model",
    "id": MODEL,
    "display_name": "Claude Haiku 5.5",
    "created_at": "2026-10-07T18:00:00Z",
    "line": "haiku",
    "max_input_tokens": 1000000,
    "max_tokens": 128000,
    "capabilities": {
        "batch": {"supported": True},
        "citations": {"supported": True},
        "code_execution": {"supported": True},
        "context_management": {
            "supported": True,
            "clear_tool_uses_20250919": {"supported": True},
            "clear_thinking_20251015": {"supported": True},
            "compact_20260112": {"supported": True},
        },
        "effort": {
            "supported": True,
            "low": {"supported": True},
            "medium": {"supported": True},
            "high": {"supported": True},
            "xhigh": {"supported": True},
            "max": {"supported": True},
        },
        "image_input": {"supported": True},
        "pdf_input": {"supported": True},
        "server_tools": {
            "supported": True,
            "code_execution": {"supported": True},
            "web_search": {"supported": True},
        },
        "structured_outputs": {"supported": True},
        "thinking": {
            "supported": True,
            "types": {
                "enabled": {"supported": False},
                "adaptive": {"supported": True},
                "disabled": {"supported": True},
            },
        },
    },
    "lifecycle": "active",
    "deprecated_at": None,
    "retires_at": None,
}


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    cw.forget_learned_windows()
    model_output_limits.forget_learned()
    model_capabilities.forget_capabilities()
    yield
    cw.forget_learned_windows()
    model_output_limits.forget_learned()
    model_capabilities.forget_capabilities()


def _answering(monkeypatch: pytest.MonkeyPatch, status: int, body: Any) -> list[httpx.Request]:
    seen: list[httpx.Request] = []
    real = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    def stub(**_kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "Client", stub)
    return seen


def _settings(**anthropic: Any) -> Settings:
    return Settings(
        _env_file=None,
        llm={
            "provider": "anthropic",
            "anthropic": {
                "api_key": "test-anthropic-key",
                "expert_model": MODEL,
                "judge_model": MODEL,
                **anthropic,
            },
        },
    )


class TestTheDescription:
    def test_the_window_is_read_and_its_source_said(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _answering(monkeypatch, 200, DESCRIPTION)
        fact = cw.window_for_settings(_settings(), ["static"])
        assert (fact.tokens, fact.source) == (1_000_000, cw.PROBED)
        assert fact.detail == "the Anthropic Models API reported 1,000,000 tokens"
        assert [str(r.url) for r in seen] == [f"https://api.anthropic.com/v1/models/{MODEL}"]

    def test_the_output_cap_is_the_model_s_declared_maximum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _answering(monkeypatch, 200, DESCRIPTION)
        settings = _settings()
        cw.window_for_settings(settings, ["static"])
        assert model_output_limits.declared_output(MODEL) == (128_000, "the Anthropic Models API")
        cap = cw.output_cap_for(settings, "expert_max_tokens", "static")
        assert cap.tokens == 128_000
        assert "declared maximum output of 128000" in cap.sentence

    def test_the_effort_levels_are_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _answering(monkeypatch, 200, DESCRIPTION)
        cw.window_for_settings(_settings(), ["static"])
        assert model_capabilities.takes_effort(MODEL, "max") is True
        assert model_capabilities.takes_effort("another-model", "max") is None

    def test_an_effort_the_model_does_not_take_is_refused_before_the_job(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        narrower = {
            **DESCRIPTION,
            "capabilities": {
                **DESCRIPTION["capabilities"],
                "effort": {**DESCRIPTION["capabilities"]["effort"], "max": {"supported": False}},
            },
        }
        _answering(monkeypatch, 200, narrower)
        settings = _settings(effort="max")
        cw.window_for_settings(settings, ["static"])
        with pytest.raises(LLMError, match="does not take"):
            AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=1024)


class TestWhenItCannotBeAsked:
    def test_a_refused_key_falls_back_to_the_vendored_row_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _answering(monkeypatch, 401, {"type": "error"})
        settings = _settings()
        fact = cw.window_for_settings(settings, ["static"])
        assert (fact.tokens, fact.source) == (1_000_000, cw.TABLE)
        assert "'claude-haiku-5-5' row" in fact.detail
        tokens, where = model_output_limits.declared_output(MODEL)
        assert tokens == 128_000
        assert "platform.claude.com/docs/en/models/haiku-5-5/overview" in where

    def test_no_key_asks_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _answering(monkeypatch, 200, DESCRIPTION)
        settings = Settings(
            _env_file=None,
            llm={"provider": "anthropic", "anthropic": {"expert_model": MODEL}},
        )
        cw.window_for_settings(settings, ["static"])
        assert seen == []
