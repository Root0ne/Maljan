"""A reasoning effort per agent: the entry's own value, else the provider's global one.

``llm.agents.<key>.effort`` (and each fallback's) is sent where the global
``llm.anthropic.effort`` / ``llm.openai.reasoning_effort`` is sent today. Left
unset, every request body is the one the provider built before the field
existed. Every request goes through a stand-in transport: no call leaves the
process.
"""

from __future__ import annotations

import json
import logging
from typing import Any, get_args

import httpx
import pytest
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from maljan.core.config import (
    ANTHROPIC_EFFORT_LEVELS,
    AgentLLMConfig,
    AnthropicConfig,
    ModelChoice,
    Settings,
)
from maljan.core.exceptions import LLMError
from maljan.llm import model_capabilities
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only
from maljan.llm.registry import LLMProviderRegistry

from .anthropic_wire import MODEL, Wire, install, message
from .streamed_wire import reply

HOSTED = "https://api.deepseek.com"


@pytest.fixture(autouse=True)
def _clean() -> Any:
    forget_standard_only()
    model_capabilities.forget_capabilities()
    yield
    forget_standard_only()
    model_capabilities.forget_capabilities()


# ---------------------------------------------------------------- the setting


class TestTheField:
    def test_it_is_unset_by_default(self) -> None:
        assert ModelChoice(provider="openai", model="m").effort is None
        assert AgentLLMConfig(provider="anthropic", model="m").effort is None

    def test_a_blank_value_inherits(self) -> None:
        assert ModelChoice(provider="openai", model="m", effort="  ").effort is None

    def test_each_fallback_carries_its_own(self) -> None:
        entry = AgentLLMConfig(
            provider="anthropic",
            model="a",
            effort="low",
            fallbacks=[{"provider": "openai", "model": "b", "effort": "high"}],
        )
        assert [c.effort for c in entry.chain()] == ["low", "high"]

    @pytest.mark.parametrize("provider", ["ollama", "gemini"])
    def test_a_provider_with_no_effort_refuses_one(self, provider: str) -> None:
        with pytest.raises(ValidationError, match="effort is only supported"):
            ModelChoice(provider=provider, model="m", effort="high")

    def test_a_fallback_on_such_a_provider_refuses_one_too(self) -> None:
        with pytest.raises(ValidationError, match="effort is only supported"):
            AgentLLMConfig(
                provider="openai",
                model="a",
                fallbacks=[{"provider": "ollama", "model": "b", "effort": "low"}],
            )

    def test_an_anthropic_level_is_one_the_api_names(self) -> None:
        with pytest.raises(ValidationError, match="not one of"):
            ModelChoice(provider="anthropic", model="m", effort="minimal")
        for level in ANTHROPIC_EFFORT_LEVELS:
            assert ModelChoice(provider="anthropic", model="m", effort=level).effort == level

    def test_an_openai_compatible_value_is_kept_as_written(self) -> None:
        assert ModelChoice(provider="openai", model="m", effort="minimal").effort == "minimal"

    def test_the_anthropic_levels_are_the_global_setting_s_levels(self) -> None:
        literal = get_args(AnthropicConfig.model_fields["effort"].annotation)
        assert tuple(v for v in literal if v) == ANTHROPIC_EFFORT_LEVELS

    def test_it_reaches_the_settings_model_through_llm_agents(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={"agents": {"reporter": {"provider": "anthropic", "model": "m", "effort": "high"}}},
        )
        assert settings.llm.agents["reporter"].effort == "high"


# ------------------------------------------------------------------ anthropic


def _anthropic_settings(agents: dict[str, Any] | None = None, **anthropic: Any) -> Settings:
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
            "agents": agents or {},
        },
    )


def _anthropic_body(monkeypatch: pytest.MonkeyPatch, llm_builder: Any) -> dict[str, Any]:
    wire = Wire(
        lambda _body: message(
            [{"type": "text", "text": "ok"}],
            stop="end_turn",
            usage={"input_tokens": 5, "output_tokens": 1},
        )
    )
    install(monkeypatch, wire)
    llm = llm_builder()
    llm.invoke([SystemMessage(content="You judge."), HumanMessage(content="Rule.")])
    return wire.bodies[0]


class TestAnthropic:
    def test_the_entry_s_effort_wins_over_the_global_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _anthropic_settings(
            {"reporter": {"provider": "anthropic", "model": MODEL, "effort": "low"}},
            effort="max",
        )
        body = _anthropic_body(
            monkeypatch,
            lambda: LLMProviderRegistry(settings).build_model_for_agent(
                "reporter", fallback_role="judge", max_tokens=8192
            ),
        )
        assert body["output_config"] == {"effort": "low"}

    def test_an_entry_without_one_sends_the_body_it_sent_before(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _anthropic_settings(
            {"reporter": {"provider": "anthropic", "model": MODEL}}, effort="max"
        )
        through_entry = _anthropic_body(
            monkeypatch,
            lambda: LLMProviderRegistry(settings).build_model_for_agent(
                "reporter", fallback_role="judge", max_tokens=8192
            ),
        )
        direct = _anthropic_body(
            monkeypatch,
            lambda: AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=8192),
        )
        assert json.dumps(through_entry, sort_keys=True) == json.dumps(direct, sort_keys=True)
        assert through_entry["output_config"] == {"effort": "max"}

    def test_no_effort_anywhere_sends_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _anthropic_settings({"judge": {"provider": "anthropic", "model": MODEL}})
        body = _anthropic_body(
            monkeypatch,
            lambda: LLMProviderRegistry(settings).build_model_for_agent(
                "judge", fallback_role="judge", max_tokens=8192
            ),
        )
        assert "output_config" not in body

    def test_an_entry_effort_with_no_global_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _anthropic_settings(
            {"static": {"provider": "anthropic", "model": MODEL, "effort": "medium"}}
        )
        body = _anthropic_body(
            monkeypatch,
            lambda: LLMProviderRegistry(settings).build_model_for_agent("static", max_tokens=8192),
        )
        assert body["output_config"] == {"effort": "medium"}

    def test_a_level_the_models_api_refuses_names_the_entry(self) -> None:
        model_capabilities.note_model_description(
            {"capabilities": {"effort": {"supported": True, "max": {"supported": False}}}},
            MODEL,
            "test",
        )
        settings = _anthropic_settings(
            {"reporter": {"provider": "anthropic", "model": MODEL, "effort": "max"}}
        )
        with pytest.raises(LLMError, match=r"llm\.agents\.reporter\.effort is 'max'"):
            LLMProviderRegistry(settings).build_model_for_agent("reporter", fallback_role="judge")

    def test_a_fallback_s_refused_level_names_the_fallback(self) -> None:
        model_capabilities.note_model_description(
            {"capabilities": {"effort": {"supported": True, "max": {"supported": False}}}},
            MODEL,
            "test",
        )
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "openai",
                "openai": {"api_key": "sk-test"},
                "anthropic": {"api_key": "test-anthropic-key"},
                "agents": {
                    "static": {
                        "provider": "openai",
                        "model": "a",
                        "fallbacks": [{"provider": "anthropic", "model": MODEL, "effort": "max"}],
                    }
                },
            },
        )
        with pytest.raises(LLMError, match=r"llm\.agents\.static\.fallbacks\[0\]\.effort is 'max'"):
            LLMProviderRegistry(settings).build_model_for_agent("static")

    def test_an_anthropic_fallback_carries_its_effort_under_an_openai_primary(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "openai",
                "openai": {"api_key": "sk-test", "reasoning_effort": "max"},
                "anthropic": {"api_key": "test-anthropic-key"},
                "agents": {
                    "static": {
                        "provider": "openai",
                        "model": "a",
                        "fallbacks": [{"provider": "anthropic", "model": MODEL, "effort": "low"}],
                    }
                },
            },
        )
        built = LLMProviderRegistry(settings).build_model_for_agent("static")
        first, second = built.models  # type: ignore[attr-defined]
        assert first.reasoning_effort == "max"
        assert second.output_config == {"effort": "low"}

    def test_the_global_refusal_keeps_its_message(self) -> None:
        model_capabilities.note_model_description(
            {"capabilities": {"effort": {"supported": True, "max": {"supported": False}}}},
            MODEL,
            "test",
        )
        with pytest.raises(LLMError, match=r"^llm\.anthropic\.effort is 'max', which the"):
            AnthropicProvider(_anthropic_settings(effort="max")).build_model(MODEL, 0.1)


# --------------------------------------------------------- openai-compatible


class _OpenAIWire:
    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return reply(
            request,
            {
                "id": "c1",
                "object": "chat.completion",
                "created": 0,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 1},
            },
        )


def _openai_settings(agents: dict[str, Any] | None = None, **openai: Any) -> Settings:
    return Settings(
        _env_file=None,
        llm={
            "provider": "openai",
            "openai": {
                "api_key": "sk-test",
                "base_url": HOSTED,
                "compat": "deepseek",
                "expert_model": "deepseek-flash",
                **openai,
            },
            "agents": agents or {},
        },
    )


def _openai_body(builder: Any) -> dict[str, Any]:
    wire = _OpenAIWire()
    client = httpx.Client(transport=httpx.MockTransport(wire))
    builder(client).invoke([HumanMessage(content="hi")])
    return wire.bodies[0]


class TestOpenAICompatible:
    def test_the_entry_s_effort_wins_over_the_global_one(self) -> None:
        settings = _openai_settings(
            {"static": {"provider": "openai", "model": "deepseek-flash", "effort": "high"}},
            reasoning_effort="max",
        )
        body = _openai_body(
            lambda client: LLMProviderRegistry(settings).build_model_for_agent(
                "static", max_tokens=5, http_client=client
            )
        )
        assert body["reasoning_effort"] == "high"

    def test_an_entry_without_one_sends_the_body_it_sent_before(self) -> None:
        settings = _openai_settings(
            {"static": {"provider": "openai", "model": "deepseek-flash"}},
            reasoning_effort="max",
        )
        through_entry = _openai_body(
            lambda client: LLMProviderRegistry(settings).build_model_for_agent(
                "static", max_tokens=5, http_client=client
            )
        )
        direct = _openai_body(
            lambda client: OpenAIProvider(settings).build_model(
                "deepseek-flash", 0.1, max_tokens=5, http_client=client
            )
        )
        assert json.dumps(through_entry, sort_keys=True) == json.dumps(direct, sort_keys=True)
        assert through_entry["reasoning_effort"] == "max"

    def test_no_effort_anywhere_sends_none(self) -> None:
        settings = _openai_settings({"static": {"provider": "openai", "model": "deepseek-flash"}})
        body = _openai_body(
            lambda client: LLMProviderRegistry(settings).build_model_for_agent(
                "static", max_tokens=5, http_client=client
            )
        )
        assert "reasoning_effort" not in body

    def test_a_fallback_sends_its_own(self) -> None:
        settings = _openai_settings(
            {
                "static": {
                    "provider": "openai",
                    "model": "deepseek-flash",
                    "fallbacks": [{"provider": "openai", "model": "deepseek-pro", "effort": "low"}],
                }
            },
            reasoning_effort="max",
        )
        built = LLMProviderRegistry(settings).build_model_for_agent("static", max_tokens=5)
        first, second = built.models  # type: ignore[attr-defined]
        assert first.reasoning_effort == "max"
        assert second.reasoning_effort == "low"


# ------------------------------------------------------------------- the log


class TestTheBuildLine:
    def _lines(self, caplog: pytest.LogCaptureFixture) -> list[str]:
        return [r.getMessage() for r in caplog.records if "Building" in r.getMessage()]

    @pytest.fixture(autouse=True)
    def _capture(self, caplog: pytest.LogCaptureFixture) -> Any:
        from maljan.core.logger import logger

        logger.addHandler(caplog.handler)
        caplog.set_level(logging.DEBUG)
        yield
        logger.removeHandler(caplog.handler)

    def test_a_role_names_the_global_effort(self, caplog: pytest.LogCaptureFixture) -> None:
        LLMProviderRegistry(_anthropic_settings(effort="max")).build_model(role="judge")
        line = self._lines(caplog)[-1]
        assert f"Building anthropic/{MODEL} (role=judge, temp=0.0" in line
        assert "effort=max from llm.anthropic.effort" in line

    def test_a_role_with_no_effort_says_so(self, caplog: pytest.LogCaptureFixture) -> None:
        LLMProviderRegistry(_anthropic_settings()).build_model(role="judge")
        assert "effort=unset, the provider's default" in self._lines(caplog)[-1]

    def test_an_entry_names_itself(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = _anthropic_settings(
            {"reporter": {"provider": "anthropic", "model": MODEL, "effort": "high"}},
            effort="max",
        )
        LLMProviderRegistry(settings).build_model_for_agent("reporter", fallback_role="judge")
        assert "effort=high from llm.agents.reporter.effort" in self._lines(caplog)[-1]

    def test_an_entry_without_one_names_the_global(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = _openai_settings(
            {"static": {"provider": "openai", "model": "deepseek-flash"}},
            reasoning_effort="max",
        )
        LLMProviderRegistry(settings).build_model_for_agent("static")
        assert "effort=max from llm.openai.reasoning_effort" in self._lines(caplog)[-1]

    def test_a_fallback_names_its_own_field(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = _openai_settings(
            {
                "static": {
                    "provider": "openai",
                    "model": "deepseek-flash",
                    "effort": "high",
                    "fallbacks": [
                        {"provider": "openai", "model": "a"},
                        {"provider": "openai", "model": "b", "effort": "low"},
                    ],
                }
            },
            reasoning_effort="max",
        )
        LLMProviderRegistry(settings).build_model_for_agent("static")
        line = {
            m: next(x for x in self._lines(caplog) if f"openai/{m} " in x)
            for m in ("deepseek-flash", "a", "b")
        }
        assert "effort=high from llm.agents.static.effort" in line["deepseek-flash"]
        assert "effort=max from llm.openai.reasoning_effort" in line["a"]
        assert "effort=low from llm.agents.static.fallbacks[1].effort" in line["b"]

    def test_ollama_has_none(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = Settings(_env_file=None, llm={"provider": "ollama"})
        LLMProviderRegistry(settings).build_model(role="expert")
        assert "effort=none for this provider" in self._lines(caplog)[-1]


# -------------------------------------------------------- what the console reads


class TestTheChoices:
    def test_the_catalogue_says_an_entry_may_name_one(self) -> None:
        from maljan.core.settings_catalog import core_catalog

        entry = next(e for e in core_catalog() if e.path == "llm.agents")
        assert "effort" in entry.description
        assert "llm.anthropic.effort" in entry.description
        assert "llm.openai.reasoning_effort" in entry.description

    def test_anthropic_offers_the_settings_levels_until_the_model_is_described(self) -> None:
        from maljan.llm.effort import effort_options

        options = effort_options(_anthropic_settings(effort="max"), "anthropic", MODEL)
        assert options["takes_effort"] is True
        assert options["levels"] == list(ANTHROPIC_EFFORT_LEVELS)
        assert options["levels_source"] == "settings"
        assert options["global_key"] == "core.llm.anthropic.effort"
        assert options["global_value"] == "max"

    def test_a_described_model_offers_the_levels_it_takes(self) -> None:
        from maljan.llm.effort import effort_options

        model_capabilities.note_model_description(
            {
                "capabilities": {
                    "effort": {
                        "supported": True,
                        "low": {"supported": True},
                        "medium": {"supported": True},
                        "high": {"supported": True},
                        "max": {"supported": False},
                    }
                }
            },
            MODEL,
            "test",
        )
        options = effort_options(_anthropic_settings(), "anthropic", MODEL)
        assert options["levels"] == ["low", "medium", "high", "xhigh"]
        assert options["undescribed_levels"] == ["xhigh"]
        assert options["levels_source"] == "models_api"

    def test_a_level_the_description_leaves_out_is_one_the_build_accepts(self) -> None:
        from maljan.llm.effort import effort_options

        model_capabilities.note_model_description(
            {"capabilities": {"effort": {"low": {"supported": True}, "high": {"supported": True}}}},
            MODEL,
            "test",
        )
        options = effort_options(_anthropic_settings(), "anthropic", MODEL)
        assert "medium" in options["levels"] and "medium" in options["undescribed_levels"]
        assert model_capabilities.takes_effort(MODEL, "medium") is None
        AnthropicProvider(_anthropic_settings(effort="medium")).build_model(MODEL, 0.1)

    def test_a_model_the_api_says_takes_none_offers_none(self) -> None:
        from maljan.llm.effort import effort_options

        model_capabilities.note_model_description(
            {"capabilities": {"effort": {"supported": False}}}, MODEL, "test"
        )
        options = effort_options(_anthropic_settings(), "anthropic", MODEL)
        assert options["levels"] == []
        assert options["levels_source"] == "models_api"

    def test_openai_compatible_is_written_as_the_endpoint_names_it(self) -> None:
        from maljan.llm.effort import effort_options

        options = effort_options(_openai_settings(reasoning_effort="max"), "openai", "m")
        assert options["takes_effort"] is True
        assert options["levels"] is None
        assert options["global_key"] == "core.llm.openai.reasoning_effort"
        assert options["global_value"] == "max"

    @pytest.mark.parametrize("provider", ["ollama", "gemini", "unknown"])
    def test_the_others_take_none(self, provider: str) -> None:
        from maljan.llm.effort import effort_options

        options = effort_options(Settings(_env_file=None), provider, "m")
        assert options["takes_effort"] is False
        assert options["levels"] == []
        assert options["global_key"] is None
