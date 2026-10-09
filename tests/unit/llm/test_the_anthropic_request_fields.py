"""Which fields an Anthropic request carries, and from what fact.

* The sampling list is data: the vendored table's ``fixed_sampling`` rows,
  each with the page that documents the 400 (the Thinking page's "Sampling
  parameters": Claude Fable 5.1, Mythos 5.1, Fable 5, Mythos 5, Mythos Preview,
  Opus 5.5, Opus 5, Opus 4.8, Opus 4.7, Sonnet 5.5, Sonnet 5 and Haiku 5.5).
* Streaming is the Anthropic SDK's own rule for a long request.
* The cache marker is the top-level automatic one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.core.paths import resolve_data
from maljan.llm.anthropic_provider import (
    AnthropicProvider,
    cache_control,
    fixed_sampling_source,
    needs_streaming,
)
from maljan.llm.context_window import TABLE_PATH

from .anthropic_wire import Wire, install, message

DOCUMENTED = [
    "claude-fable-5-1",
    "claude-mythos-5-1",
    "claude-fable-5",
    "claude-mythos-5",
    "claude-mythos-preview",
    "claude-opus-5-5",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-sonnet-5-5",
    "claude-sonnet-5",
    "claude-haiku-5-5",
]
NOT_LISTED = [
    "claude-sonnet-4-20250514",
    "claude-haiku-4-5",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
]


class TestTheSamplingRows:
    def test_every_row_names_its_page(self) -> None:
        raw = json.loads(resolve_data(TABLE_PATH).read_text(encoding="utf-8"))
        rows = {k: v for k, v in raw["fixed_sampling"].items() if not k.startswith("_")}
        assert rows
        for key, row in rows.items():
            assert row["source"].startswith("https://platform.claude.com/docs/"), key

    @pytest.mark.parametrize("model", DOCUMENTED)
    def test_each_documented_model_is_covered(self, model: str) -> None:
        assert fixed_sampling_source(model)

    @pytest.mark.parametrize("model", NOT_LISTED)
    def test_a_model_not_documented_so_is_not(self, model: str) -> None:
        assert fixed_sampling_source(model) == ""


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )


def _first_body(monkeypatch: pytest.MonkeyPatch, model: str, temperature: float) -> dict[str, Any]:
    wire = Wire(
        lambda _b: message(
            [{"type": "text", "text": "ok"}],
            stop="end_turn",
            usage={"input_tokens": 1, "output_tokens": 1},
        )
    )
    install(monkeypatch, wire)
    llm = AnthropicProvider(_settings()).build_model(model, temperature, max_tokens=1024)
    llm.invoke([HumanMessage(content="hi")])
    return wire.bodies[0]


class TestTheBody:
    def test_a_documented_model_is_sent_no_temperature(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = _first_body(monkeypatch, "claude-haiku-5-5", 0.0)
        assert "temperature" not in body

    def test_any_other_model_keeps_the_temperature_it_was_built_with(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        body = _first_body(monkeypatch, "claude-sonnet-4-20250514", 0.1)
        assert body["temperature"] == 0.1

    def test_a_single_shot_call_asks_for_no_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A write is 1.25 times an input token and pays off only on a read."""
        body = _first_body(monkeypatch, "claude-haiku-5-5", 0.1)
        assert "cache_control" not in json.dumps(body)
        assert cache_control("1h") == {"type": "ephemeral", "ttl": "1h"}


class TestStreaming:
    def test_the_sdk_s_own_bound(self) -> None:
        assert not needs_streaming("claude-haiku-5-5", 21_333)
        assert needs_streaming("claude-haiku-5-5", 21_334)
        assert needs_streaming("claude-haiku-5-5", 128_000)

    def test_no_cap_streams_nothing(self) -> None:
        assert not needs_streaming("claude-haiku-5-5", None)
        assert not needs_streaming("claude-haiku-5-5", 0)
