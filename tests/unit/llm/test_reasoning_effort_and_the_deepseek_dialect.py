"""A hosted reasoning model used as configured, capped where it reads the cap, and counted.

Three things a DeepSeek run showed the OpenAI provider did not do:

* no setting sent a reasoning effort, so the endpoint's default was all a run
  could get (``llm.openai.reasoning_effort``, sent as written);
* the output cap went out only as ``max_completion_tokens``, which DeepSeek
  ignores (measured: a cap of 5 came back as 88 and 138 tokens), and OpenAI's
  own API refuses the ``max_tokens`` DeepSeek reads beside it for its reasoning
  models — so DeepSeek is a dialect of its own (``compat: deepseek``);
* the cache split and the reasoning part of a call were dropped, although the
  answer carried both.

Every request here goes through a stand-in transport: the body checked is the
body the SDK would have sent, and no request leaves the process.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.core.token_ledger import TokenLedger, record_response_usage, turn_usage
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only

HOSTED = "https://api.deepseek.com"
LOCAL = "http://127.0.0.1:8080/v1"

# The usage block DeepSeek returns, in its own field names.
DEEPSEEK_USAGE = {
    "prompt_tokens": 3884,
    "completion_tokens": 138,
    "total_tokens": 4022,
    "prompt_cache_hit_tokens": 3712,
    "prompt_cache_miss_tokens": 172,
    "prompt_tokens_details": {"cached_tokens": 3712},
    "completion_tokens_details": {"reasoning_tokens": 101},
}


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _settings(base_url: str | None, **openai: Any) -> Settings:
    return Settings(
        _env_file=None, llm={"openai": {"api_key": "sk-test", "base_url": base_url, **openai}}
    )


class _Wire:
    """A transport that records each request body and answers like a chat completion."""

    def __init__(self, usage: dict[str, Any] | None = None) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.usage = usage if usage is not None else {"prompt_tokens": 5, "completion_tokens": 1}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
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
                "usage": self.usage,
            },
        )


def _ask(settings: Settings, wire: _Wire, *, max_tokens: int | None = 5) -> Any:
    kwargs: dict[str, Any] = {"http_client": httpx.Client(transport=httpx.MockTransport(wire))}
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens
    model = OpenAIProvider(settings).build_model("deepseek-flash", 0.0, **kwargs)
    return model.invoke([HumanMessage(content="hi")])


class TestTheReasoningEffort:
    def test_nothing_is_sent_when_it_is_not_set(self) -> None:
        wire = _Wire()
        _ask(_settings(HOSTED), wire)
        assert "reasoning_effort" not in wire.bodies[0]

    def test_it_ships_empty(self) -> None:
        assert Settings(_env_file=None).llm.openai.reasoning_effort == ""

    @pytest.mark.parametrize("base_url", [HOSTED, LOCAL, None])
    @pytest.mark.parametrize("compat", ["auto", "standard", "llama_cpp", "deepseek"])
    def test_it_is_sent_as_written_at_the_top_of_the_body(
        self, base_url: str | None, compat: str
    ) -> None:
        wire = _Wire()
        _ask(_settings(base_url, reasoning_effort="max", compat=compat), wire)
        assert wire.bodies[0]["reasoning_effort"] == "max"
        assert "reasoning" not in wire.bodies[0]

    def test_a_blank_value_is_not_sent(self) -> None:
        wire = _Wire()
        _ask(_settings(HOSTED, reasoning_effort="   "), wire)
        assert "reasoning_effort" not in wire.bodies[0]

    def test_it_is_in_the_catalog_without_a_default(self) -> None:
        from maljan.core.settings_catalog import core_catalog

        entry = next(e for e in core_catalog() if e.path == "llm.openai.reasoning_effort")
        assert entry.type == "str"
        assert entry.default == ""
        assert entry.title != entry.path and entry.description
        assert entry.probe == "llm"


class TestTheCapReachesDeepSeek:
    def test_the_deepseek_dialect_sends_max_tokens(self) -> None:
        wire = _Wire()
        _ask(_settings(HOSTED, compat="deepseek"), wire)
        body = wire.bodies[0]
        assert body["max_tokens"] == 5
        # None of the llama.cpp extras reach a hosted API.
        for key in ("n_predict", "repeat_penalty", "repetition_penalty", "chat_template_kwargs"):
            assert key not in body
        assert "thinking" not in body

    def test_it_sends_deepseek_s_own_thinking_switch(self) -> None:
        wire = _Wire()
        _ask(_settings(HOSTED, compat="deepseek", disable_thinking=True), wire)
        assert wire.bodies[0]["thinking"] == {"type": "disabled"}
        assert "chat_template_kwargs" not in wire.bodies[0]

    def test_no_cap_sends_no_max_tokens(self) -> None:
        wire = _Wire()
        _ask(_settings(HOSTED, compat="deepseek"), wire, max_tokens=None)
        assert "max_tokens" not in wire.bodies[0]

    @pytest.mark.parametrize("compat", ["auto", "standard"])
    def test_a_hosted_api_under_the_other_dialects_gets_max_completion_tokens_alone(
        self, compat: str
    ) -> None:
        """OpenAI's own API refuses ``max_tokens`` beside it for its reasoning models."""
        wire = _Wire()
        _ask(_settings(HOSTED, compat=compat), wire)
        assert wire.bodies[0]["max_completion_tokens"] == 5
        assert "max_tokens" not in wire.bodies[0]

    def test_api_openai_com_is_left_alone(self) -> None:
        wire = _Wire()
        _ask(_settings(None), wire)
        assert wire.bodies[0]["max_completion_tokens"] == 5
        assert "max_tokens" not in wire.bodies[0]

    def test_the_settings_probe_asks_with_the_same_fields(self) -> None:
        from app.services.settings_probes import _completion_request

        _url, _headers, body = _completion_request(
            "openai",
            HOSTED,
            "deepseek-flash",
            "k",
            disable_thinking=True,
            compat="deepseek",
            reasoning_effort="max",
        )
        assert body["thinking"] == {"type": "disabled"}
        assert body["reasoning_effort"] == "max"
        assert "chat_template_kwargs" not in body
        _url, _headers, plain = _completion_request("openai", HOSTED, "m", "k")
        assert "reasoning_effort" not in plain and "thinking" not in plain


class TestTheUsageParts:
    def test_the_cache_split_and_the_reasoning_are_recorded(self) -> None:
        answer = _ask(_settings(HOSTED, compat="deepseek"), _Wire(DEEPSEEK_USAGE))
        usage = turn_usage(answer)
        assert usage is not None
        assert usage["input_tokens"] == 3884
        assert usage["output_tokens"] == 138
        assert usage["cached_input_tokens"] == 3712
        assert usage["reasoning_tokens"] == 101

    def test_deepseek_s_own_cache_field_is_read_when_it_is_the_only_one(self) -> None:
        only_hits = {
            key: value
            for key, value in DEEPSEEK_USAGE.items()
            if key not in ("prompt_tokens_details", "completion_tokens_details")
        }
        answer = _ask(_settings(HOSTED, compat="deepseek"), _Wire(only_hits))
        usage = turn_usage(answer)
        assert usage is not None
        assert usage["cached_input_tokens"] == 3712
        assert "reasoning_tokens" not in usage

    def test_nothing_is_invented_where_nothing_was_reported(self) -> None:
        answer = _ask(_settings(HOSTED), _Wire({"prompt_tokens": 9, "completion_tokens": 2}))
        usage = turn_usage(answer)
        assert usage == {"input_tokens": 9, "output_tokens": 2}

    def test_the_ledger_and_the_report_sentence_carry_them(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        ledger = TokenLedger()
        answer = _ask(_settings(HOSTED, compat="deepseek"), _Wire(DEEPSEEK_USAGE))
        record_response_usage(ledger, answer, agent="static")
        plain = _ask(_settings(HOSTED), _Wire({"prompt_tokens": 9, "completion_tokens": 2}))
        record_response_usage(ledger, plain, agent="judge")
        snapshot = ledger.snapshot()
        assert snapshot["cached_input_tokens"] == 3712
        assert snapshot["cached_calls"] == 1
        assert snapshot["reasoning_tokens"] == 101
        assert snapshot["reasoning_calls"] == 1
        assert "cached_calls" not in snapshot["agents"]["judge"]
        summary = RunSummaryBuilder(start_time=0.0).set_token_usage(snapshot).build().to_dict()
        tokens = summary["tokens"]
        assert tokens["cached_input_tokens"] == 3712
        assert tokens["reasoning_tokens"] == 101
        assert (
            "3,712 of the input read from the prompt cache (reported for 1 call)"
            in tokens["sentence"]
        )
        assert "101 of the output reasoning (reported for 1 call)" in tokens["sentence"]

    def test_a_run_that_reported_no_part_says_nothing_of_one(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        ledger = TokenLedger()
        plain = _ask(_settings(HOSTED), _Wire({"prompt_tokens": 9, "completion_tokens": 2}))
        record_response_usage(ledger, plain, agent="judge")
        snapshot = ledger.snapshot()
        assert "cached_input_tokens" not in snapshot and "reasoning_tokens" not in snapshot
        tokens = RunSummaryBuilder(start_time=0.0).set_token_usage(snapshot).build().to_dict()
        assert "cached_input_tokens" not in tokens["tokens"]
        assert "cache" not in tokens["tokens"]["sentence"]
