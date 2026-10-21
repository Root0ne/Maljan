"""An agent's own ceiling stops that agent's model calls, and no other agent's.

``llm.agents.<key>.max_spend_usd`` bounds what the agent's priced calls cost,
``max_unpriced_tokens`` the tokens its calls of a model with no price use.
Both are kept by the job's spend meter and asked by the models built for the
agent, fallbacks included. Unset, nothing changes.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import ValidationError

from maljan.analysis.run_summary import usage_totals
from maljan.core.config import AgentLLMConfig, Settings
from maljan.core.spend import (
    AGENT_CEILING_RECORD,
    AgentCeilingStop,
    SpendCeilingStop,
    SpendMeter,
)
from maljan.core.token_ledger import TokenLedger
from maljan.llm.agent_ceiling import AgentCeiling, attach_agent_ceiling, carry_agent_ceiling
from maljan.llm.fallback import FallbackChatModel

# One USD per million tokens either way: a call of 10 input and 2 output
# tokens costs 0.000012 USD.
_PRICES = {"priced-model": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 1.0}}


class _Model(BaseChatModel):
    """A chat model that answers with a reported usage, and counts the calls that reached it."""

    model_name: str = "priced-model"
    calls: int = 0
    fails: bool = False

    @property
    def _llm_type(self) -> str:
        return "counted"

    def _next(self) -> ChatResult:
        self.calls += 1
        if self.fails:
            raise ConnectionRefusedError(111, "refused")
        message = AIMessage(
            content="answer",
            usage_metadata={"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        return self._next()

    async def _agenerate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        return self._next()


def _ledger(**ceilings: tuple[float | None, int | None]) -> tuple[TokenLedger, list[dict]]:
    meter = SpendMeter(None, _PRICES, table={})
    for agent, (usd, tokens) in ceilings.items():
        meter.set_agent_ceiling(agent, usd, tokens)
    ledger = TokenLedger(spend=meter)
    feed: list[dict] = []
    ledger.on_call = feed.append
    return ledger, feed


_ASK = [HumanMessage(content="go")]


class TestTheSetting:
    def test_an_entry_sets_no_ceiling_by_default(self) -> None:
        entry = AgentLLMConfig(provider="openai", model="m")
        assert entry.max_spend_usd is None
        assert entry.max_unpriced_tokens is None

    def test_an_entry_takes_both_ceilings(self) -> None:
        entry = AgentLLMConfig(
            provider="openai", model="m", max_spend_usd=1.5, max_unpriced_tokens=50_000
        )
        assert (entry.max_spend_usd, entry.max_unpriced_tokens) == (1.5, 50_000)

    @pytest.mark.parametrize("field", ["max_spend_usd", "max_unpriced_tokens"])
    def test_a_ceiling_of_zero_is_refused(self, field: str) -> None:
        with pytest.raises(ValidationError):
            AgentLLMConfig(provider="openai", model="m", **{field: 0})

    def test_the_meter_reads_each_entry_s_ceiling(self) -> None:
        settings = Settings()
        settings.llm.agents = {
            "static": AgentLLMConfig(provider="openai", model="m", max_spend_usd=2.0),
            "dynamic": AgentLLMConfig(provider="openai", model="m"),
        }
        meter = SpendMeter.from_settings(settings)
        assert meter.agent_ceiling("static") == (2.0, None)
        assert meter.agent_ceiling("dynamic") is None

    def test_with_no_ceiling_the_spend_block_is_as_it_was(self) -> None:
        settings = Settings()
        settings.llm.agents = {"static": AgentLLMConfig(provider="openai", model="m")}
        assert SpendMeter.from_settings(settings).snapshot() is None


class TestTheMeter:
    def test_an_agent_under_its_ceiling_is_not_refused(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 1.0)
        meter.note_agent_call("static", {"input_tokens": 10, "output_tokens": 2}, "priced-model")
        assert meter.agent_refusal("static") == ("", False)

    def test_an_agent_at_its_spend_ceiling_is_refused_and_said_once(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 0.00001)
        meter.note_agent_call("static", {"input_tokens": 10, "output_tokens": 2}, "priced-model")
        said, first = meter.agent_refusal("static")
        assert first and "agent static" in said and "of 0.00001 USD" in said
        assert "llm.agents.static.max_spend_usd" in said
        assert meter.agent_refusal("static") == (said, False)
        # The job's spend is not exhausted, and another agent goes on.
        assert not meter.exhausted()
        assert meter.agent_refusal("dynamic") == ("", False)

    def test_unpriced_calls_count_their_tokens(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 5.0, 20)
        usage = {"input_tokens": 10, "output_tokens": 2}
        meter.note_agent_call("static", usage, "local-model")
        assert meter.agent_refusal("static")[0] == ""
        meter.note_agent_call("static", usage, "local-model")
        said, _ = meter.agent_refusal("static")
        assert "unpriced-token ceiling of 20 tokens" in said
        assert "llm.agents.static.max_unpriced_tokens" in said

    def test_a_priced_call_does_not_count_toward_the_token_ceiling(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", None, 5)
        meter.note_agent_call("static", {"input_tokens": 10, "output_tokens": 2}, "priced-model")
        assert meter.agent_refusal("static")[0] == ""

    def test_the_run_summary_names_the_agent_and_its_ceiling(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 0.00001)
        meter.note_agent_call("static", {"input_tokens": 10, "output_tokens": 2}, "priced-model")
        meter.agent_refusal("static")
        (reason,) = meter.agent_reasons()
        assert reason.startswith("The agent static reached its spend ceiling of 0.00001 USD")
        assert "no other agent was affected" in reason
        block = meter.snapshot()
        assert block is not None and block["agent_ceilings"]["static"]["stopped"] is True

    def test_the_job_s_spend_block_carries_the_agents_beside_it(self) -> None:
        meter = SpendMeter(10.0, _PRICES, table={})
        meter.set_agent_ceiling("judge", 1.0)
        block = meter.snapshot()
        assert block is not None and block["ceiling_usd"] == 10.0
        assert block["agent_ceilings"]["judge"]["max_spend_usd"] == 1.0


class TestTheModels:
    def test_a_model_of_an_agent_with_no_ceiling_is_left_as_built(self) -> None:
        ledger, _ = _ledger()
        model = _Model()
        before = list(model.callbacks or [])
        attach_agent_ceiling(model, ledger, "static")
        assert list(model.callbacks or []) == before

    def test_the_call_after_the_ceiling_is_not_sent(self) -> None:
        ledger, feed = _ledger(static=(0.00001, None))
        model = attach_agent_ceiling(_Model(), ledger, "static")
        model.invoke(_ASK)
        with pytest.raises(AgentCeilingStop) as stop:
            model.invoke(_ASK)
        assert isinstance(stop.value, SpendCeilingStop)
        assert stop.value.agent == "static"
        assert model.calls == 1
        # Said once on the call feed, by agent and ceiling.
        records = [row for row in feed if row.get("call") == AGENT_CEILING_RECORD]
        assert len(records) == 1 and records[0]["agent"] == "static"
        assert "max_spend_usd" in records[0]["reason"]
        with pytest.raises(AgentCeilingStop):
            asyncio.run(model.ainvoke(_ASK))
        assert len([row for row in feed if row.get("call") == AGENT_CEILING_RECORD]) == 1

    def test_a_fallback_s_calls_count_toward_the_same_agent(self) -> None:
        ledger, _ = _ledger(static=(0.00002, None))
        first, second = _Model(fails=True), _Model(model_name="priced-model")
        chain = FallbackChatModel(
            models=[first, second], labels=["openai/a", "openai/b"], agent="static"
        )
        attach_agent_ceiling(chain, ledger, "static")
        assert all(
            any(isinstance(cb, AgentCeiling) for cb in (m.callbacks or [])) for m in chain.models
        )
        chain.invoke(_ASK)
        chain.invoke(_ASK)
        assert second.calls == 2
        with pytest.raises(AgentCeilingStop):
            chain.invoke(_ASK)
        assert second.calls == 2

    def test_another_agent_s_model_goes_on(self) -> None:
        ledger, _ = _ledger(static=(0.00001, None), dynamic=(1.0, None))
        static = attach_agent_ceiling(_Model(), ledger, "static")
        dynamic = attach_agent_ceiling(_Model(), ledger, "dynamic")
        static.invoke(_ASK)
        with pytest.raises(AgentCeilingStop):
            static.invoke(_ASK)
        dynamic.invoke(_ASK)
        dynamic.invoke(_ASK)
        assert dynamic.calls == 2

    def test_a_rebuilt_model_carries_the_ceiling(self) -> None:
        ledger, _ = _ledger(static=(1.0, None))
        source = attach_agent_ceiling(_Model(), ledger, "static")
        target = carry_agent_ceiling(source, _Model())
        assert any(isinstance(cb, AgentCeiling) for cb in (target.callbacks or []))

    def test_the_feed_record_is_not_counted_as_a_call(self) -> None:
        record = {
            "agent": "static",
            "model": "priced-model",
            "call": AGENT_CEILING_RECORD,
            "reported": False,
            "reason": "agent static reached its spend ceiling",
        }
        totals = usage_totals([record], lambda: SpendMeter(None, _PRICES, table={}))
        assert totals["calls"] == 0


class TestWhatCounts:
    def test_a_billed_failed_attempt_counts_toward_the_agent(self) -> None:
        from maljan.llm.transient import attach_retry_recorder, recorder_of

        ledger, _ = _ledger(mediator=(0.00001, None))
        model = _Model()
        # The mediator's calls are filed under the judge; its ceiling is its own.
        attach_retry_recorder(model, ledger, "judge")
        attach_agent_ceiling(model, ledger, "mediator")
        recorder = recorder_of(model)
        assert recorder is not None
        recorder._charge({"input_tokens": 10, "output_tokens": 2}, None)
        assert ledger.spend.agent_refusal("mediator")[0]
        assert ledger.spend.agent_refusal("judge") == ("", False)

    def test_an_estimate_counts_and_is_said(self) -> None:
        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 0.00001)
        meter.note_agent_call(
            "static", None, "priced-model", estimated={"input_tokens": 10, "output_tokens": 2}
        )
        said, _ = meter.agent_refusal("static")
        assert "1 call(s) reported no usage and are counted at a stated estimate" in said

    def test_an_answer_ended_while_it_streamed_counts_its_estimate(self) -> None:
        from langchain_core.outputs import LLMResult

        from maljan.llm.stream_watch import ESTIMATED_USAGE_KEY

        ledger, _ = _ledger(static=(0.00001, None))
        ceiling = AgentCeiling(ledger, "static", "priced-model")
        message = AIMessage(
            content="cut",
            response_metadata={ESTIMATED_USAGE_KEY: {"input_tokens": 10, "output_tokens": 2}},
        )
        ceiling.on_llm_end(LLMResult(generations=[[ChatGeneration(message=message)]]), run_id=None)
        assert "reported no usage" in ledger.spend.agent_refusal("static")[0]


class TestACeilingOnlyEntry:
    def test_it_is_accepted_and_chooses_no_model(self) -> None:
        entry = AgentLLMConfig(max_spend_usd=1.0)
        assert not entry.names_a_model()
        assert entry.chain() == []

    def test_it_needs_a_ceiling(self) -> None:
        with pytest.raises(ValidationError):
            AgentLLMConfig()

    def test_a_model_setting_beside_it_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            AgentLLMConfig(max_spend_usd=1.0, temperature=0.3)

    def test_the_agent_s_model_is_built_as_with_no_entry(self) -> None:
        from maljan.llm.registry import LLMProviderRegistry

        plain = Settings(_env_file=None, llm={"provider": "ollama"})
        bounded = Settings(
            _env_file=None,
            llm={"provider": "ollama", "agents": {"static": {"max_spend_usd": 1.0}}},
        )
        one = LLMProviderRegistry(plain).build_model_for_agent("static")
        two = LLMProviderRegistry(bounded).build_model_for_agent("static")
        assert type(one) is type(two)
        assert one.model_dump() == two.model_dump()
        assert SpendMeter.from_settings(bounded).agent_ceiling("static") == (1.0, None)


class TestTheProbeGate:
    def test_a_new_ceiling_only_entry_moves_nothing(self) -> None:
        from app.services.model_probes import _points_somewhere_new

        assert not _points_somewhere_new({"max_spend_usd": 1.0}, None)

    def test_a_model_entry_turned_ceiling_only_moves_the_agent(self) -> None:
        from app.services.model_probes import _points_somewhere_new

        was = {"provider": "openai", "model": "m"}
        assert _points_somewhere_new({"provider": "", "model": "", "max_spend_usd": 1.0}, was)

    def test_a_new_model_entry_still_moves(self) -> None:
        from app.services.model_probes import _points_somewhere_new

        assert _points_somewhere_new({"provider": "openai", "model": "m"}, None)

    def test_a_half_blank_entry_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            AgentLLMConfig(provider="openai", model="")


class TestTheDump:
    def test_an_entry_with_no_ceiling_dumps_as_before(self) -> None:
        entry = AgentLLMConfig(provider="openai", model="m")
        assert set(entry.model_dump()) == {
            "provider",
            "model",
            "temperature",
            "base_url",
            "effort",
            "fallbacks",
        }
        settings = Settings(
            _env_file=None, llm={"agents": {"static": {"provider": "openai", "model": "m"}}}
        )
        dumped = settings.model_dump(mode="json")["llm"]["agents"]["static"]
        assert "max_spend_usd" not in dumped and "max_unpriced_tokens" not in dumped

    def test_a_ceiling_that_is_set_is_dumped(self) -> None:
        entry = AgentLLMConfig(provider="openai", model="m", max_unpriced_tokens=10)
        assert entry.model_dump()["max_unpriced_tokens"] == 10
        assert "max_spend_usd" not in entry.model_dump()


class TestTheSummary:
    def test_each_agent_ceiling_is_a_line(self) -> None:
        from maljan.analysis.run_summary import spend_lines

        meter = SpendMeter(None, _PRICES, table={})
        meter.set_agent_ceiling("static", 0.01)
        meter.set_agent_ceiling("judge", None, 5_000)
        assert spend_lines(meter.snapshot()) == [
            "Agent judge's own ceiling of 5,000 unpriced tokens: 0 USD and 0 unpriced tokens used",
            "Agent static's own ceiling of 0.01 USD: 0 USD and 0 unpriced tokens used",
        ]


class TestTheLog:
    def test_langchain_does_not_log_each_refusal(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        ledger, _ = _ledger(static=(0.00001, None))
        model = attach_agent_ceiling(_Model(), ledger, "static")
        model.invoke(_ASK)
        with caplog.at_level(logging.WARNING, logger="langchain_core.callbacks.manager"):
            with pytest.raises(AgentCeilingStop):
                model.invoke(_ASK)
        assert not [r for r in caplog.records if r.name == "langchain_core.callbacks.manager"]
