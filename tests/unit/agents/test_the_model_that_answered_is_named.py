"""Every turn says which model gave it: on the ledger entry and in the conversation."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BudgetMeter
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core.config import AgentLLMConfig, Settings
from maljan.llm.fallback import FALLBACK_KEY, MODEL_KEY
from maljan.pipeline.events import AGENT_MESSAGE_DELTA, emit_agent_message_delta


def _fallback_turn(text: str = "") -> AIMessage:
    return AIMessage(
        content=text,
        response_metadata={
            MODEL_KEY: "ollama/gemma",
            FALLBACK_KEY: "openai/qwen: the provider timed out; answered by ollama/gemma",
        },
        usage_metadata={"input_tokens": 40, "output_tokens": 4, "total_tokens": 44},
    )


class TestTheLedgerEntry:
    def test_a_call_is_filed_under_the_agent_first_model_until_a_turn_names_another(self) -> None:
        recorder = EvidenceRecorder("static", model="openai/qwen")
        first = recorder.record(tool="pe_info", args={}, server="analysis", output="{}")
        recorder.note_turn(_fallback_turn())
        second = recorder.record(tool="strings", args={}, server="analysis", output="{}")
        assert (first.model, second.model) == ("openai/qwen", "ollama/gemma")

    def test_a_turn_that_names_no_model_is_the_first_model_again(self) -> None:
        recorder = EvidenceRecorder("static", model="openai/qwen")
        recorder.note_turn(_fallback_turn())
        recorder.note_turn(AIMessage(content=""))
        entry = recorder.record(tool="pe_info", args={}, server=None, output="{}")
        assert entry.model == "openai/qwen"

    def test_an_agent_outside_a_job_names_nothing(self) -> None:
        entry = EvidenceRecorder("static").record(tool="t", args={}, server=None, output="")
        assert entry.model is None


class _Agent(BudgetMeter):
    def __init__(self, sink: Any, settings: Settings) -> None:
        self.name = "static"
        self.pipeline_stage = "analysis"
        self.logger = logging.getLogger("test")
        self._container = SimpleNamespace(event_sink=sink, config=settings)


class TestTheConversationEvent:
    def test_a_turn_carries_its_model_its_fallback_and_what_it_spent(self) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        settings = Settings()
        settings.llm.agents = {
            "static": AgentLLMConfig.model_validate(
                {
                    "provider": "openai",
                    "model": "qwen",
                    "fallbacks": [{"provider": "ollama", "model": "gemma"}],
                }
            )
        }
        agent = _Agent(lambda kind, data: events.append((kind, data)), settings)
        plain = AIMessage(content="first says", usage_metadata=None)
        agent._publish_deltas({"messages": [plain, _fallback_turn()]}, set())
        assert [kind for kind, _ in events] == [AGENT_MESSAGE_DELTA, AGENT_MESSAGE_DELTA]
        first, second = (data for _, data in events)
        assert first["model"].startswith("openai/qwen")
        assert "fallback" not in first and "tokens" not in first
        assert second["model"] == "ollama/gemma"
        assert "the provider timed out" in second["fallback"]
        assert second["tokens"] == {"input_tokens": 40, "output_tokens": 4}

    def test_a_silent_turn_is_announced_only_when_a_fallback_gave_it(self) -> None:
        events: list[dict[str, Any]] = []
        emit_agent_message_delta(
            lambda _k, d: events.append(d), stage="a", agent="s", text_delta=""
        )
        emit_agent_message_delta(
            lambda _k, d: events.append(d),
            stage="a",
            agent="s",
            text_delta="",
            model="ollama/gemma",
            fallback="openai/qwen: timed out",
        )
        assert len(events) == 1 and events[0]["fallback"] == "openai/qwen: timed out"


def test_the_report_says_what_the_run_spent_and_which_turns_fell_back() -> None:
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    text = MarkdownRenderer()._section_run_summary(
        {
            "tokens": {
                "llm_calls": 4,
                "unreported_calls": 1,
                "input_tokens": 900,
                "output_tokens": 30,
            },
            "models": {
                "static": {
                    "turns": {"ollama/gemma": 1},
                    "fallbacks": [{"model": "ollama/gemma", "reason": "openai/qwen: timed out"}],
                }
            },
            "server_rests": [
                {"server": "analysis", "failures": 3, "cooldown_s": 60, "reason": "timed out"}
            ],
        }
    )
    assert "- Tokens: 900 in and 30 out over 4 model calls; not reported for 1 of them." in text
    assert "- Model fallback (static): openai/qwen: timed out" in text
    assert "Tool server analysis was rested for 60 s" in text
