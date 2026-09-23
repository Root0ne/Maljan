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
from maljan.pipeline.events import (
    AGENT_MESSAGE_DELTA,
    MODEL_FALLBACK,
    emit_agent_message_delta,
)


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
    @staticmethod
    def _agent(events: list[tuple[str, dict[str, Any]]], stream: bool = True) -> _Agent:
        settings = Settings()
        settings.events.stream_deltas = stream
        settings.llm.agents = {
            "static": AgentLLMConfig.model_validate(
                {
                    "provider": "openai",
                    "model": "qwen",
                    "fallbacks": [{"provider": "ollama", "model": "gemma"}],
                }
            )
        }
        return _Agent(lambda kind, data: events.append((kind, data)), settings)

    def test_a_turn_carries_its_model_and_what_it_spent(self) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        agent = self._agent(events)
        plain = AIMessage(content="first says", usage_metadata=None)
        agent._publish_deltas({"messages": [plain, _fallback_turn("second says")]}, set())
        assert [kind for kind, _ in events] == [AGENT_MESSAGE_DELTA, AGENT_MESSAGE_DELTA]
        first, second = (data for _, data in events)
        assert first["model"].startswith("openai/qwen")
        assert "tokens" not in first
        assert second["model"] == "ollama/gemma"
        assert second["tokens"] == {"input_tokens": 40, "output_tokens": 4}

    def test_a_turn_that_only_asked_for_tools_still_says_what_it_spent(self) -> None:
        events: list[dict[str, Any]] = []
        emit_agent_message_delta(
            lambda _k, d: events.append(d), stage="a", agent="s", text_delta=""
        )
        emit_agent_message_delta(
            lambda _k, d: events.append(d),
            stage="a",
            agent="s",
            text_delta="",
            model="openai/qwen",
            tokens={"input_tokens": 3, "output_tokens": 1},
        )
        assert len(events) == 1 and events[0]["tokens"] == {"input_tokens": 3, "output_tokens": 1}

    def test_the_switch_is_announced_once_whether_or_not_deltas_stream(self) -> None:
        for stream in (True, False):
            events: list[tuple[str, dict[str, Any]]] = []
            agent = self._agent(events, stream=stream)
            agent._record_usage(_fallback_turn("second says"))
            agent._record_usage(
                AIMessage(content="again", response_metadata={MODEL_KEY: "ollama/gemma"})
            )
            announced = [data for kind, data in events if kind == MODEL_FALLBACK]
            assert len(announced) == 1
            assert announced[0]["model"] == "ollama/gemma"
            assert "the provider timed out" in announced[0]["reason"]

    def test_the_tool_loop_announces_as_it_goes_and_records_without_announcing(self) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        agent = self._agent(events)
        agent._record_usage(_fallback_turn(), announce=False)
        assert [kind for kind, _ in events if kind == MODEL_FALLBACK] == []


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
