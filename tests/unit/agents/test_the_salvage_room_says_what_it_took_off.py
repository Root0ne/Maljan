"""A salvage's room is its window less what goes beside the turns, and its record says so.

Where a model keeps its turns as received, the salvage re-sends the loop's
history with the loop's tools withheld, so the tool definitions go with the
request outside the messages the trim measures; they come off the room. Where
the turns are rebuilt, the request goes without tools and nothing comes off.
Either way the salvage's row on the loop record names the room, how it was
derived, what the trim dropped and how the call ended — the judge's as well as
the analysts'.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

import maljan.agents.judge_agent as judge_agent
from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.judge_agent import JudgeAgent
from maljan.core.spend import SpendCeilingStop

ROOM = 40_000
DEFINITIONS = 7_000
HOW = f"{ROOM} characters — pinned"


class _KeepsTurns:
    """A model whose adapter sends assistant turns as received."""

    _maljan_keeps_turns = True
    model = "kept @ http://127.0.0.1:1"

    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        return AIMessage(content="CONTRADICTIONS: NONE")


class _RebuildsTurns(_KeepsTurns):
    _maljan_keeps_turns = False


class _Fails(_RebuildsTurns):
    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        raise RuntimeError("the server went away")


def _conversation(tools: int, chars_each: int) -> list[Any]:
    msgs: list[Any] = [SystemMessage(content="You decide."), HumanMessage(content="The task.")]
    for i in range(tools):
        msgs.append(
            AIMessage(content="", tool_calls=[{"name": "lookup", "args": {}, "id": f"c{i}"}])
        )
        msgs.append(ToolMessage(content=f"answer-{i}-" + "x" * chars_each, tool_call_id=f"c{i}"))
    return msgs


@pytest.fixture(autouse=True)
def _pinned_room(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("maljan.agents.base_agent.synthesis_budget", lambda *a, **k: (ROOM, HOW))
    monkeypatch.setattr(judge_agent, "synthesis_budget", lambda *a, **k: (ROOM, HOW))


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")
        self.logger = logging.getLogger("test.salvage_room")
        self._tool_definition_chars = DEFINITIONS
        self._note_budget({"stage": "analysis", "cap": "steps"})

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: Any, **_: Any) -> str:
        return "CLAIM: x"


def _analyst_salvage(llm: Any) -> dict[str, Any]:
    agent = _Analyst(llm)
    agent._force_final_synthesis(_conversation(3, 100), None, 0.0)
    (row,) = agent.drain_budget_records()
    return dict(row["salvage"])


class TestTheAnalystSalvage:
    def test_kept_turns_take_the_definitions_off_the_room(self) -> None:
        salvage = _analyst_salvage(_KeepsTurns())

        assert salvage["budget_chars"] == ROOM - DEFINITIONS
        assert salvage["window_budget"] == (
            f"{HOW}, less {DEFINITIONS} characters sent beside the turns"
        )

    def test_rebuilt_turns_take_nothing_off(self) -> None:
        salvage = _analyst_salvage(_RebuildsTurns())

        assert salvage["budget_chars"] == ROOM
        assert salvage["window_budget"] == HOW


def _judge_salvage(
    llm: Any, msgs: list[Any] | None = None, timeout: float = 30.0
) -> tuple[JudgeAgent, str]:
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    judge._tool_definition_chars = DEFINITIONS
    said = asyncio.run(
        judge._reasoning_from_what_was_gathered(
            _conversation(3, 100) if msgs is None else msgs, timeout, None, ended_why="steps"
        )
    )
    return judge, said


class TestTheJudgeSalvage:
    def test_kept_turns_take_the_definitions_off_the_room(self) -> None:
        judge, said = _judge_salvage(_KeepsTurns())

        row = judge._salvage_row
        assert said == "CONTRADICTIONS: NONE"
        assert row is not None and row["outcome"] == "answered"
        assert row["budget_chars"] == ROOM - DEFINITIONS
        assert row["window_budget"] == f"{HOW}, less {DEFINITIONS} characters sent beside the turns"
        assert "messages_dropped" not in row

    def test_rebuilt_turns_take_nothing_off(self) -> None:
        judge, _said = _judge_salvage(_RebuildsTurns())

        row = judge._salvage_row
        assert row is not None
        assert row["budget_chars"] == ROOM
        assert row["window_budget"] == HOW

    def test_a_cut_is_counted_and_said(self, caplog: pytest.LogCaptureFixture) -> None:
        msgs = _conversation(8, 9_000)

        with caplog.at_level(logging.WARNING, logger="maljan.judge"):
            judge, _said = _judge_salvage(_RebuildsTurns(), msgs)

        row = judge._salvage_row
        assert row is not None
        assert row["sent_chars"] <= ROOM < row["conversation_chars"]
        assert row["messages_dropped"] >= 2
        assert (
            f"JudgeAgent reasoning salvage: trimmed {row['messages_dropped']} of {len(msgs)} "
            f"messages to fit {ROOM} chars."
        ) in caplog.text

    def test_a_call_the_spend_ceiling_refuses_is_not_sent(self) -> None:
        with patch.object(
            JudgeAgent, "_spend_admits", side_effect=SpendCeilingStop("the ceiling is reached")
        ):
            judge, said = _judge_salvage(_RebuildsTurns())

        assert said == ""
        assert judge._salvage_row is not None
        assert judge._salvage_row["outcome"] == "not sent"

    def test_a_call_that_raises_failed(self) -> None:
        judge, said = _judge_salvage(_Fails())

        assert said == ""
        assert judge._salvage_row is not None
        assert (judge._salvage_row["outcome"], judge._salvage_row["detail"]) == (
            "failed",
            "RuntimeError",
        )

    def test_no_time_left_is_on_the_record(self) -> None:
        judge, said = _judge_salvage(_RebuildsTurns(), timeout=0.2)

        assert said == ""
        assert judge._salvage_row == {
            "seconds_left": 0.2,
            "outcome": "not sent",
            "detail": "no time left",
        }
