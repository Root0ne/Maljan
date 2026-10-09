"""Every history Maljan re-sends to Claude keeps the thinking blocks it replays valid.

The Preserved thinking page: a thinking block is valid only while the
``system`` prompt, the ``tools`` and every message before it are unchanged;
an edited prefix is a 400 on the accounts the API checks it for by default.
Appending is valid, and so is removing thinking blocks from the end of the
history or all of them.

Each place Maljan re-sends a conversation it changed is driven here with its
own function, on the real provider model, against a stand-in API that runs
the same prefix check (``anthropic_wire.Wire``). Each request must be taken;
where the edit came before a block, that block and every later one are left
out, and where it did not, every block goes back as it came.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import (
    FINAL_ANSWER_NUDGE,
    BaseAnalyst,
    _trim_for_synthesis,
    frame_messages,
    nudge_turns,
    tool_free_turns,
)
from maljan.core.config import Settings
from maljan.llm import anthropic_history
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.pipeline.run_state import RUN_STATE_END
from maljan.pipeline.turns import with_question

from .anthropic_wire import MODEL, Wire, install, message

USAGE = {"input_tokens": 10, "output_tokens": 5}
REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"


def _thinking(turn: int) -> dict[str, Any]:
    return {"type": "thinking", "thinking": "", "signature": f"sig-{turn}-" + "A" * 40}


def _answer(body: dict[str, Any]) -> dict[str, Any]:
    done = sum(
        1
        for m in body["messages"]
        if m["role"] == "user" and isinstance(m["content"], list)
        for b in m["content"]
        if b.get("type") == "tool_result"
    )
    if body.get("tools") and done < 2:
        return message(
            [
                _thinking(done),
                {
                    "type": "tool_use",
                    "id": f"toolu_{done}",
                    "name": "lookup",
                    "input": {"what": "x"},
                },
            ],
            stop="tool_use",
            usage=USAGE,
        )
    return message(
        [_thinking(100 + done), {"type": "text", "text": REPORT}], stop="end_turn", usage=USAGE
    )


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    anthropic_history.forget()
    yield
    anthropic_history.forget()


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Wire:
    found = Wire(_answer)
    install(monkeypatch, found)
    return found


def _model() -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _two_rounds(model: Any) -> list[Any]:
    """System, task, then two tool rounds, each turn thinking first."""
    bound = model.bind_tools([_lookup()])
    history: list[Any] = [
        SystemMessage(content="You are an analyst. Call the tools you are given."),
        HumanMessage(content="Analyse the sample."),
    ]
    for index in range(2):
        turn = bound.invoke(history)
        call = turn.tool_calls[0]
        history += [turn, ToolMessage(content=f"answer {index}", tool_call_id=call["id"])]
    return history


def _sent_thinking(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        block
        for m in body["messages"]
        if m["role"] == "assistant" and isinstance(m["content"], list)
        for block in m["content"]
        if block.get("type") == "thinking"
    ]


class TestTheStandInChecksWhatTheApiChecks:
    def test_an_edited_prefix_is_refused_when_nothing_keeps_it_valid(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(anthropic_history, "prepared", lambda payload: payload)
        model = _model()
        history = _two_rounds(model)
        edited = [*history]
        edited[3] = ToolMessage(content="answer 0, shortened", tool_call_id=history[3].tool_call_id)
        with pytest.raises(Exception, match="Invalid `signature`"):
            model.bind_tools([_lookup()]).invoke(edited)


class TestEachEditMaljanMakes:
    def test_an_appended_question_keeps_every_block(self, wire: Wire) -> None:
        """The nudge sent on the loop's own model: the question is a new turn."""
        model = _model()
        history = _two_rounds(model)
        sendable, _ = nudge_turns(history)
        model.bind_tools([_lookup()]).invoke(with_question(sendable, FINAL_ANSWER_NUDGE))
        assert wire.refused == []
        assert _sent_thinking(wire.bodies[-1]) == [_thinking(0), _thinking(1)]

    def test_the_tool_free_nudge_leaves_every_block_out(self, wire: Wire) -> None:
        """No tools and a changed system turn: every block is stale."""
        model = _model()
        history = _two_rounds(model)
        sendable, _ = nudge_turns(history)
        model.invoke(with_question(tool_free_turns(sendable), FINAL_ANSWER_NUDGE))
        assert wire.refused == []
        assert _sent_thinking(wire.bodies[-1]) == []
        assert "tools" not in wire.bodies[-1]

    def test_the_forced_synthesis_trimmed_to_fit(self, wire: Wire) -> None:
        model = _model()
        history = _two_rounds(model)
        trimmed = _trim_for_synthesis(history, 200)
        assert len(trimmed) < len(history)
        model.invoke(with_question(tool_free_turns(trimmed), "Write your answer now."))
        assert wire.refused == []
        assert _sent_thinking(wire.bodies[-1]) == []

    def test_an_earlier_tool_answer_changed_leaves_out_the_blocks_after_it(
        self, wire: Wire
    ) -> None:
        model = _model()
        history = _two_rounds(model)
        edited = [*history]
        edited[3] = ToolMessage(content="answer 0, shortened", tool_call_id=history[3].tool_call_id)
        model.bind_tools([_lookup()]).invoke(edited)
        assert wire.refused == []
        # The first turn's block was written before the edit and stays.
        assert _sent_thinking(wire.bodies[-1]) == [_thinking(0)]

    def test_a_block_this_process_never_received_is_sent_as_it_is(self, wire: Wire) -> None:
        model = _model()
        history = _two_rounds(model)
        anthropic_history.forget()
        model.bind_tools([_lookup()]).invoke(with_question(history, "And now."))
        assert _sent_thinking(wire.bodies[-1]) == [_thinking(0), _thinking(1)]


class TestTheRunStateBlock:
    def test_an_earlier_turn_is_sent_with_the_block_it_was_first_sent_with(
        self, wire: Wire
    ) -> None:
        """The loop's own framing moves the block; the request puts it back."""
        model = _model().bind_tools([_lookup()])
        history: list[Any] = [SystemMessage(content="sys"), HumanMessage(content="task")]
        for index in range(2):
            sent = frame_messages(history, run_state=f"steps left: {10 - index}")
            turn = model.invoke(sent)
            history += [
                turn,
                ToolMessage(content=f"answer {index}", tool_call_id=turn.tool_calls[0]["id"]),
            ]
        model.invoke(frame_messages(history, run_state="steps left: 8"))
        assert wire.refused == []
        first, second, third = wire.bodies
        assert second["messages"][: len(first["messages"])] == first["messages"]
        assert third["messages"][: len(second["messages"])] == second["messages"]
        assert first["messages"][0]["content"].endswith(RUN_STATE_END)
        assert "steps left: 10" in third["messages"][0]["content"]
        assert "steps left: 8" in str(third["messages"][-1]["content"])
        assert _sent_thinking(third) == [_thinking(0), _thinking(1)]


class TestTheAnalystsLoopAgainstTheCheck:
    def test_a_loop_with_a_counting_budget_is_never_refused(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The analysts' loop with a step budget, whose block changes every turn."""
        from maljan.agents import base_agent

        monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 20))

        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
                return ""

        agent = _Analyst(llm=_model(), name="static")
        agent.run_state_block = "sample: c"
        agent.tools = [_lookup()]
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        assert len(wire.bodies) == 3
        assert wire.refused == []
        assert _sent_thinking(wire.bodies[-1]) == [_thinking(0), _thinking(1)]
