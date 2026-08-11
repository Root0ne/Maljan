"""The salvage path must fit inside the budget it is salvaging.

Measured 2026-08-11 on a real binary: the static analyst's ReAct loop spent its
40-step budget in **109 seconds**, ended without a final answer, and triggered
`_force_final_synthesis`. That call was handed the *entire* 41-message
conversation — 19 tool outputs — and a **fresh** copy of the full 1,500 s
timeout. It ran 25 minutes, hit the 1,530 s hard cap, and the analysis produced
**zero techniques**.

Two bounds composed into nothing: exceeding the step cap *guarantees* an attempt
at the time cap, and on a rich binary that attempt cannot finish. The fallback
was not a safety net on that workload, it was a 25-minute path to zero.

Both halves are fixed here and both are pinned:

* **Time.** Synthesis gets what is *left* of the budget, not a new one. The loop
  has already spent part of it, and a salvage that overruns the deadline it was
  called to respect is not a salvage.
* **Input.** The conversation is trimmed to a character budget before being
  re-sent, keeping the framing (system + task) and the *most recent* evidence —
  the model cannot synthesise from context it never finishes reading.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents.base_agent import BaseAnalyst


class _Analyst(BaseAnalyst):
    """Concrete stand-in: records what synthesis was asked to do."""

    def __init__(self) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.forced_synthesis")
        self.seen_messages: list[Any] = []
        self.seen_timeout: int | None = None

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: int) -> str:
        self.seen_messages = list(messages)
        self.seen_timeout = timeout
        return "FINAL ANSWER"


def _conversation(n_tools: int, chars_each: int) -> list:
    msgs: list = [
        SystemMessage(content="You are a static analyst."),
        HumanMessage(content="Analyse this binary."),
    ]
    for i in range(n_tools):
        msgs.append(AIMessage(content="", tool_calls=[]))
        msgs.append(ToolMessage(content=f"tool-{i}-" + ("x" * chars_each), tool_call_id=str(i)))
    msgs.append(AIMessage(content="Sorry, need more steps to process this request."))
    return msgs


class TestSynthesisGetsTheRemainingBudget:
    def test_time_already_spent_is_subtracted(self) -> None:
        a = _Analyst()
        a._force_final_synthesis(_conversation(3, 100), timeout=1500, elapsed=1100.0)
        assert a.seen_timeout is not None
        assert a.seen_timeout <= 400, f"synthesis got {a.seen_timeout}s of a 1500s budget"

    def test_a_nearly_exhausted_budget_skips_synthesis_entirely(self) -> None:
        """Below a floor there is no point starting: the call cannot finish, and
        starting it is how the 1,530 s hard cap came to fire."""
        a = _Analyst()
        out = a._force_final_synthesis(_conversation(3, 100), timeout=1500, elapsed=1495.0)
        assert out == ""
        assert a.seen_timeout is None, "no call should have been made"

    def test_a_fresh_budget_is_never_handed_out(self) -> None:
        a = _Analyst()
        a._force_final_synthesis(_conversation(3, 100), timeout=1500, elapsed=109.5)
        assert a.seen_timeout is not None
        assert a.seen_timeout < 1500


class TestSynthesisInputIsBounded:
    def test_a_huge_conversation_is_trimmed(self) -> None:
        """19 tool outputs at 6,000 chars each is the measured shape."""
        a = _Analyst()
        a._force_final_synthesis(_conversation(19, 6000), timeout=1500, elapsed=109.5)
        total = sum(len(str(m.content)) for m in a.seen_messages)
        assert total < 114_000, f"sent {total} chars unbounded"

    def test_the_framing_survives_trimming(self) -> None:
        """Dropping the system prompt or the task would change the question,
        not just its size."""
        a = _Analyst()
        a._force_final_synthesis(_conversation(19, 6000), timeout=1500, elapsed=109.5)
        kinds = [type(m).__name__ for m in a.seen_messages]
        assert "SystemMessage" in kinds
        assert any(
            isinstance(m, HumanMessage) and "Analyse this binary" in str(m.content)
            for m in a.seen_messages
        )

    def test_the_most_recent_evidence_is_the_evidence_kept(self) -> None:
        """When something must go, the oldest tool output goes first — the
        model was still working when the budget ran out, so the late calls are
        the ones it chose after seeing the early ones."""
        a = _Analyst()
        a._force_final_synthesis(_conversation(19, 6000), timeout=1500, elapsed=109.5)
        body = " ".join(str(m.content) for m in a.seen_messages)
        assert "tool-18-" in body, "the last tool result was dropped"

    def test_a_small_conversation_is_left_alone(self) -> None:
        a = _Analyst()
        convo = _conversation(2, 50)
        a._force_final_synthesis(convo, timeout=1500, elapsed=10.0)
        # convo + the directive
        assert len(a.seen_messages) == len(convo) + 1

    def test_the_directive_is_still_appended(self) -> None:
        a = _Analyst()
        a._force_final_synthesis(_conversation(19, 6000), timeout=1500, elapsed=109.5)
        last = a.seen_messages[-1]
        assert isinstance(last, HumanMessage)
        assert "Do NOT" in str(last.content)


class TestTheBudgetIsMeasuredAsTheServerSeesIt:
    """A ReAct transcript is mostly tool-call requests, and those carry an empty
    ``content``. Measuring text alone reported zero for them: the first cut of
    this trim dropped one message from a conversation llama.cpp then reported at
    38,868 tokens, and the salvage still took 25 minutes.
    """

    def test_a_tool_call_request_is_not_free(self) -> None:
        from maljan.agents.base_agent import _message_chars

        m = AIMessage(
            content="",
            tool_calls=[{"name": "decompile_function", "args": {"addr": "0x401000"}, "id": "1"}],
        )
        assert len(str(m.content)) == 0
        assert _message_chars(m) > 20, "the request payload was counted as nothing"

    def test_a_transcript_of_tool_requests_is_trimmed(self) -> None:
        from maljan.agents.base_agent import _trim_for_synthesis

        msgs: list = [SystemMessage(content="sys"), HumanMessage(content="task")]
        for i in range(40):
            msgs.append(
                AIMessage(
                    content="",
                    tool_calls=[{"name": "f", "args": {"blob": "y" * 2000}, "id": str(i)}],
                )
            )
        kept = _trim_for_synthesis(msgs, 16_000)
        assert len(kept) < len(msgs), "a transcript of empty-content messages was left whole"
