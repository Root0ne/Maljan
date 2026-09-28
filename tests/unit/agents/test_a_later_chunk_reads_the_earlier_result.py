"""A later chunk's call that an earlier chunk made is answered with the result it recorded.

A reverser's second chunk asked 24 calls and made 3 new ledger entries: every
call the first chunk had made was refused with "the result is in [ev_…]", an
entry the model could not read from its own conversation, so it asked again
and the loop ended at its repeat stop. The earlier call is now answered with
the text its entry recorded, stamped with that entry's id, and neither run
again nor counted toward the repeat stop. The later chunk's prompt still lists
the earlier calls, and it reaches the model.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import EARLIER_CHUNKS_HEAD, BaseAnalyst
from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    earlier_chunk_answer,
    record_tools,
    seeded_repeat_guard,
)
from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry

RESULT = "int FUN_3c7c(void)\n{ return decode(0x10); }"


class _Args(BaseModel):
    path: str = ""


def _tool(calls: list[str]) -> StructuredTool:
    def _run(path: str = "") -> str:
        calls.append(path)
        return f"fresh answer for {path}"

    return StructuredTool.from_function(
        func=_run,
        name="decompile_function",
        description="Decompile one function.",
        args_schema=_Args,
        infer_schema=False,
    )


def _wrapped(guard: RepeatGuard, calls: list[str]) -> Any:
    recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
    return record_tools([_tool(calls)], recorder, guard)[0]


def _entry(**fields: Any) -> LedgerEntry:
    base: dict[str, Any] = {
        "id": "ev_0003",
        "tool": "decompile_function",
        "args": {"path": "0x3c7c"},
        "output": RESULT,
    }
    base.update(fields)
    return LedgerEntry(**base)


class TestTheEarlierResultAnswersTheCall:
    def test_it_is_the_recorded_text_under_the_entry_s_id_and_nothing_runs(self) -> None:
        guard = seeded_repeat_guard([_entry()])
        calls: list[str] = []

        answer = _wrapped(guard, calls).invoke({"path": "0x3c7c"})

        assert calls == []
        assert answer == earlier_chunk_answer("decompile_function", "ev_0003", RESULT)
        assert answer.startswith(f"[ev_0003]\n{RESULT}")
        assert guard.served_repeats == 0

    def test_the_answer_says_where_the_result_came_from(self) -> None:
        answer = earlier_chunk_answer("decompile_function", "ev_0003", RESULT)
        tail = answer[len(f"[ev_0003]\n{RESULT}") :]

        assert "earlier chunk" in tail
        assert "[ev_0003]" in tail
        assert "not run again" in tail

    def test_asking_again_in_the_same_chunk_is_a_repeat(self) -> None:
        guard = seeded_repeat_guard([_entry()])
        calls: list[str] = []
        tool = _wrapped(guard, calls)

        tool.invoke({"path": "0x3c7c"})
        again = tool.invoke({"path": "0x3c7c"})

        assert calls == []
        assert "the result is in [ev_0003]" in again
        assert guard.served_repeats == 1

    def test_several_earlier_calls_asked_once_each_leave_the_loop_running(self) -> None:
        guard = seeded_repeat_guard(
            [
                _entry(id=f"ev_{n:04d}", args={"path": f"0x{n:x}"}, output=f"body {n}")
                for n in range(1, 25)
            ]
        )
        calls: list[str] = []
        tool = _wrapped(guard, calls)

        answers = [tool.invoke({"path": f"0x{n:x}"}) for n in range(1, 25)]

        assert calls == []
        assert [a.split("\n", 2)[1] for a in answers] == [f"body {n}" for n in range(1, 25)]
        assert guard.served_repeats == 0
        assert guard.ending_the_loop() is False

    def test_a_failed_earlier_call_is_still_served_once_more(self) -> None:
        guard = seeded_repeat_guard([_entry(ok=False, output="Program not found")])
        calls: list[str] = []

        retried = _wrapped(guard, calls).invoke({"path": "0x3c7c"})

        assert calls == ["0x3c7c"]
        assert "fresh answer for 0x3c7c" in retried
        assert guard.served_repeats == 0

    def test_an_earlier_result_the_run_did_not_keep_is_run_once_more(self) -> None:
        """A byte budget that blanked the entry left no text to answer with."""
        guard = seeded_repeat_guard([_entry(output="", truncated=True)])
        calls: list[str] = []
        tool = _wrapped(guard, calls)

        ran = tool.invoke({"path": "0x3c7c"})
        refused = tool.invoke({"path": "0x3c7c"})

        assert calls == ["0x3c7c"]
        assert "fresh answer for 0x3c7c" in ran
        assert "the result is in [ev_0001]" in refused
        assert "failed" not in refused
        assert guard.served_repeats == 1

    def test_a_replayed_conversation_is_answered_from_the_record_again(self) -> None:
        guard = seeded_repeat_guard([_entry()])
        calls: list[str] = []
        tool = _wrapped(guard, calls)
        tool.invoke({"path": "0x3c7c"})

        guard.reset()

        assert tool.invoke({"path": "0x3c7c"}).startswith(f"[ev_0003]\n{RESULT}")
        assert calls == []
        assert guard.served_repeats == 0


# ---------------------------------------------------------------------------
# Through the real chunked analysis: what the model receives in chunk two.
# ---------------------------------------------------------------------------

REPORT = "CLAIM: it decodes a string table\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"


class _Model(BaseChatModel):
    """Calls the same function once per conversation, then answers."""

    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        if any(isinstance(m, ToolMessage) for m in sent):
            turn = AIMessage(content=REPORT)
        else:
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "decompile_function", "args": {"path": "0x3c7c"}, "id": "c1"}],
            )
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:
        return self.execute_tool_loop([("system", "s"), ("human", data)])

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _chunk(index: int) -> TextChunk:
    content = f"function listing part {index + 1}"
    return TextChunk(
        index=index,
        total=2,
        strategy=ChunkStrategy.SLIDING_WINDOW,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="static",
    )


@pytest.fixture(autouse=True)
def _no_suggestions(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.tools import knowledge

    monkeypatch.setattr(knowledge, "resolve_technique", lambda *a, **k: {"candidates": []})


def test_the_second_chunk_s_model_reads_the_earlier_calls_and_their_result() -> None:
    model = _Model()
    model.seen = []
    calls: list[str] = []
    analyst = _Analyst(llm=model, name="reverser")
    analyst.logger = logging.getLogger("test.later_chunk")
    analyst.tools = [_tool(calls)]

    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
        analyst.safe_analyze_isr_chunked([_chunk(0), _chunk(1)])

    assert calls == ["0x3c7c"], "the second chunk's identical call is not run"
    second = [
        sent
        for sent in model.seen
        if any("function listing part 2" in str(m.content) for m in sent)
    ]
    assert second, "the second chunk reached the model"
    human = next(m for m in second[0] if isinstance(m, HumanMessage))
    assert EARLIER_CHUNKS_HEAD in str(human.content)
    assert 'decompile_function({"path": "0x3c7c"}) → ev_0001' in str(human.content)
    answered = [m for m in second[-1] if isinstance(m, ToolMessage)]
    assert answered and str(answered[-1].content).startswith("[ev_0001]\nfresh answer for 0x3c7c")
    assert "earlier chunk" in str(answered[-1].content)
