"""On Claude, a question asked after a loop continues the loop's own conversation, from its cache.

A validation retry, the whole-answer question and the drops question each ran
the analyst's tool loop over a conversation rebuilt from text: the evidence
as the first user turn, the answer, the question. Its prefix was none the
loop had sent, so the provider wrote it again (a 98 k to 250 k token write at
the long-prompt price on the stored run's analysts) and a question asked once
read nothing back. Asked over the loop's conversation as the loop last sent
it, the question's request is the loop's last request plus the turns the
rebuilt one put after its first turn (the answer as text, the question):
every byte before them is read from the cache the loop wrote, a question
answered in one turn writes nothing, and a question that calls a tool writes
only what follows the loop. The rebuilt conversation stays the question
wherever no loop ended on the answer, the model's cache entry has lived past
its lifetime, or the conversation would not fit the window, and it is the
tools-free call's conversation.

The cost model here is the provider's: an entry is written at each
breakpoint whose prefix no entry holds, from the longest prefix one holds,
and read up to the longest prefix an entry holds; sizes are the characters of
the canonical rendering.
"""

from __future__ import annotations

import json
import time
from typing import Any, cast
from unittest.mock import patch

import pytest

from maljan.agents.base_agent import BaseAnalyst, KeptConversation
from maljan.llm import anthropic_history
from maljan.pipeline.validation import ANALYST_TOOLS_ATTACHED, TECHNIQUE_FACTS_LEAD, Violation

from .anthropic_wire import Wire, _as_blocks, _unmarked, install, message
from .test_a_replayed_thinking_block_stays_valid import (
    REPORT,
    USAGE,
    _calls_allowed,
    _lookup,
    _model,
    _results,
    _thinking,
)

SYSTEM = "You are a static analyst."
TOLD = [Violation(code="isr.ungrounded_technique", message="cite the entry that holds it")]


def _is_question(body: dict[str, Any]) -> bool:
    return ANALYST_TOOLS_ATTACHED in json.dumps(body["messages"], ensure_ascii=False)


def _answers(retry_calls: int) -> Any:
    """The loop calls twice then reports; the retry calls ``retry_calls`` times then answers."""

    def answer(body: dict[str, Any]) -> dict[str, Any]:
        done = _results(body)
        wanted = 2 + retry_calls if _is_question(body) else 2
        if _calls_allowed(body) and done < wanted:
            call = {
                "type": "tool_use",
                "id": f"toolu_{done}",
                "name": "lookup",
                "input": {"what": str(done)},
            }
            return message([_thinking(done), call], stop="tool_use", usage=USAGE)
        text = {"type": "text", "text": REPORT}
        return message([_thinking(100 + len(body["messages"])), text], stop="end_turn", usage=USAGE)

    return answer


class _Analyst(BaseAnalyst):
    def _system_prompt(self, fallback: Any, tools: Any = None) -> str:
        return SYSTEM if tools is None else f"{SYSTEM} No tools are attached."

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _canonical(body: dict[str, Any], turns: int) -> str:
    return json.dumps(
        _unmarked(
            {
                "system": body.get("system"),
                "tools": body.get("tools"),
                "messages": [_as_blocks(t) for t in body["messages"][:turns]],
            }
        ),
        sort_keys=True,
    )


def _marks(body: dict[str, Any]) -> list[int]:
    return [
        index
        for index, turn in enumerate(body["messages"])
        if isinstance(turn["content"], list)
        and any(isinstance(b, dict) and "cache_control" in b for b in turn["content"])
    ]


class _Cache:
    """The provider's prompt cache over the requests sent, in characters."""

    def __init__(self) -> None:
        self.entries: set[str] = set()

    def send(self, body: dict[str, Any]) -> tuple[int, int]:
        """``(read, written)`` for one request."""
        marks = _marks(body)
        if not marks:
            return 0, 0
        read = max(
            (len(p) for k in range(1, marks[-1] + 2) if (p := _canonical(body, k)) in self.entries),
            default=0,
        )
        upto, written = read, 0
        for index in marks:
            prefix = _canonical(body, index + 1)
            if prefix not in self.entries:
                written += max(0, len(prefix) - upto)
                self.entries.add(prefix)
            upto = max(upto, len(prefix))
        return read, written


def _run(monkeypatch: pytest.MonkeyPatch, retry_calls: int, *, aged: bool = False) -> Any:
    from maljan.agents import base_agent

    wire = Wire(_answers(retry_calls))
    install(monkeypatch, wire)
    monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 40))
    agent = _Analyst(llm=_model(), name="static")
    agent.run_state_block = "sample: c"
    agent.tools = [_lookup()]
    text = agent.execute_tool_loop([("system", SYSTEM), ("human", "Analyse.")])
    loop = list(wire.bodies)
    isr = agent._text_to_isr(text, revision_round=0)
    if aged:
        kept = agent._kept_conversation
        assert kept is not None
        agent._kept_conversation = KeptConversation(kept.messages, kept.sent_at - 3600.0)
    answers = iter([TOLD, TOLD, []])
    with patch("maljan.pipeline.validation.validate_isr", lambda *_a, **_k: next(answers, [])):
        agent._validate_isr(isr, "the raw data")
    questions = [body for body in wire.bodies if _is_question(body)]
    return wire, loop, questions


class TestTheRetryContinuesTheLoop:
    def test_its_request_is_the_loop_s_last_request_and_the_question(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, loop, questions = _run(monkeypatch, 0)
        assert wire.refused == [] and wire.dropped == []
        assert len(questions) == 1
        last, first = loop[-1], questions[0]
        sent = len(last["messages"])
        assert _canonical(first, sent) == _canonical(last, sent)
        answer = _as_blocks(first["messages"][sent])
        assert answer["role"] == "assistant"
        assert answer["content"] == [{"type": "text", "text": REPORT}], "its text, as rebuilt"
        assert first["messages"][-1]["role"] == "user"
        assert "the raw data" not in json.dumps(first["messages"]), "no rebuilt first turn"

    def test_a_question_answered_once_reads_the_loop_and_writes_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, loop, questions = _run(monkeypatch, 0)
        cache = _Cache()
        for body in loop:
            cache.send(body)
        read, written = cache.send(questions[0])
        assert written == 0
        assert read == len(_canonical(loop[-1], len(loop[-1]["messages"])))
        newest = questions[0]["messages"][-1]
        assert not any(
            isinstance(b, dict) and "cache_control" in b
            for b in (newest["content"] if isinstance(newest["content"], list) else [])
        ), "the question itself carries no breakpoint"

    def test_a_question_that_calls_a_tool_writes_only_what_follows_the_loop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, loop, questions = _run(monkeypatch, 1)
        assert wire.refused == []
        assert len(questions) == 2
        cache = _Cache()
        for body in loop:
            cache.send(body)
        loop_prefix = len(_canonical(loop[-1], len(loop[-1]["messages"])))
        assert cache.send(questions[0]) == (loop_prefix, 0)
        read, written = cache.send(questions[1])
        assert read == loop_prefix
        whole = len(_canonical(questions[1], len(questions[1]["messages"])))
        assert written == whole - loop_prefix

    def test_the_tool_answers_are_in_view_so_no_entry_is_shown_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire, _loop, questions = _run(monkeypatch, 0)
        question = questions[0]["messages"][-1]
        text = json.dumps(question["content"])
        assert "answer for 0" not in text and "answer for 1" not in text


class TestTheRebuiltConversationStands:
    def test_past_the_cache_lifetime_the_retry_is_rebuilt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, _loop, questions = _run(monkeypatch, 0, aged=True)
        assert wire.refused == []
        assert "the raw data" in json.dumps(questions[0]["messages"][0])

    def test_an_answer_no_loop_ended_on_has_no_base(self) -> None:
        agent = _Analyst(llm=cast(Any, None), name="static")
        task = _human("Analyse.")
        agent._kept_conversation = KeptConversation((task, _ai(REPORT)), time.monotonic())
        assert agent._question_base_of("another answer", tools=True) is None
        assert agent._question_base_of(REPORT, tools=False) is None
        base = agent._question_base_of(f"  {REPORT}\n", tools=True)
        assert base is not None and base.messages == (task,), "the loop without its answer"

    def test_only_turns_that_start_with_the_rebuilt_ones_are_continued(self) -> None:
        agent = _Analyst(llm=cast(Any, None), name="static")
        task = _human("Analyse.")
        agent._question_base = KeptConversation((task,), time.monotonic())
        rebuilt = [_human("the raw data")]
        asked = [*rebuilt, _ai(REPORT), _human("q")]
        continued = agent._continued_question(asked, rebuilt, 0, tools=True)
        assert continued == [task, *asked[1:]]
        merged = [_human("the raw data\n\nq")]
        assert agent._continued_question(merged, rebuilt, 0, tools=True) is None
        assert agent._continued_question(asked, rebuilt, 0, tools=False) is None

    def test_a_base_read_lives_again_from_that_read(self) -> None:
        from maljan.agents import base_agent

        agent = _Analyst(llm=cast(Any, None), name="static")
        rebuilt = [_human("the raw data")]
        asked = [*rebuilt, _ai(REPORT), _human("q")]
        agent._question_base = KeptConversation((_human("Analyse."),), time.monotonic() - 250.0)
        with patch("maljan.llm.anthropic_history.prompt_cache_seconds", lambda *_a, **_k: 300):
            assert agent._continued_question(asked, rebuilt, 0, tools=True) is not None
            assert time.monotonic() - agent._question_base.sent_at < 5.0
            agent._question_base = KeptConversation(
                agent._question_base.messages,
                time.monotonic() - 300.0 + base_agent.KEPT_CONVERSATION_MARGIN_S,
            )
            assert agent._continued_question(asked, rebuilt, 0, tools=True) is None

    def test_a_tools_free_call_asks_over_the_rebuilt_turns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _Analyst(llm=cast(Any, None), name="static")
        sent: list[Any] = []

        def _sent(messages: Any, *_a: Any, **_k: Any) -> str:
            sent.append(messages)
            return "a"

        monkeypatch.setattr(agent, "_invoke_llm_with_timeout", _sent)
        continued = [_human("Analyse."), _ai(REPORT), _human("q")]
        plain = [_human("the raw data"), _ai(REPORT), _human("q")]
        agent._answer_after_loop(continued, None, what="validation retry", tools=False, plain=plain)
        assert sent == [plain]


class TestTheBreakpointRule:
    def test_a_string_turn_s_breakpoint_reads_the_loop_s_entry(self) -> None:
        memory = anthropic_history.Memory()
        mark = {"type": "ephemeral"}
        result = {"type": "tool_result", "tool_use_id": "t1", "content": "answer"}
        call = {"type": "tool_use", "id": "t1", "name": "lookup", "input": {}}
        loop_turns = [
            {"role": "user", "content": "Analyse."},
            {"role": "assistant", "content": [_thinking(1), call]},
            {"role": "user", "content": [result]},
        ]
        anthropic_history.prepared(
            {"messages": loop_turns}, memory, bound=True, cache_marker=mark, loop=True
        )
        answer = {"role": "assistant", "content": [_thinking(2), {"type": "text", "text": REPORT}]}
        retried = {"role": "assistant", "content": [_thinking(3), {"type": "text", "text": "x"}]}
        whole = [
            *loop_turns,
            answer,
            {"role": "user", "content": "the retry's question"},
            retried,
            {"role": "user", "content": "the whole-answer question"},
        ]
        sent = anthropic_history.prepared(
            {"messages": whole}, memory, bound=True, cache_marker=mark, loop=True
        )
        marked = [
            i
            for i, turn in enumerate(sent["messages"])
            if isinstance(turn["content"], list)
            and any(isinstance(b, dict) and "cache_control" in b for b in turn["content"])
        ]
        assert marked == [2], "the loop's last entry, read; nothing new written"

    def test_with_no_entry_before_it_no_breakpoint_is_placed(self) -> None:
        memory = anthropic_history.Memory()
        turns = [
            {"role": "user", "content": "task"},
            {"role": "assistant", "content": [_thinking(2), {"type": "text", "text": REPORT}]},
            {"role": "user", "content": "the question"},
        ]
        sent = anthropic_history.prepared(
            {"messages": turns}, memory, bound=True, cache_marker={"type": "ephemeral"}
        )
        assert "cache_control" not in json.dumps(sent["messages"])


class TestTheRetryCarriesTheCatalogueFacts:
    def test_a_technique_question_names_each_id_s_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _wire, _loop, questions = _run(monkeypatch, 0)
        text = json.dumps(questions[0]["messages"][-1]["content"], ensure_ascii=False)
        assert TECHNIQUE_FACTS_LEAD in text
        assert "T1005 Data from Local System" in text


def _human(text: str) -> Any:
    from langchain_core.messages import HumanMessage

    return HumanMessage(content=text)


def _ai(text: str) -> Any:
    from langchain_core.messages import AIMessage

    return AIMessage(content=text)
