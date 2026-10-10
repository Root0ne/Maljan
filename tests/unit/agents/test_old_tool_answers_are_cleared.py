"""A long tool loop clears its oldest tool answers to ledger references, in batches.

Two points clear: the window, always — a request that would not fit the model's
window less its output room would be refused and end the loop — and the
operator's ``react_agent_clear_tool_answers_at``, off by default. A clear takes
the oldest answers down to half the point in one batch and keeps them cleared,
under the same text, so the request's front is the same from one clear to the
next. The newest turn's answers, the framing and the agent's own turns (its
reasoning included) are never cleared; a reference names every ledger id the
answer carried and the tool that reads it again, which the loop offers from the
first clear on. Without a point the request is what it always was.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    convert_to_openai_messages,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel

from maljan.agents import tool_answer_clearing as tac
from maljan.agents.base_agent import BaseAnalyst, _message_chars, _reported_request
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.llm import context_window as cw
from maljan.pipeline.events import TOOL_ANSWERS_CLEARED

REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
TASK = "Analyse the sample."


# ---------------------------------------------------------------------------
# The clearing itself, over a conversation built by hand
# ---------------------------------------------------------------------------


def _conversation(turns: int, answer_chars: int, reasoning: int = 0) -> list[Any]:
    """A system turn, the task, then ``turns`` model turns each with two stamped answers."""
    out: list[Any] = [SystemMessage(content="s" * 500), HumanMessage(content=TASK)]
    entry = 0
    for turn in range(turns):
        calls = []
        for slot in range(2):
            calls.append(
                {"name": "lookup", "args": {"n": turn * 2 + slot}, "id": f"c{turn}_{slot}"}
            )
        kwargs = {"reasoning_content": "r" * reasoning} if reasoning else {}
        out.append(AIMessage(content="", tool_calls=calls, additional_kwargs=kwargs))
        for call in calls:
            entry += 1
            out.append(
                ToolMessage(
                    content=f"[ev_{entry:04d}]\n" + "a" * answer_chars,
                    tool_call_id=call["id"],
                )
            )
    return out


def _no_report(_messages: list[Any]) -> tuple[int, int]:
    return 0, -1


def _fit(clearing: tac.ToolAnswerClearing, messages: list[Any], extra: int = 0) -> tac.FitResult:
    return clearing.fit(
        messages, extra_chars=extra, measure=_message_chars, reported=_no_report, turn=1
    )


def _size(messages: list[Any]) -> int:
    return sum(_message_chars(m) for m in messages)


def _wire(messages: list[Any]) -> list[str]:
    return [json.dumps(m, sort_keys=True) for m in convert_to_openai_messages(messages)]


class TestNoPointOrUnderIt:
    def test_a_request_under_the_point_is_the_same_messages(self) -> None:
        messages = _conversation(4, 1_000)
        clearing = tac.ToolAnswerClearing(window_chars=_size(messages) + 1)
        fitted = _fit(clearing, messages)
        assert fitted.clearing is None
        assert all(a is b for a, b in zip(fitted.messages, messages, strict=True))
        assert _wire(fitted.messages) == _wire(messages)

    def test_no_point_at_all_is_the_same_messages(self) -> None:
        messages = _conversation(4, 1_000)
        fitted = _fit(tac.ToolAnswerClearing(), messages)
        assert fitted.clearing is None and _wire(fitted.messages) == _wire(messages)


class TestARequestThatWouldNotFit:
    def test_the_oldest_answers_go_until_it_fits_and_the_newest_turn_stays(self) -> None:
        messages = _conversation(6, 5_000)
        point = _size(messages) - 10_000
        clearing = tac.ToolAnswerClearing(window_chars=point)
        fitted = _fit(clearing, messages)
        assert fitted.clearing is not None
        assert fitted.clearing.why == tac.CLEARED_FOR_WINDOW
        assert _size(fitted.messages) <= point // 2
        assert fitted.clearing.chars_after == _size(fitted.messages)
        tools = [m for m in fitted.messages if isinstance(m, ToolMessage)]
        cleared = [m for m in tools if str(m.content).startswith("[cleared ")]
        # Oldest first, in order, and the newest turn's two answers untouched.
        assert tools[: len(cleared)] == cleared
        assert tools[-2:] == messages[-2:]
        assert all(m is n for m, n in zip(tools[-2:], messages[-2:], strict=True))

    def test_a_reference_names_the_ids_and_the_tool_that_reads_them_again(self) -> None:
        messages = _conversation(3, 5_000)
        messages[3] = ToolMessage(
            content="[ev_0001]\n" + "a" * 5_000 + "\nthe same as ev_0042",
            tool_call_id="c0_0",
        )
        fitted = _fit(tac.ToolAnswerClearing(window_chars=_size(messages) - 1), messages)
        reference = str(fitted.messages[3].content)
        assert reference.startswith("[cleared ev_0001, ev_0042]")
        assert tac.READ_EVIDENCE_TOOL in reference and "evidence_id ev_0001" in reference
        assert fitted.messages[3].tool_call_id == "c0_0"

    def test_only_tool_answers_are_cleared_and_reasoning_stays_byte_for_byte(self) -> None:
        messages = _conversation(5, 3_000, reasoning=2_000)
        fitted = _fit(tac.ToolAnswerClearing(window_chars=_size(messages) - 1), messages)
        for before, after in zip(messages, fitted.messages, strict=True):
            if not isinstance(before, ToolMessage):
                assert after is before
        thoughts = [
            m.additional_kwargs.get("reasoning_content")
            for m in fitted.messages
            if isinstance(m, AIMessage)
        ]
        assert thoughts == ["r" * 2_000] * 5

    def test_an_answer_without_an_id_is_never_cleared(self) -> None:
        messages = _conversation(3, 4_000)
        messages[3] = ToolMessage(content="b" * 4_000, tool_call_id="c0_0")
        fitted = _fit(tac.ToolAnswerClearing(window_chars=1), messages)
        assert fitted.messages[3] is messages[3]

    def test_the_server_s_own_count_is_lowered_by_what_the_clear_took(self) -> None:
        messages = _conversation(4, 4_000)
        last_turn = max(i for i, m in enumerate(messages) if isinstance(m, AIMessage))

        def reported(sent: list[Any]) -> tuple[int, int]:
            return _size(sent) + 3_000, last_turn

        clearing = tac.ToolAnswerClearing(window_chars=_size(messages))
        fitted = clearing.fit(
            messages, extra_chars=0, measure=_message_chars, reported=reported, turn=5
        )
        assert fitted.clearing is not None
        assert fitted.freed_before_report == _size(messages) - _size(fitted.messages)
        assert fitted.clearing.chars_after <= _size(messages) // 2


class TestTheOperatorsPoint:
    def test_a_batch_down_to_half_and_the_front_stays_until_the_next(self) -> None:
        messages = _conversation(8, 2_000)
        point = _size(messages) - 1
        clearing = tac.ToolAnswerClearing(window_chars=10 * point, setting_chars=point)
        first = _fit(clearing, messages)
        assert first.clearing is not None and first.clearing.why == tac.CLEARED_FOR_SETTING
        assert _size(first.messages) <= point // 2
        sent = [first.messages]
        grown = list(messages)
        clears = 1
        for turn in range(20):
            call = {"name": "lookup", "args": {"n": 100 + turn}, "id": f"late{turn}"}
            grown.append(AIMessage(content="", tool_calls=[call]))
            grown.append(
                ToolMessage(
                    content=f"[ev_{200 + turn:04d}]\n" + "a" * 2_000, tool_call_id=call["id"]
                )
            )
            fitted = _fit(clearing, grown)
            if fitted.clearing is None:
                # No clear: every earlier request is this one's front, byte for byte.
                head = _wire(sent[-1])
                assert _wire(fitted.messages)[: len(head)] == head
            else:
                clears += 1
            sent.append(fitted.messages)
        # Batches: several turns between clears, never one a turn.
        assert 1 < clears < 20 // 2
        assert len(clearing.clears) == clears


class TestLinear:
    def test_ten_times_the_messages_takes_about_ten_times_as_long(self) -> None:
        def timed(turns: int) -> float:
            messages = _conversation(turns, 300)
            clearing = tac.ToolAnswerClearing(window_chars=_size(messages) // 3)
            began = time.perf_counter()
            _fit(clearing, messages)
            _fit(clearing, messages)
            return time.perf_counter() - began

        timed(200)
        small = min(timed(200) for _ in range(3))
        large = min(timed(2_000) for _ in range(3))
        # Ten times the messages in at most about ten times the time (twenty, for noise).
        assert large < small * 20


class TestReadAgain:
    def _recorder(self) -> EvidenceRecorder:
        recorder = EvidenceRecorder("static")
        recorder.record(tool="lookup", args={"n": 1}, server=None, output="the first answer")
        recorder.record(
            tool="lookup", args={"n": 1}, server=None, output="see ev_0001", repeated_of="ev_0001"
        )
        return recorder

    def test_it_answers_with_the_stored_output(self) -> None:
        from maljan.agents.base_agent import _stored_answer_of

        tool = tac.read_evidence_tool(_stored_answer_of(self._recorder()))
        assert tool.name == tac.READ_EVIDENCE_TOOL
        assert tool.invoke({"evidence_id": "ev_0001"}) == "the first answer"
        # A repeat reads the entry that holds its answer.
        assert tool.invoke({"evidence_id": "EV_0002"}) == "the first answer"

    def test_an_id_it_never_filed_is_a_failure_with_a_remedy(self) -> None:
        from maljan.agents.base_agent import _stored_answer_of

        tool = tac.read_evidence_tool(_stored_answer_of(self._recorder()))
        answer = json.loads(tool.invoke({"evidence_id": "ev_0099"}))
        assert answer["error"]["code"] == "bad_argument"
        assert answer["error"]["remediation"] == tac.UNKNOWN_EVIDENCE_REMEDIATION

    def test_it_is_sized_by_the_job_s_guardrail(self) -> None:
        from maljan.agents.base_agent import _stored_answer_of

        class _Sizer:
            def _apply_output_guardrail(self, text: str, narrowing: Any) -> str:
                return text[:5]

        tool = tac.read_evidence_tool(_stored_answer_of(self._recorder()), _Sizer())
        assert tool.invoke({"evidence_id": "ev_0001"}) == "the f"


# ---------------------------------------------------------------------------
# Through an analyst's tool loop
# ---------------------------------------------------------------------------


class _Thinker(BaseChatModel):
    """Calls ``lookup`` ``calls`` times, reasoning at length before each; records every request."""

    calls: int = 12
    reasoning: int = 1_000
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        sent = list(messages)
        tools = [t["function"]["name"] for t in kwargs.get("tools") or []]
        self.seen.append((sent, tools))
        made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
        if made < self.calls and isinstance(sent[-1], ToolMessage | HumanMessage):
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "lookup", "args": {"what": f"w{made}"}, "id": f"c{made}"}],
                additional_kwargs={"reasoning_content": "r" * self.reasoning},
            )
        else:
            turn = AIMessage(content=REPORT)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "thinker"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self.bind(tools=[convert_to_openai_tool(t) for t in tools])


class _What(BaseModel):
    what: str = ""


def _lookup(answer_chars: int) -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": "a" * answer_chars,
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


class _Container:
    def __init__(self, budget: Any) -> None:
        self.budget = budget
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


@contextlib.contextmanager
def _settings(clear_at: int | None) -> Iterator[None]:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = None
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = None
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 100
        cfg.react_agent_clear_tool_answers_at = clear_at
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _window(tokens: int, reply: int) -> cw.ContextBudget:
    return cw.ContextBudget(cw.WindowFact(tokens, cw.DECLARED, "test"), reply_tokens=reply)


def _run(
    budget: Any,
    *,
    clear_at: int | None = None,
    calls: int = 12,
    answer_chars: int = 6_000,
    reasoning: int = 1_000,
    no_clearing: bool = False,
) -> tuple[_Thinker, _Container]:
    model = _Thinker(seen=[], calls=calls, reasoning=reasoning)
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.clearing")
    agent.run_state_block = "sample: c"
    container = _Container(budget)
    agent._container = container
    agent.tools = [_lookup(answer_chars)]
    with contextlib.ExitStack() as stack:
        stack.enter_context(_settings(clear_at))
        if no_clearing:
            stack.enter_context(
                patch.object(BaseAnalyst, "_tool_answer_clearing", lambda self: None)
            )
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", TASK)])
    return model, container


def _requests(model: _Thinker) -> list[list[str]]:
    return [_wire(sent) for sent, _tools in model.seen]


class TestThroughTheLoop:
    def test_a_loop_that_fits_sends_what_it_always_sent(self) -> None:
        roomy = _window(1_000_000, 8_192)
        today, _ = _run(roomy, no_clearing=True)
        now, container = _run(roomy)
        assert _requests(now) == _requests(today)
        assert [tools for _s, tools in now.seen] == [tools for _s, tools in today.seen]
        assert all(tools == ["lookup"] for _s, tools in now.seen)
        assert not [e for e in container.events if e[0] == TOOL_ANSWERS_CLEARED]

    def test_a_loop_past_its_window_clears_and_every_request_fits(self) -> None:
        budget = _window(20_000, 5_000)
        point = (20_000 - 5_000) * cw.CHARS_PER_TOKEN
        today, _ = _run(budget, no_clearing=True)
        assert max(_size(sent) for sent, _t in today.seen) > point
        now, container = _run(budget)
        assert all(_size(sent) <= point for sent, _t in now.seen)
        cleared = [e[1] for e in container.events if e[0] == TOOL_ANSWERS_CLEARED]
        assert cleared and all(e["why"] == tac.CLEARED_FOR_WINDOW for e in cleared)
        assert all(e["chars_after"] < e["chars_before"] for e in cleared)
        # The read-again tool is offered from the first clear on, never before.
        offered = [tools for _s, tools in now.seen]
        first = next(i for i, tools in enumerate(offered) if tac.READ_EVIDENCE_TOOL in tools)
        assert all(tools == ["lookup"] for tools in offered[:first])
        assert all(tac.READ_EVIDENCE_TOOL in tools for tools in offered[first:])
        assert any(
            isinstance(m, ToolMessage) and str(m.content).startswith("[cleared ")
            for m in now.seen[first][0]
        )

    def test_the_operator_s_point_clears_where_the_window_would_not(self) -> None:
        roomy = _window(1_000_000, 8_192)
        now, container = _run(roomy, clear_at=15_000, calls=20, reasoning=100)
        cleared = [e[1] for e in container.events if e[0] == TOOL_ANSWERS_CLEARED]
        assert cleared and all(e["why"] == tac.CLEARED_FOR_SETTING for e in cleared)
        # Several turns between clears: the front holds across them.
        assert 2 <= len(cleared) < len(now.seen) // 3
        requests = _requests(now)
        holds = 0
        for earlier, later in zip(requests, requests[1:], strict=False):
            head = earlier[:-1]
            if later[: len(head)] == head:
                holds += 1
        assert holds >= len(requests) - 1 - len(cleared)

    def test_every_id_the_loop_was_shown_stays_readable_or_named(self) -> None:
        now, _ = _run(_window(1_000_000, 8_192), clear_at=8_000)
        last, _tools = now.seen[-1]
        shown = {m.content.split("]")[0][1:] for m in last if isinstance(m, ToolMessage)}
        named = set()
        for message in last:
            if isinstance(message, ToolMessage):
                named.update(tac.entry_ids_of(str(message.content)))
        assert {f"ev_{n:04d}" for n in range(1, 13)} <= named | shown


def test_the_clearing_point_derives_from_the_window_less_the_output_cap() -> None:
    model = _Thinker(seen=[])
    agent = _Analyst(llm=model, name="static")
    agent._container = _Container(_window(100_000, 10_000))
    cw.record_built_cap(model, cw.OutputCap(30_000, "test"))
    with _settings(None):
        clearing = agent._tool_answer_clearing()
    assert clearing is not None
    assert clearing.window_chars == (100_000 - 30_000) * cw.CHARS_PER_TOKEN
    assert clearing.setting_chars is None


def test_an_unknown_window_and_no_setting_clear_nothing() -> None:
    agent = _Analyst(llm=_Thinker(seen=[]), name="static")
    agent._container = _Container(cw.ContextBudget(cw.unknown_window()))
    with _settings(None):
        assert agent._tool_answer_clearing() is None
    with _settings(50_000):
        clearing = agent._tool_answer_clearing()
    assert clearing is not None and clearing.window_chars is None
    assert clearing.setting_chars == 50_000 * cw.CHARS_PER_TOKEN


class _Rereader(_Thinker):
    """A thinker that reads the first cleared answer again once it sees one."""

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        sent = list(messages)
        asked = any(
            isinstance(m, AIMessage)
            and any(c["name"] == tac.READ_EVIDENCE_TOOL for c in m.tool_calls)
            for m in sent
        )
        cleared = [
            str(m.content)
            for m in sent
            if isinstance(m, ToolMessage) and str(m.content).startswith("[cleared ")
        ]
        if cleared and not asked:
            wanted = cleared[0][len("[cleared ") :].split("]")[0].split(",")[0]
            self.seen.append((sent, [t["function"]["name"] for t in kwargs.get("tools") or []]))
            turn = AIMessage(
                content="",
                tool_calls=[
                    {"name": tac.READ_EVIDENCE_TOOL, "args": {"evidence_id": wanted}, "id": "again"}
                ],
            )
            return ChatResult(generations=[ChatGeneration(message=turn)])
        return super()._generate(messages, stop, run_manager, **kwargs)


def test_the_model_reads_a_cleared_answer_again_through_the_loop() -> None:
    model = _Rereader(seen=[], calls=8, reasoning=100)
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.clearing")
    agent._container = _Container(_window(1_000_000, 8_192))
    agent.tools = [
        StructuredTool.from_function(
            func=lambda what="": f"answer {what} " + "a" * 6_000,
            name="lookup",
            description="Look it up.",
            args_schema=_What,
        )
    ]
    with _settings(8_000):
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", TASK)])
    # The request right after the read, where its answer is the newest.
    last = next(
        sent
        for sent, _tools in model.seen
        if isinstance(sent[-1], ToolMessage) and sent[-1].tool_call_id == "again"
    )
    again = last[-1]
    first_cleared = next(
        str(m.content) for m in last if isinstance(m, ToolMessage) and "[cleared " in str(m.content)
    )
    wanted = first_cleared[len("[cleared ") :].split("]")[0].split(",")[0]
    entry = next(e for e in agent._evidence_entries if e.id == wanted)
    # The stored output, filed and fenced like any tool answer under an id of its own.
    assert str(again.content).startswith("[ev_")
    assert entry.output in str(again.content)
    reread = next(e for e in agent._evidence_entries if e.tool == tac.READ_EVIDENCE_TOOL)
    assert reread.args == {"evidence_id": wanted}


def test_the_reported_count_names_its_turn() -> None:
    turn = AIMessage(
        content="x", usage_metadata={"input_tokens": 10, "output_tokens": 1, "total_tokens": 11}
    )
    chars, index = _reported_request([HumanMessage(content="t"), turn], 3)
    assert index == 1 and chars == 30 + 1
