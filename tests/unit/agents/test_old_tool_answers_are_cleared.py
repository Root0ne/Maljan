"""A long tool loop clears its oldest tool answers to ledger references, in batches.

Three things clear: a provider refusing a request as over its window (the turn
is then sent again), a prompt alone past the agent's own model window, and the
operator's ``react_agent_clear_tool_answers_at``, off by default. A clear takes
the oldest answers down to what no clear can take plus half of the room above
it, and keeps them cleared under the same text, so the request's front is the
same from one clear to the next. The newest turn's answers, the framing and the
agent's own turns (its reasoning included) are never cleared; a reference
names the id the recorder stamped and the tool that reads it again, which the
loop offers — and names anywhere — from its first clear on. Without a clear the
loop sends, byte for byte, what ``origin/dev`` sends.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import openai
import pytest
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

from .no_tool_call_scenario import requests as no_tool_call_requests

REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
TASK = "Analyse the sample."
GOLDEN = (
    Path(__file__).resolve().parents[2] / "fixtures" / "clearing" / "no_tool_call_requests_dev.json"
)


# ---------------------------------------------------------------------------
# The clearing itself, over a conversation built by hand
# ---------------------------------------------------------------------------


def _conversation(turns: int, answer_chars: int, reasoning: int = 0) -> list[Any]:
    """A system turn, the task, then ``turns`` model turns each with two stamped answers."""
    out: list[Any] = [SystemMessage(content="s" * 500), HumanMessage(content=TASK)]
    entry = 0
    for turn in range(turns):
        calls = [
            {"name": "lookup", "args": {"n": turn * 2 + slot}, "id": f"c{turn}_{slot}"}
            for slot in range(2)
        ]
        kwargs = {"reasoning_content": "r" * reasoning} if reasoning else {}
        out.append(AIMessage(content="", tool_calls=calls, additional_kwargs=kwargs))
        for call in calls:
            entry += 1
            out.append(
                ToolMessage(
                    content=f"[ev_{entry:04d}]\n" + "a" * answer_chars, tool_call_id=call["id"]
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


def _fixed(messages: list[Any]) -> int:
    """What no clear can take: the size with every clearable answer cleared."""
    probe = tac.ToolAnswerClearing(window_chars=1)
    return _size(_fit(probe, messages).messages)


def _wire(messages: list[Any]) -> list[str]:
    return [json.dumps(m, sort_keys=True) for m in convert_to_openai_messages(messages)]


class TestNoClear:
    def test_a_request_under_every_point_is_the_same_messages(self) -> None:
        messages = _conversation(4, 1_000)
        clearing = tac.ToolAnswerClearing(window_chars=_size(messages) + 1)
        fitted = _fit(clearing, messages)
        assert fitted.clearing is None
        assert all(a is b for a, b in zip(fitted.messages, messages, strict=True))

    def test_no_point_and_no_refusal_is_the_same_messages(self) -> None:
        messages = _conversation(4, 1_000)
        fitted = _fit(tac.ToolAnswerClearing(), messages)
        assert fitted.clearing is None and _wire(fitted.messages) == _wire(messages)

    def test_the_server_s_count_under_the_point_wins_over_a_larger_measure(self) -> None:
        messages = _conversation(4, 4_000)
        last_turn = max(i for i, m in enumerate(messages) if isinstance(m, AIMessage))
        clearing = tac.ToolAnswerClearing(window_chars=_size(messages) // 2)
        fitted = clearing.fit(
            messages,
            extra_chars=0,
            measure=_message_chars,
            reported=lambda _sent: (_size(messages) // 3, last_turn),
            turn=5,
        )
        assert fitted.clearing is None and _wire(fitted.messages) == _wire(messages)


class TestAPromptPastTheWindow:
    def test_the_oldest_go_to_half_the_clearable_room_and_the_newest_turn_stays(self) -> None:
        messages = _conversation(6, 5_000)
        point = _size(messages) - 10_000
        fixed = _fixed(messages)
        fitted = _fit(tac.ToolAnswerClearing(window_chars=point), messages)
        assert fitted.clearing is not None
        assert fitted.clearing.why == tac.CLEARED_FOR_WINDOW
        assert fitted.clearing.target_chars == fixed + (point - fixed) // 2
        assert _size(fitted.messages) <= fitted.clearing.target_chars
        tools = [m for m in fitted.messages if isinstance(m, ToolMessage)]
        cleared = [m for m in tools if str(m.content).startswith("[cleared ")]
        # Oldest first, in order, and the newest turn's two answers untouched.
        assert tools[: len(cleared)] == cleared
        assert all(m is n for m, n in zip(tools[-2:], messages[-2:], strict=True))

    def test_a_reference_names_the_stamp_only_never_an_id_the_tool_wrote(self) -> None:
        messages = _conversation(3, 5_000)
        messages[3] = ToolMessage(
            content="[ev_0001]\n" + "a" * 5_000 + "\nthe string table holds ev_0042",
            tool_call_id="c0_0",
        )
        fitted = _fit(tac.ToolAnswerClearing(window_chars=1), messages)
        reference = str(fitted.messages[3].content)
        assert reference.startswith("[cleared ev_0001]")
        assert "ev_0042" not in reference
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

    def test_an_answer_without_the_recorder_s_stamp_is_never_cleared(self) -> None:
        messages = _conversation(3, 4_000)
        messages[3] = ToolMessage(content="b" * 2_000 + "[ev_0009]\n", tool_call_id="c0_0")
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
        assert fitted.clearing.chars_after <= fitted.clearing.target_chars


class TestARefusal:
    def test_a_refusal_clears_half_the_clearable_room_under_every_point(self) -> None:
        messages = _conversation(6, 4_000)
        clearing = tac.ToolAnswerClearing()
        assert clearing.refused(messages, _message_chars)
        fitted = _fit(clearing, messages)
        assert fitted.clearing is not None and fitted.clearing.why == tac.CLEARED_FOR_REFUSAL
        fixed = _fixed(messages)
        assert fitted.clearing.target_chars == fixed + (_size(messages) - fixed) // 2
        # Armed once: the next request clears nothing more.
        assert _fit(clearing, messages).clearing is None

    def test_a_refusal_with_nothing_left_to_clear_is_not_armed(self) -> None:
        messages = _conversation(1, 4_000)
        assert not tac.ToolAnswerClearing().refused(messages, _message_chars)


class TestTheOperatorsPoint:
    def test_batches_to_half_the_clearable_room_and_the_front_holds_between(self) -> None:
        messages = _conversation(8, 2_000)
        point = _size(messages) - 1
        clearing = tac.ToolAnswerClearing(window_chars=10 * point, setting_chars=point)
        first = _fit(clearing, messages)
        assert first.clearing is not None and first.clearing.why == tac.CLEARED_FOR_SETTING
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
        assert 1 < clears < 20 // 2

    def test_a_large_fixed_part_still_clears_in_batches(self) -> None:
        """Most of the request is what no clear can take: clears still come turns apart."""
        messages = _conversation(8, 2_000, reasoning=3_000)
        point = _size(messages) - 1
        clearing = tac.ToolAnswerClearing(setting_chars=point)
        grown = list(messages)
        clears = int(_fit(clearing, grown).clearing is not None)
        turns = 0
        for turn in range(30):
            call = {"name": "lookup", "args": {"n": 100 + turn}, "id": f"late{turn}"}
            grown.append(AIMessage(content="", tool_calls=[call]))
            grown.append(
                ToolMessage(
                    content=f"[ev_{200 + turn:04d}]\n" + "a" * 2_000, tool_call_id=call["id"]
                )
            )
            fitted = _fit(clearing, grown)
            turns += 1
            if fitted.clearing is not None:
                clears += 1
            elif fitted.setting_unreachable is not None:
                break
        assert clears < turns

    def test_a_setting_below_what_no_clear_can_take_does_not_clear_and_says_so_once(
        self,
    ) -> None:
        messages = _conversation(4, 2_000, reasoning=20_000)
        fixed = _fixed(messages)
        clearing = tac.ToolAnswerClearing(setting_chars=fixed - 1)
        first = _fit(clearing, messages)
        assert first.clearing is None
        assert first.setting_unreachable == (fixed, fixed - 1)
        again = _fit(clearing, messages)
        assert again.clearing is None and again.setting_unreachable is None
        assert _wire(first.messages) == _wire(messages)


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

    def test_ten_times_the_ids_in_one_answer_takes_about_ten_times_as_long(self) -> None:
        def hostile(ids: int) -> list[Any]:
            messages = _conversation(3, 10)
            body = "".join(f" ev_{n:05d}" for n in range(ids))
            messages[3] = ToolMessage(content="[ev_0001]\n" + body, tool_call_id="c0_0")
            return messages

        def timed(ids: int) -> float:
            messages = hostile(ids)
            began = time.perf_counter()
            for _ in range(5):
                _fit(tac.ToolAnswerClearing(setting_chars=1), messages)
            return time.perf_counter() - began

        timed(2_000)
        small = min(timed(2_000) for _ in range(3))
        large = min(timed(20_000) for _ in range(3))
        assert large < small * 20
        reference = str(
            _fit(tac.ToolAnswerClearing(window_chars=1), hostile(500)).messages[3].content
        )
        assert reference.startswith("[cleared ev_0001]") and "ev_00002" not in reference


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
        assert answer["error"]["message"] == tac.unknown_evidence_message("ev_0099")
        assert answer["error"]["remediation"] == tac.UNKNOWN_EVIDENCE_REMEDIATION

    def test_it_is_sized_by_the_job_s_guardrail(self) -> None:
        from maljan.agents.base_agent import _stored_answer_of

        class _Sizer:
            def _apply_output_guardrail(self, text: str, narrowing: Any) -> str:
                return text[:5]

        tool = tac.read_evidence_tool(_stored_answer_of(self._recorder()), _Sizer())
        assert tool.invoke({"evidence_id": "ev_0001"}) == "the f"

    def test_the_recorder_files_a_read_as_a_repeat_served_under_the_original_id(self) -> None:
        from maljan.agents.base_agent import _stored_answer_of
        from maljan.agents.evidence_recorder import record_tools

        class _Corpus:
            def __init__(self) -> None:
                self.kept: list[str] = []

            def remember(self, entry_id: str, tool: str, text: str) -> None:
                self.kept.append(entry_id)

        corpus = _Corpus()
        recorder = EvidenceRecorder("static", corpus=corpus)
        recorder.record(tool="lookup", args={"n": 1}, server=None, output="the first answer")
        (read,) = record_tools([tac.read_evidence_tool(_stored_answer_of(recorder))], recorder)
        shown = read.invoke({"evidence_id": "ev_0001"})
        assert shown.startswith("[ev_0001]\n") and "the first answer" in shown
        filed = recorder.entries[-1]
        assert filed.tool == tac.READ_EVIDENCE_TOOL and filed.repeated_of == "ev_0001"
        assert filed.output == tac.read_again_note("ev_0001")
        # The corpus holds the answer once, under the original id.
        assert corpus.kept == ["ev_0001"]


# ---------------------------------------------------------------------------
# Through an analyst's tool loop
# ---------------------------------------------------------------------------


def _over_the_window(limit: int) -> openai.BadRequestError:
    request = httpx.Request("POST", "https://api.example.invalid/v1/chat/completions")
    message = (
        f"This model's maximum context length is {limit} tokens. However, your messages "
        "resulted in more tokens."
    )
    return openai.BadRequestError(message, response=httpx.Response(400, request=request), body=None)


class _Thinker(BaseChatModel):
    """Calls ``lookup`` ``calls`` times, reasoning at length before each; records every request.

    With ``refuse_over`` set, a request whose messages weigh more than that
    many characters is refused as a provider refuses one over its window.
    """

    calls: int = 12
    reasoning: int = 1_000
    refuse_over: int = 0
    seen: list = []
    refused: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        sent = list(messages)
        tools = [t["function"]["name"] for t in kwargs.get("tools") or []]
        if self.refuse_over and _size(sent) > self.refuse_over:
            self.refused.append(_size(sent))
            raise _over_the_window(self.refuse_over)
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
        func=lambda what="": f"answer {what} " + "a" * answer_chars,
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


def _window(tokens: int, reply: int = 8_192) -> cw.ContextBudget:
    return cw.ContextBudget(cw.WindowFact(tokens, cw.DECLARED, "test"), reply_tokens=reply)


def _run(
    budget: Any,
    *,
    clear_at: int | None = None,
    calls: int = 12,
    answer_chars: int = 6_000,
    reasoning: int = 1_000,
    own_window: int | None = None,
    own_cap: int | None = None,
    refuse_over: int = 0,
    no_clearing: bool = False,
) -> tuple[_Thinker, _Container, _Analyst, str]:
    model = _Thinker(seen=[], refused=[], calls=calls, reasoning=reasoning, refuse_over=refuse_over)
    if own_window is not None:
        cw.record_built_window(model, cw.WindowFact(own_window, cw.DECLARED, "test"))
    if own_cap is not None:
        cw.record_built_cap(model, cw.OutputCap(own_cap, "test"))
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
                patch.object(
                    BaseAnalyst,
                    "_tool_answer_clearing",
                    lambda self: None,
                )
            )
        answer = agent.execute_tool_loop([("system", "You are a static analyst."), ("human", TASK)])
    return model, container, agent, answer


def _requests(model: _Thinker) -> list[list[str]]:
    return [_wire(sent) for sent, _tools in model.seen]


def _cleared_events(container: _Container) -> list[dict[str, Any]]:
    return [e[1] for e in container.events if e[0] == TOOL_ANSWERS_CLEARED]


class TestWithoutAClearTheLoopIsDev:
    def test_the_no_tool_call_question_and_every_request_are_dev_s_byte_for_byte(self) -> None:
        """A golden ``origin/dev`` wrote (``no_tool_call_scenario``), not this branch."""
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        now = json.loads(json.dumps(no_tool_call_requests(), sort_keys=True))
        assert now == golden
        asked = [r for r in golden if "The tools you have in this loop are" in json.dumps(r)]
        assert asked, "the golden must take the no-tool-call question's path"
        assert tac.READ_EVIDENCE_TOOL not in json.dumps(now)

    def test_a_loop_that_fits_sends_what_it_sends_with_clearing_off(self) -> None:
        roomy = _window(1_000_000)
        today, _, _, _ = _run(roomy, no_clearing=True)
        now, container, _, _ = _run(roomy, own_window=1_000_000)
        assert _requests(now) == _requests(today)
        assert all(tools == ["lookup"] for _s, tools in now.seen)
        assert not _cleared_events(container)

    def test_a_prompt_between_the_window_less_the_cap_and_the_window_is_not_cleared(
        self,
    ) -> None:
        """Servers accept it (Anthropic stops at the window; others refuse only a longer prompt)."""
        today, _, _, _ = _run(_window(1_000_000), no_clearing=True)
        largest = max(_size(sent) for sent, _t in today.seen) // cw.CHARS_PER_TOKEN
        window, cap = largest + 1_000, 20_000
        assert window - cap < largest < window
        now, container, _, _ = _run(_window(1_000_000), own_window=window, own_cap=cap)
        assert not _cleared_events(container)
        assert _requests(now) == _requests(today)


class TestThroughTheLoop:
    def test_a_refused_request_is_cleared_and_sent_again(self) -> None:
        limit = 50_000
        today, _, _, answer_today = _run(_window(1_000_000), refuse_over=limit, no_clearing=True)
        assert today.refused and answer_today != REPORT.strip()
        now, container, _, answer = _run(_window(1_000_000), refuse_over=limit)
        assert answer.strip().startswith("CLAIM:")
        assert all(_size(sent) <= limit for sent, _t in now.seen)
        cleared = _cleared_events(container)
        assert cleared and all(e["why"] == tac.CLEARED_FOR_REFUSAL for e in cleared)
        assert len(now.refused) <= len(cleared)
        # The read-again tool is offered from the first clear on, never before.
        offered = [tools for _s, tools in now.seen]
        first = next(i for i, tools in enumerate(offered) if tac.READ_EVIDENCE_TOOL in tools)
        assert all(tools == ["lookup"] for tools in offered[:first])
        assert all(tac.READ_EVIDENCE_TOOL in tools for tools in offered[first:])

    def test_a_refusal_with_nothing_to_clear_is_handled_as_today(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 — the provider's own error, as today
            _run(_window(1_000_000), refuse_over=10)

    def test_a_prompt_past_the_agent_s_own_window_is_cleared_before_it_is_sent(self) -> None:
        # The job's window is smaller than the agent's own: only the agent's counts.
        today, _, _, _ = _run(_window(1_000_000), no_clearing=True)
        own = max(_size(sent) for sent, _t in today.seen) // cw.CHARS_PER_TOKEN - 3_000
        now, container, _, _ = _run(_window(own // 2), own_window=own)
        assert all(_size(sent) <= own * cw.CHARS_PER_TOKEN for sent, _t in now.seen)
        cleared = _cleared_events(container)
        assert cleared and all(e["why"] == tac.CLEARED_FOR_WINDOW for e in cleared)

    def test_the_operator_s_point_clears_in_batches_and_the_front_holds(self) -> None:
        now, container, _, _ = _run(_window(1_000_000), clear_at=15_000, calls=20, reasoning=100)
        cleared = _cleared_events(container)
        assert cleared and all(e["why"] == tac.CLEARED_FOR_SETTING for e in cleared)
        assert 2 <= len(cleared) < len(now.seen) // 3
        requests = _requests(now)
        holds = sum(
            1
            for earlier, later in zip(requests, requests[1:], strict=False)
            if later[: len(earlier) - 1] == earlier[:-1]
        )
        assert holds >= len(requests) - 1 - len(cleared)

    def test_every_id_the_loop_was_shown_stays_readable_or_named(self) -> None:
        now, _, _, _ = _run(_window(1_000_000), clear_at=8_000, reasoning=100)
        last, _tools = now.seen[-1]
        named = {
            tac.stamp_of(str(m.content)) or str(m.content)[len("[cleared ") :].split("]")[0]
            for m in last
            if isinstance(m, ToolMessage)
        }
        assert {f"ev_{n:04d}" for n in range(1, 13)} <= named


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
            wanted = cleared[0][len("[cleared ") :].split("]")[0]
            self.seen.append((sent, [t["function"]["name"] for t in kwargs.get("tools") or []]))
            turn = AIMessage(
                content="",
                tool_calls=[
                    {"name": tac.READ_EVIDENCE_TOOL, "args": {"evidence_id": wanted}, "id": "again"}
                ],
            )
            return ChatResult(generations=[ChatGeneration(message=turn)])
        return super()._generate(messages, stop, run_manager, **kwargs)


def test_the_model_reads_a_cleared_answer_again_under_its_own_id() -> None:
    model = _Rereader(seen=[], refused=[], calls=8, reasoning=100)
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.clearing")
    agent._container = _Container(_window(1_000_000))
    agent.tools = [_lookup(6_000)]
    with _settings(8_000):
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", TASK)])
    last = next(
        sent
        for sent, _tools in model.seen
        if isinstance(sent[-1], ToolMessage) and sent[-1].tool_call_id == "again"
    )
    again = last[-1]
    first_cleared = next(
        str(m.content) for m in last if isinstance(m, ToolMessage) and "[cleared " in str(m.content)
    )
    wanted = first_cleared[len("[cleared ") :].split("]")[0]
    entry = next(e for e in agent._evidence_entries if e.id == wanted)
    # The stored output, under the original id: no second citable id.
    assert str(again.content).startswith(f"[{wanted}]\n")
    assert entry.output in str(again.content)
    reread = next(e for e in agent._evidence_entries if e.tool == tac.READ_EVIDENCE_TOOL)
    assert reread.args == {"evidence_id": wanted} and reread.repeated_of == wanted


def test_the_window_point_is_the_agent_s_own_window_never_the_job_s() -> None:
    model = _Thinker(seen=[], refused=[])
    agent = _Analyst(llm=model, name="static")
    agent._container = _Container(_window(50_000))
    cw.record_built_window(model, cw.WindowFact(100_000, cw.PROBED, "test"))
    with _settings(None):
        clearing = agent._tool_answer_clearing()
    assert clearing.window_chars == 100_000 * cw.CHARS_PER_TOKEN
    assert clearing.setting_chars is None


def test_an_unknown_own_window_gives_no_window_point() -> None:
    agent = _Analyst(llm=_Thinker(seen=[], refused=[]), name="static")
    agent._container = _Container(cw.ContextBudget(cw.unknown_window()))
    with _settings(50_000), patch.object(BaseAnalyst, "_own_window_tokens", lambda self: None):
        clearing = agent._tool_answer_clearing()
    assert clearing.window_chars is None
    assert clearing.setting_chars == 50_000 * cw.CHARS_PER_TOKEN


def test_the_reported_count_names_its_turn() -> None:
    turn = AIMessage(
        content="x", usage_metadata={"input_tokens": 10, "output_tokens": 1, "total_tokens": 11}
    )
    chars, index = _reported_request([HumanMessage(content="t"), turn], 3)
    assert index == 1 and chars == 30 + 1
