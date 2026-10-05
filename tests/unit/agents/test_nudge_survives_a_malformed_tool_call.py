"""The final-answer nudge survives a transcript the server cannot render.

Live run, static analyst: the loop ended on an assistant turn whose tool call
carried arguments that never parsed (a runaway regular expression), so no
tool ran and the loop stopped. The nudge sent that turn back as it was, and
the server answered 500 — "Failed to parse tool call arguments as JSON" —
because rendering the template means rendering that call. Two rules are
pinned: the nudge leaves such a call out and says so in the run summary, and
when the plain request still fails it asks once more with the loop's tools
bound and forbidden, the one other shape the server accepts.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents.base_agent import FINAL_ANSWER_NUDGE, BaseAnalyst, nudge_turns

_REPORT = (
    "CLAIM: it resolves imports at runtime\nEVIDENCE: ev_0002\nCONFIDENCE: 0.7\nTECHNIQUE: T1027\n"
)
_BAD_ARGS = '{"pattern": "http|https|www|com|net|org|key|software'


def _malformed_turn() -> AIMessage:
    return AIMessage(
        content="Let me search the strings.",
        invalid_tool_calls=[
            {"name": "strings", "args": _BAD_ARGS, "id": "call_9", "error": "unterminated"}
        ],
    )


def _conversation() -> list[Any]:
    return [
        SystemMessage(content="You are a static analyst."),
        HumanMessage(content="Analyse this binary."),
        AIMessage(
            content="",
            tool_calls=[{"name": "identify_file", "args": {"path": "/s"}, "id": "call_1"}],
        ),
        ToolMessage(content='[ev_0002]\n{"file_type": "pe"}', tool_call_id="call_1"),
        _malformed_turn(),
    ]


def _has_invalid(messages: list[Any]) -> bool:
    return any(getattr(m, "invalid_tool_calls", None) for m in messages)


class _StrictServer:
    """Answers unless the transcript carries a tool call it cannot render."""

    def __init__(self) -> None:
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.seen.append(list(messages))
        if _has_invalid(messages):
            raise RuntimeError(
                "Error code: 500 - Failed to parse tool call arguments as JSON: parse error"
            )
        return AIMessage(content=_REPORT)


class _RefusesBare(_StrictServer):
    """Fails the plain request every time; answers once the tools are bound."""

    def __init__(self) -> None:
        super().__init__()
        self.bound_with: list[tuple[list[Any], Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.seen.append(list(messages))
        raise RuntimeError("Error code: 500 - template failure")

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> Any:
        self.bound_with.append((list(tools), kwargs))
        outer = self

        class _Bound:
            async def ainvoke(self, messages: list[Any]) -> AIMessage:
                outer.seen.append(list(messages))
                return AIMessage(content=_REPORT)

        return _Bound()


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any, tools: list[Any] | None = None) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.nudge")
        self.llm = llm
        self.tools = tools or []
        self.token_ledger = None
        self._answer_unstructured = False
        self._nudge_retry_mode = None

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestTheTranscriptTheNudgeSends:
    def test_a_tool_call_whose_arguments_never_parsed_is_left_out(self) -> None:
        turns, changed = nudge_turns(_conversation())
        assert changed is True
        assert not _has_invalid(turns)
        # The turn's own words stay; only the call it could not make goes.
        assert turns[-1].content == "Let me search the strings."
        assert turns[-1].tool_calls == []

    def test_a_turn_that_was_nothing_but_the_bad_call_is_left_out(self) -> None:
        empty = AIMessage(
            content="",
            invalid_tool_calls=[{"name": "strings", "args": "{", "id": "bad", "error": "x"}],
        )
        turns, changed = nudge_turns([SystemMessage(content="s"), empty])
        assert changed is True
        assert [type(m).__name__ for m in turns] == ["SystemMessage"]

    def test_a_clean_transcript_is_sent_as_it_is(self) -> None:
        clean = _conversation()[:4]
        turns, changed = nudge_turns(clean)
        assert changed is False
        assert turns == clean

    def test_a_turn_with_a_good_and_a_bad_call_keeps_the_good_one(self) -> None:
        mixed = AIMessage(
            content="",
            tool_calls=[{"name": "hashes", "args": {"path": "/s"}, "id": "ok"}],
            invalid_tool_calls=[{"name": "strings", "args": "{", "id": "bad", "error": "x"}],
        )
        (turn,), _ = nudge_turns([mixed])
        assert [c["id"] for c in turn.tool_calls] == ["ok"]
        assert not turn.invalid_tool_calls


class TestTheNudgeAgainstAStrictServer:
    def test_the_report_comes_back_and_the_summary_learns_how(self) -> None:
        server = _StrictServer()
        agent = _Analyst(server)
        answer = agent._nudge_for_final_answer(_conversation(), timeout=60, elapsed=0, max_steps=40)
        assert answer == _REPORT
        assert len(server.seen) == 1
        assert not _has_invalid(server.seen[0])
        assert server.seen[0][-1].content == FINAL_ANSWER_NUDGE
        assert agent._nudge_retry_mode == "invalid_tool_calls_dropped"

    def test_a_clean_transcript_records_no_retry_mode(self) -> None:
        server = _StrictServer()
        agent = _Analyst(server)
        agent._nudge_for_final_answer(_conversation()[:4], timeout=60, elapsed=0, max_steps=40)
        assert agent._nudge_retry_mode is None

    def test_when_the_plain_request_fails_the_tools_are_bound_and_withheld(self) -> None:
        server = _RefusesBare()
        agent = _Analyst(server, tools=[object()])
        answer = agent._nudge_for_final_answer(
            _conversation()[:4], timeout=60, elapsed=0, max_steps=40
        )
        assert answer == _REPORT
        assert len(server.seen) == 2
        assert server.bound_with[0][1] == {"tool_choice": "none"}
        assert agent._nudge_retry_mode == "tool_choice_none"

    def test_both_repairs_are_named_when_both_were_needed(self) -> None:
        server = _RefusesBare()
        agent = _Analyst(server, tools=[object()])
        agent._nudge_for_final_answer(_conversation(), timeout=60, elapsed=0, max_steps=40)
        assert agent._nudge_retry_mode == "invalid_tool_calls_dropped+tool_choice_none"

    def test_without_tools_a_failing_nudge_changes_nothing(self) -> None:
        server = _RefusesBare()
        agent = _Analyst(server)
        answer = agent._nudge_for_final_answer(
            _conversation()[:4], timeout=60, elapsed=0, max_steps=40
        )
        assert answer is None
        assert len(server.seen) == 1
        assert agent._nudge_retry_mode is None


class TestForcedSynthesisFollowsTheSameRule:
    def test_the_salvage_is_not_sent_the_call_that_never_parsed(self) -> None:
        agent = _Analyst(_StrictServer())
        sent: list[list[Any]] = []

        def _capture(messages: list[Any], timeout: int, **_: Any) -> str:
            sent.append(list(messages))
            return _REPORT

        agent._invoke_llm_with_timeout = _capture  # type: ignore[method-assign]
        agent.truncation_ledger = None
        text = agent._force_final_synthesis(_conversation(), timeout=600, elapsed=0.0)
        assert text == _REPORT
        assert sent and not _has_invalid(sent[0])
