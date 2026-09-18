"""The places that produce the live conversation, driven rather than described.

The schema test pins what an event looks like. This one pins that the code
paths a run actually takes emit them: a wrapped tool, a refused repeat, a
correction turn, a delegated ask.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from maljan.pipeline.validation import Violation, retry_with_feedback, retry_with_feedback_sync
from maljan.schemas.evidence import EvidenceCounter


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def of(self, event_type: str) -> list[dict[str, Any]]:
        return [data for name, data in self.events if name == event_type]


def _recorder(sink: _Sink | None = None, *, stage: str = "analysis") -> EvidenceRecorder:
    return EvidenceRecorder(
        "static",
        counter=EvidenceCounter(),
        stage=stage,
        sink=sink,  # type: ignore[arg-type]
    )


def _tool(func: Any, name: str) -> Any:
    return StructuredTool.from_function(func=func, name=name)


class TestTheRecorderFeedsTheConversation:
    def test_a_call_is_announced_and_then_answered(self) -> None:
        sink = _Sink()
        recorder = _recorder(sink)

        def identify_file(path: str = "/home/op/samples/ab12/evil.exe") -> str:
            """Name the format of one file."""
            return "PE32 executable"

        record_tools([_tool(identify_file, "identify_file")], recorder)[0].invoke(
            {"path": "/home/op/samples/ab12/evil.exe"}
        )

        assert [name for name, _ in sink.events] == ["tool_call_started", "tool_call_finished"]
        started, finished = sink.of("tool_call_started")[0], sink.of("tool_call_finished")[0]
        assert started["tool"] == "identify_file"
        assert started["agent"] == "static"
        assert started["stage"] == "analysis"
        # The host path never leaves; the file name does.
        assert "/home/op" not in started["args_summary"]
        assert started["args_summary"] == "path=evil.exe"
        assert finished["evidence_id"] == recorder.entries[0].id
        assert finished["ok"] is True
        assert finished["summary"] == "PE32 executable"

    def test_a_failing_call_says_it_failed_without_its_error_text(self) -> None:
        sink = _Sink()
        recorder = _recorder(sink)

        def broken(path: str = "/etc/maljan/secrets.env") -> str:
            """Fail the way an unreachable sidecar fails."""
            raise RuntimeError("cannot read /etc/maljan/secrets.env")

        record_tools([_tool(broken, "broken")], recorder)[0].invoke({"path": "/x"})

        finished = sink.of("tool_call_finished")[0]
        assert finished["ok"] is False
        assert "/etc/maljan" not in finished["summary"]
        assert "RuntimeError" not in finished["summary"]

    def test_a_refused_repeat_announces_nothing(self) -> None:
        """No tool runs, so there is no call to draw: the notice is a message
        to the model, and a start with no finish would leave the console
        holding a bubble open for a call that never happened."""
        sink = _Sink()
        recorder = _recorder(sink)

        def probe(path: str = "/x") -> str:
            """Answer the same thing every time."""
            return "answer"

        wrapped = record_tools([_tool(probe, "probe")], recorder, RepeatGuard())[0]
        for _ in range(3):
            wrapped.invoke({"path": "/x"})

        assert len(sink.of("tool_call_started")) == 2
        assert len(sink.of("tool_call_finished")) == 2

    def test_a_recorder_without_a_sink_is_silent_and_still_records(self) -> None:
        recorder = _recorder(None)

        def probe() -> str:
            """Answer once."""
            return "answer"

        record_tools([_tool(probe, "probe")], recorder)[0].invoke({})
        assert len(recorder.entries) == 1

    def test_the_stage_on_the_recorder_is_the_stage_on_the_events(self) -> None:
        sink = _Sink()
        recorder = _recorder(sink, stage="triage_pack")
        recorder.record(tool="pe_info", args={}, server=None, output="{}")
        assert sink.of("tool_call_finished")[0]["stage"] == "triage_pack"


class TestValidationFeedbackReachesTheConversation:
    def _violations(self) -> list[Violation]:
        return [Violation(code="technique_unknown", message="T9999 is not in the catalogue")]

    def test_the_sync_loop_publishes_one_event_per_violation_shown(self) -> None:
        sink = _Sink()
        answers = iter(["first", "second"])

        def run(_turns: list[Any]) -> Any:
            return next(answers)

        seen = {"count": 0}

        def validator(_parsed: Any) -> list[Violation]:
            seen["count"] += 1
            return self._violations() if seen["count"] == 1 else []

        retry_with_feedback_sync(
            run,
            ["turn"],
            [validator],
            parse=lambda a: a,
            sink=sink,  # type: ignore[arg-type]
            agent="static",
            stage="analysis",
        )
        shown, outcome = sink.of("validation_feedback")
        assert shown["code"] == "technique_unknown"
        assert shown["agent"] == "static"
        assert shown["stage"] == "analysis"
        assert shown["retry_index"] == 1
        assert shown["state"] == "retried"
        # And what became of it, which nothing used to publish.
        assert outcome["code"] == "technique_unknown"
        assert outcome["state"] == "resolved"

    def test_a_loop_with_nobody_to_tell_publishes_nothing(self) -> None:
        answers = iter(["first", "second"])
        seen = {"count": 0}

        def validator(_parsed: Any) -> list[Violation]:
            seen["count"] += 1
            return self._violations() if seen["count"] == 1 else []

        # No sink at all: the CLI and the report composer take this path and
        # must not need one.
        retry_with_feedback_sync(
            lambda _turns: next(answers), ["turn"], [validator], parse=lambda a: a
        )

    def test_the_async_loop_publishes_the_same_thing(self) -> None:
        sink = _Sink()
        answers = iter(["first", "second"])
        seen = {"count": 0}

        async def run(_turns: list[Any]) -> Any:
            return next(answers)

        def validator(_parsed: Any) -> list[Violation]:
            seen["count"] += 1
            return self._violations() if seen["count"] == 1 else []

        asyncio.run(
            retry_with_feedback(
                run,
                ["turn"],
                [validator],
                parse=lambda a: a,
                sink=sink,  # type: ignore[arg-type]
                agent="judge",
                stage="verdict",
            )
        )
        assert sink.of("validation_feedback")[0]["agent"] == "judge"


class TestEveryViolationSaysWhatBecameOfIt:
    """A reader of the conversation sees every violation the run recorded.

    Only the batch that triggered a retry used to be published: the ones that
    survived it and the ones the retry introduced were in the run summary and
    nowhere a reader could watch. One run showed two corrections in the feed
    beside a summary recording ten unresolved findings.
    """

    @staticmethod
    def _rows(sink: _Sink) -> list[tuple[str, str]]:
        return [(row["code"], row["state"]) for row in sink.of("validation_feedback")]

    @staticmethod
    def _loop(sink: _Sink, rounds: list[list[Violation]]) -> None:
        answers = iter(["first", "second", "third"])
        remaining = list(rounds)

        def validator(_parsed: Any) -> list[Violation]:
            return remaining.pop(0) if remaining else []

        retry_with_feedback_sync(
            lambda _turns: next(answers),
            ["turn"],
            [validator],
            parse=lambda a: a,
            sink=sink,  # type: ignore[arg-type]
            agent="static",
            stage="analysis",
        )

    def test_a_violation_that_survived_its_retry_is_published(self) -> None:
        sink = _Sink()
        kept = Violation(code="attck.unknown_id", message="T9999 is not in the catalogue")

        self._loop(sink, [[kept], [kept]])

        assert self._rows(sink) == [
            ("attck.unknown_id", "retried"),
            ("attck.unknown_id", "survived"),
        ]

    def test_a_violation_the_retry_introduced_is_published_once(self) -> None:
        sink = _Sink()
        first = Violation(code="isr.empty_evidence", message="cite the artifact")
        introduced = Violation(code="attck.unknown_id", message="T9999 is not in the catalogue")

        self._loop(sink, [[first], [introduced]])

        assert self._rows(sink) == [
            ("isr.empty_evidence", "retried"),
            ("isr.empty_evidence", "resolved"),
            ("attck.unknown_id", "survived"),
        ]

    def test_an_answer_that_needed_no_correction_publishes_nothing(self) -> None:
        sink = _Sink()

        self._loop(sink, [[]])

        assert self._rows(sink) == []


class TestTheJudgeAsks:
    def test_only_a_turn_that_ends_in_a_question_is_published(self) -> None:
        from langchain_core.messages import AIMessage

        from maljan.agents.judge_agent import JudgeAgent

        sink = _Sink()
        judge = JudgeAgent.__new__(JudgeAgent)
        judge._container = type("C", (), {"event_sink": sink})()
        judge.pipeline_stage = "verdict"
        judge.logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None)})()

        already: set[str] = set()
        judge._publish_questions(
            [
                AIMessage(content="Reading the ledger now."),
                AIMessage(content="Which import set does this sample use?"),
            ],
            already,
        )
        (event,) = sink.of("judge_question")
        assert event["text"] == "Which import set does this sample use?"
        assert event["stage"] == "verdict"
        assert event["addressed_to"] is None

    def test_a_question_is_published_once_however_often_the_hook_runs(self) -> None:
        from langchain_core.messages import AIMessage

        from maljan.agents.judge_agent import JudgeAgent

        sink = _Sink()
        judge = JudgeAgent.__new__(JudgeAgent)
        judge._container = type("C", (), {"event_sink": sink})()
        judge.pipeline_stage = "verdict"
        judge.logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None)})()

        conversation = [AIMessage(content="Is this a packer stub?")]
        already: set[str] = set()
        judge._publish_questions(conversation, already)
        judge._publish_questions(conversation, already)
        assert len(sink.of("judge_question")) == 1

    def test_a_question_asked_twice_is_published_twice(self) -> None:
        """The dedupe is per turn, not per sentence.

        A model that repeats itself is the degenerate loop this codebase
        guards against elsewhere; a feed that showed one question where the
        judge asked two would hide it.
        """
        from langchain_core.messages import AIMessage

        from maljan.agents.judge_agent import JudgeAgent

        sink = _Sink()
        judge = JudgeAgent.__new__(JudgeAgent)
        judge._container = type("C", (), {"event_sink": sink})()
        judge.pipeline_stage = "verdict"
        judge.logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None)})()

        # No ids: the fallback key is what is under test.
        asked = "Is this a packer stub?"
        conversation = [
            AIMessage(content=asked, id=None),
            AIMessage(content="Reading the ledger.", id=None),
            AIMessage(content=asked, id=None),
        ]
        already: set[str] = set()
        judge._publish_questions(conversation, already)
        assert len(sink.of("judge_question")) == 2

        # And the same conversation seen again publishes nothing further.
        judge._publish_questions(conversation, already)
        assert len(sink.of("judge_question")) == 2

    def test_a_question_that_delegates_names_the_agent_it_asks(self) -> None:
        from langchain_core.messages import AIMessage

        from maljan.agents.judge_agent import JudgeAgent

        sink = _Sink()
        judge = JudgeAgent.__new__(JudgeAgent)
        judge._container = type("C", (), {"event_sink": sink})()
        judge.pipeline_stage = "verdict"
        judge.logger = type("L", (), {"debug": staticmethod(lambda *a, **k: None)})()

        message = AIMessage(
            content="Can you confirm the imports?",
            tool_calls=[{"name": "ask_static", "args": {"task": "confirm"}, "id": "1"}],
        )
        judge._publish_questions([message], set())
        assert sink.of("judge_question")[0]["addressed_to"] == "static"
