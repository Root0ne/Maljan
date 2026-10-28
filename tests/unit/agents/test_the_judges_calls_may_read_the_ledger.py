"""The judge's verdict and its technique question may read the run's ledger by id.

Both were one call with no tool: an entry the prompt shortened, or one a claim
cites and the prompt does not show, could not be read. Each now offers
``read_evidence`` from its first turn, answered from the run's ledger; a model
that cannot bind it is asked as before, and the run is told once. A call that
reads nothing sends what it always sent and reads its answer as it always did.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from maljan.agents.evidence_recorder import RepeatGuard
from maljan.agents.judge_agent import (
    TECHNIQUE_QUESTION_SYSTEM,
    TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS,
    JudgeAgent,
)
from maljan.agents.ledger_reads import LedgerReads, not_bound_reason
from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.schemas.evidence import LedgerEntry
from tests.unit.agents.test_the_judge_decides_what_it_did_not_name import (
    EVIDENCE,
    LEFT_OUT,
    REPORTS,
    _bundle,
    _isrs,
)
from tests.unit.agents.test_the_judge_decides_what_it_did_not_name import (
    _Llm as _ToolsFreeLlm,
)

DECODED = "decoded routine: builds names from the current date"
LEDGER = [
    LedgerEntry(id="ev_0012", agent="network", tool="decode", output=DECODED),
    LedgerEntry(id="ev_0013", agent="network", tool="resolve", output="resolver calls"),
    LedgerEntry(id="ev_0020", agent="network", tool="decode", repeated_of="ev_0012"),
]


def _read(entry_id: str, call_id: str = "c1") -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[{"name": READ_EVIDENCE_TOOL, "args": {"evidence_id": entry_id}, "id": call_id}],
    )


def _read_page(entry_id: str, call_id: str, *, offset: int) -> AIMessage:
    args = {"evidence_id": entry_id, "offset": offset, "limit": 10}
    return AIMessage(
        content="", tool_calls=[{"name": READ_EVIDENCE_TOOL, "args": args, "id": call_id}]
    )


class _Bound:
    def __init__(self, llm: _ReadingLlm, names: list[str]) -> None:
        self.llm = llm
        self.names = names

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> Any:
        return self.llm.answer(self.names, messages)


class _ReadingLlm:
    """Binds tools, answers each call from a queue, and remembers what each call was sent."""

    def __init__(self, *answers: Any) -> None:
        self._answers = list(answers)
        self.calls: list[tuple[list[str] | None, list[Any]]] = []

    def bind_tools(self, tools: list[Any], **_kwargs: Any) -> _Bound:
        names = [str(getattr(t, "name", None) or getattr(t, "__name__", "")) for t in tools]
        return _Bound(self, names)

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> Any:
        return self.answer(None, messages)

    def answer(self, names: list[str] | None, messages: list[Any]) -> Any:
        self.calls.append((names, list(messages)))
        answer = self._answers.pop(0)
        return answer if isinstance(answer, AIMessage) else AIMessage(content=answer)


def _bundle_json() -> str:
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332200",
            "objects": [
                {
                    "type": "malware",
                    "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "sample",
                    "is_family": False,
                }
            ],
            "x_maljan_assessment": {
                "verdict": "Malware",
                "severity": {"rating": "High", "rationale": "it does harm"},
                "malware_category": "loader",
            },
        }
    )


def _verdict(llm: Any, ledger: Any = LEDGER) -> tuple[Any, JudgeAgent]:
    judge = JudgeAgent(llm=llm)
    verdict = asyncio.run(
        judge.give_verdict(reports={"network": "It loads a payload."}, history=[], ledger=ledger)
    )
    return verdict, judge


def _techniques(llm: Any, ledger: Any = LEDGER) -> tuple[Any, JudgeAgent]:
    judge = JudgeAgent(llm=llm)
    review = asyncio.run(
        judge.decide_techniques(
            _bundle(),
            _isrs(),
            reports=REPORTS,
            evidence_texts=EVIDENCE,
            facts_block="=== PACK ===\nthe pack",
            run_state="the run state",
            ledger=ledger,
        )
    )
    return review, judge


def _technique_answer() -> str:
    return json.dumps(
        [
            {"id": LEFT_OUT, "decision": "keep", "reason": "ev_0012 shows the routine"},
            {"id": "T1003", "decision": "drop", "reason": "nothing shows it"},
        ]
    )


class TestTheVerdict:
    def test_the_verdict_call_carries_read_evidence_from_its_first_turn(self) -> None:
        llm = _ReadingLlm(_bundle_json())

        _verdict(llm)

        names, _messages = llm.calls[0]
        assert names == [READ_EVIDENCE_TOOL]

    def test_a_read_reaches_the_ledger_and_the_answer_after_it_is_the_verdict(self) -> None:
        llm = _ReadingLlm(_read("ev_0020"), _bundle_json())

        verdict, _judge = _verdict(llm)

        _names, second = llm.calls[1]
        assert isinstance(second[-1], ToolMessage)
        assert second[-1].tool_call_id == "c1"
        # A repeat's id reads the entry that holds its answer, under that id.
        assert second[-1].content.startswith("[ev_0012]\n")
        assert DECODED in second[-1].content
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.verdict == "Malware"

    def test_an_unknown_id_is_answered_as_one_the_run_s_ledger_does_not_hold(self) -> None:
        llm = _ReadingLlm(_read("ev_9999"), _bundle_json())

        _verdict(llm)

        assert "ev_9999 is no evidence id the run's ledger holds" in llm.calls[1][1][-1].content

    def test_the_verdict_is_unchanged_when_no_tool_is_called(self) -> None:
        reading = _ReadingLlm(_bundle_json())
        plain = _ReadingLlm(_bundle_json())

        with_reads, _ = _verdict(reading)
        without, _ = _verdict(plain, ledger=None)

        assert [m.content for m in reading.calls[0][1]] == [m.content for m in plain.calls[0][1]]
        assert plain.calls[0][0] is None
        assert with_reads.bundle.x_maljan_assessment == without.bundle.x_maljan_assessment
        assert [o.type for o in with_reads.bundle.objects] == [
            o.type for o in without.bundle.objects
        ]
        assert with_reads.violations == without.violations

    def test_a_model_that_cannot_bind_it_answers_without_and_the_run_is_told_once(self) -> None:
        llm = _ToolsFreeLlm("not a bundle", _bundle_json())

        verdict, judge = _verdict(llm)

        assert len(llm.calls) == 2
        assert judge.read_degradations == [not_bound_reason(str(judge.name))]
        assert verdict.bundle.x_maljan_assessment is not None

    def test_repeated_reads_end_the_loop_with_the_reply_kept_without_its_calls(self) -> None:
        last = 2 + RepeatGuard.ENDS_AT
        reads = [_read("ev_0012", f"c{n}") for n in range(last)]
        llm = _ReadingLlm(*reads, _bundle_json())

        verdict, _judge = _verdict(llm)

        # Two identical reads served, the next refused and sent until the
        # stated count, the last refused and its reply kept with no call: an
        # empty answer, asked again as one.
        refused = [
            m
            for m in llm.calls[last - 1][1]
            if isinstance(m, ToolMessage) and "not read again" in str(m.content)
        ]
        assert len(refused) == RepeatGuard.ENDS_AT - 1
        assert len(llm.calls) == last + 1
        assert verdict.bundle.x_maljan_assessment is not None
        # Each refusal names the id it already holds, and how to page it.
        assert "ev_0012 not read again" in str(refused[0].content)
        assert "Pass another offset, and a limit" in str(refused[0].content)

    def test_reads_of_other_pages_are_never_refused(self) -> None:
        pages = [
            _read_page("ev_0012", f"p{n}", offset=n * 10) for n in range(RepeatGuard.ENDS_AT + 2)
        ]
        llm = _ReadingLlm(*pages, _bundle_json())

        _verdict(llm)

        assert len(llm.calls) == RepeatGuard.ENDS_AT + 3
        assert not any(
            isinstance(m, ToolMessage) and "not read again" in str(m.content)
            for m in llm.calls[-1][1]
        )


class TestTheTechniqueQuestion:
    def test_the_question_carries_read_evidence_and_says_so(self) -> None:
        llm = _ReadingLlm(_technique_answer())

        _techniques(llm)

        names, messages = llm.calls[0]
        assert names == [READ_EVIDENCE_TOOL]
        assert messages[0].content == TECHNIQUE_QUESTION_SYSTEM

    def test_a_read_reaches_the_ledger_and_the_answer_after_it_decides(self) -> None:
        llm = _ReadingLlm(_read("ev_0013"), _technique_answer())

        review, _judge = _techniques(llm)

        assert "resolver calls" in llm.calls[1][1][-1].content
        assert review is not None
        decided = {d.technique_id: d.decision for d in review.decisions}
        assert decided[LEFT_OUT] == "keep"

    def test_the_question_is_unchanged_when_no_tool_is_called(self) -> None:
        reading = _ReadingLlm(_technique_answer())
        plain = _ToolsFreeLlm(_technique_answer())

        with_reads, _ = _techniques(reading)
        # The same ledger, a model that binds no tool: the question as it was.
        without, _ = _techniques(plain)

        sent = [m.content for m in reading.calls[0][1]]
        before = [m.content for m in plain.calls[0]]
        assert sent[1:] == before[1:]
        assert before[0] == TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS
        assert with_reads == without

    def test_the_structured_question_offers_the_read_beside_its_schema(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(JudgeAgent, "_supports_structured_output", lambda self: True)
        rows = [{"id": LEFT_OUT, "decision": "drop", "reason": "ev_0013 shows only lookups"}]
        answer = AIMessage(
            content="",
            tool_calls=[{"name": "TechniqueAnswer", "args": {"decisions": rows}, "id": "s1"}],
        )
        llm = _ReadingLlm(_read("ev_0013"), answer)

        review, _judge = _techniques(llm)

        assert llm.calls[0][0] == ["TechniqueAnswer", READ_EVIDENCE_TOOL]
        assert llm.calls[1][0] == llm.calls[0][0]
        assert "resolver calls" in llm.calls[1][1][-1].content
        assert review is not None
        assert {d.technique_id: d.decision for d in review.decisions}[LEFT_OUT] == "drop"

    def test_a_model_that_cannot_bind_it_is_asked_as_before_and_the_run_is_told(self) -> None:
        llm = _ToolsFreeLlm(_technique_answer())

        review, judge = _techniques(llm)

        assert llm.calls[0][0].content == TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS
        assert judge.read_degradations == [not_bound_reason(str(judge.name))]
        assert review is not None


class TestWhatAReadReturns:
    def test_a_blanked_answer_is_read_from_the_store_and_paged_from_it(self) -> None:
        whole = "x" * 50 + "THE TAIL"
        spill = MagicMock()
        spill.read = lambda digest, offset=0, length=None: whole.encode()[
            offset : None if length is None else offset + length
        ]
        entry = LedgerEntry(
            id="ev_0030",
            tool="strings",
            output="",
            truncated=True,
            spilled=[{"part": "output", "key": "k", "sha256": "d" * 64, "bytes": len(whole)}],
        )
        reads = LedgerReads([entry], spill=spill)

        assert "THE TAIL" in reads.read({"evidence_id": "ev_0030"})
        paged = reads.read({"evidence_id": "ev_0030", "offset": 50})
        assert "bytes 50-58 of 58" in paged
        assert "THE TAIL" in paged

    @pytest.mark.parametrize("args", [{}, {"evidence_id": "ev_0012", "offset": -1}])
    def test_a_malformed_read_is_answered_and_never_raises(self, args: dict[str, Any]) -> None:
        said = LedgerReads(LEDGER).read(args)

        assert "error" in said


class TestTheMediatorReadsTheRunsLedger:
    """The mediator's ``read_evidence`` reads every analyst's entry, not its own loop's alone."""

    def test_the_mediator_reads_an_analyst_s_entry_and_gets_its_text(self) -> None:
        from tests.unit.agents.test_the_mediator_decides_whether_to_read_or_ask import (
            MEDIATION,
            PROMPT,
            _call,
            _mediator,
        )

        judge, _container = _mediator(
            [_call(READ_EVIDENCE_TOOL, {"evidence_id": "ev_0020"}, "r1"), AIMessage(MEDIATION)],
            [],
        )
        asyncio.run(judge._initialize_mcp_client())
        judge._mediation_ledger = [entry.model_dump(mode="json") for entry in LEDGER]

        answer = asyncio.run(judge.execute_tool_loop(PROMPT))

        assert answer == MEDIATION
        said = next(str(m.content) for m in judge.llm.seen[1] if getattr(m, "type", "") == "tool")
        # A repeat's id reads the entry that holds the analyst's answer, under its id.
        assert said.startswith("[ev_0012]\n") and DECODED in said
        (read,) = [e for e in judge.drain_evidence_entries() if e.tool == READ_EVIDENCE_TOOL]
        # Filed as a repeat of the analyst's entry: no second citable copy.
        assert read.repeated_of == "ev_0012" and DECODED not in read.output

    def test_without_the_run_s_ledger_an_analyst_s_id_is_one_it_never_filed(self) -> None:
        from tests.unit.agents.test_the_mediator_decides_whether_to_read_or_ask import (
            MEDIATION,
            PROMPT,
            _call,
            _mediator,
        )

        judge, _container = _mediator(
            [_call(READ_EVIDENCE_TOOL, {"evidence_id": "ev_0012"}, "r1"), AIMessage(MEDIATION)],
            [],
        )
        asyncio.run(judge._initialize_mcp_client())

        asyncio.run(judge.execute_tool_loop(PROMPT))

        said = next(str(m.content) for m in judge.llm.seen[1] if getattr(m, "type", "") == "tool")
        assert "ev_0012 is no evidence id this analysis filed" in said

    def test_the_block_question_may_read_the_run_s_ledger(self) -> None:
        from maljan.agents.judge_agent import CONTRADICTIONS_BLOCK_QUESTION

        block = "CONTRADICTIONS: NONE\nagreement_confidence: 0.9"
        llm = _ReadingLlm(_read("ev_0013"), block)
        judge = JudgeAgent(llm=llm)
        judge._mediation_ledger = list(LEDGER)

        text = asyncio.run(
            judge._ask_for_contradictions_block([("human", "Mediate.")], "My reasoning.")
        )

        assert text.endswith(block)
        names, first = llm.calls[0]
        assert names == [READ_EVIDENCE_TOOL]
        assert first[-1].content == CONTRADICTIONS_BLOCK_QUESTION
        assert "resolver calls" in llm.calls[1][1][-1].content

    def test_with_no_ledger_the_block_question_says_it_carries_no_tools(self) -> None:
        from maljan.agents.judge_agent import CONTRADICTIONS_BLOCK_QUESTION_WITHOUT_TOOLS

        llm = _ReadingLlm("CONTRADICTIONS: NONE")
        judge = JudgeAgent(llm=llm)

        asyncio.run(judge._ask_for_contradictions_block([("human", "Mediate.")], "Reasoning."))

        names, first = llm.calls[0]
        assert names is None
        assert first[-1].content == CONTRADICTIONS_BLOCK_QUESTION_WITHOUT_TOOLS

    def test_mediate_hands_the_round_the_ledger_and_takes_it_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = JudgeAgent(llm=_ReadingLlm())
        seen: list[Any] = []

        async def _round(*_args: Any, **_kwargs: Any) -> Any:
            seen.append(judge._mediation_ledger)
            return None, None

        monkeypatch.setattr(judge, "_mediate_round", _round)

        asyncio.run(judge.mediate({}, [], ledger=LEDGER))

        assert seen == [LEDGER]
        assert judge._mediation_ledger is None


class TestTheReadsAreCounted:
    def test_each_read_is_counted_by_call_and_stated_in_the_efficiency_block(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.ledger_reads import ledger_reads_record
        from maljan.analysis.efficiency import efficiency_lines

        container = SimpleNamespace()
        llm = _ReadingLlm(_read("ev_0012"), _read("ev_9999", "c2"), _bundle_json())
        judge = JudgeAgent(llm=llm)
        judge._container = container

        asyncio.run(judge.give_verdict(reports={"network": "x"}, history=[], ledger=LEDGER))

        record = ledger_reads_record(container)
        assert record == {"reads": 2, "by_call": {"verdict": 2}, "unfound": 1}
        line = [ln for ln in efficiency_lines({"v": 1, "ledger_reads": record}) if "outside" in ln]
        assert line == [
            "Entries read by id outside a tool loop (read_evidence, not filed): 2 reads — "
            "`verdict` 2 reads; 1 read named no entry the ledger holds."
        ]

    def test_a_job_whose_calls_offered_no_read_records_nothing(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.ledger_reads import ledger_reads_record

        assert ledger_reads_record(SimpleNamespace()) is None


SCHEMA_ARGS = {"decisions": [{"technique_id": LEFT_OUT, "decision": "keep", "reason": "ev_0012"}]}


def _mixed(args: dict[str, Any] = SCHEMA_ARGS) -> AIMessage:
    """A read and the schema's call in one reply, thinking first, as the Anthropic wire has it."""
    read = {"name": READ_EVIDENCE_TOOL, "args": {"evidence_id": "ev_0013"}, "id": "toolu_read"}
    schema = {"name": "TechniqueAnswer", "args": args, "id": "toolu_schema"}
    return AIMessage(
        content=[
            {"type": "thinking", "thinking": "Read it, and answer.", "signature": "sig"},
            {"type": "tool_use", "id": read["id"], "name": read["name"], "input": read["args"]},
            {"type": "tool_use", "id": schema["id"], "name": schema["name"], "input": args},
        ],
        tool_calls=[read, schema],
        response_metadata={"stop_reason": "tool_use"},
        usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        id="msg_1",
    )


def _answered(reply: AIMessage) -> Any:
    async def send(_conversation: list[Any]) -> Any:
        return reply

    return asyncio.run(LedgerReads(LEDGER).answer(send, []))


class TestAReadBesideTheSchemasCall:
    """A reply that reads and calls the schema's tool is the answer, kept without its reads."""

    def test_the_schema_call_refused_is_the_kept_text_and_the_retry_answers_it(self) -> None:
        from langchain_core.messages import HumanMessage

        from maljan.agents.judge_agent import TechniqueAnswer
        from maljan.agents.ledger_reads import structured_reply
        from maljan.core.token_ledger import read_structured_reply
        from maljan.llm.answer_text import structured_answer_text, tool_call_arguments
        from maljan.pipeline.validation import Violation, _with_feedback

        raw = _answered(_mixed())

        read = read_structured_reply(structured_reply(raw, TechniqueAnswer), None)
        assert read.parsed is None and read.kept is not None
        assert tool_call_arguments(read.raw) == SCHEMA_ARGS
        assert json.loads(structured_answer_text(read.raw)) == SCHEMA_ARGS
        # Its thinking, metadata, usage and id stay; the read's block does not.
        assert [b["type"] for b in raw.content] == ["thinking", "tool_use"]
        assert raw.content[1]["id"] == "toolu_schema"
        assert raw.id == "msg_1" and raw.usage_metadata["output_tokens"] == 5
        assert raw.response_metadata == {"stop_reason": "tool_use"}

        turns = _with_feedback(
            [HumanMessage(content="Decide.")],
            raw,
            [Violation(code="x", path="decisions", message="not a row")],
            reply_to_calls=True,
        )
        replies = [m for m in turns if isinstance(m, ToolMessage)]
        assert replies and replies[0].tool_call_id == "toolu_schema"

    def test_a_valid_schema_call_beside_a_read_is_parsed_from_the_same_reply(self) -> None:
        from maljan.agents.judge_agent import TechniqueAnswer
        from maljan.agents.ledger_reads import structured_reply

        args = {"decisions": [{"id": LEFT_OUT, "decision": "drop", "reason": "lookups only"}]}

        raw = _answered(_mixed(args))

        assert [c["id"] for c in raw.tool_calls] == ["toolu_schema"]
        assert structured_reply(raw, TechniqueAnswer)["parsed"] == TechniqueAnswer(**args)

    def test_the_technique_question_salvages_the_schema_call_not_the_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(JudgeAgent, "_supports_structured_output", lambda self: True)
        llm = _ReadingLlm(_mixed())

        review, _judge = _techniques(llm)

        assert review is not None
        assert {d.technique_id: d.decision for d in review.decisions}[LEFT_OUT] == "keep"


class TestAReadOfAFailedEntry:
    FAILED = [LedgerEntry(id="ev_0040", tool="unpack", ok=False, output="error: no section")]

    def test_the_served_repeat_carries_the_analysts_failed_entry_notice(self) -> None:
        from maljan.agents.evidence_recorder import served_repeat_notice

        reads = LedgerReads(self.FAILED)
        notice = served_repeat_notice(
            READ_EVIDENCE_TOOL, "ev_0040", ("offset", "limit"), failed=True
        )

        first = reads.read({"evidence_id": "ev_0040"})
        again = reads.read({"evidence_id": "ev_0040"}, again=True)

        assert notice not in first
        assert again == f"{first}\n\n{notice}"
        # An entry that holds an answer is served again as it was.
        assert LedgerReads(LEDGER).read({"evidence_id": "ev_0012"}, again=True) == LedgerReads(
            LEDGER
        ).read({"evidence_id": "ev_0012"})

    def test_the_loop_s_second_identical_read_is_the_served_repeat(self) -> None:
        llm = _ReadingLlm(_read("ev_0040", "c1"), _read("ev_0040", "c2"), _bundle_json())

        _verdict(llm, ledger=self.FAILED)

        assert "failed the same way before, in [ev_0040]" not in llm.calls[1][1][-1].content
        assert "failed the same way before, in [ev_0040]" in llm.calls[2][1][-1].content


class TestTheMediatorStatesAnOutsideEntrysCut:
    def test_the_cut_of_the_analyst_s_row_is_stated_under_its_answer(self) -> None:
        from tests.unit.agents.test_the_mediator_decides_whether_to_read_or_ask import (
            MEDIATION,
            PROMPT,
            _call,
            _mediator,
        )

        judge, _container = _mediator(
            [_call(READ_EVIDENCE_TOOL, {"evidence_id": "ev_0012"}, "r1"), AIMessage(MEDIATION)],
            [],
        )
        asyncio.run(judge._initialize_mcp_client())
        cut = LedgerEntry(
            id="ev_0012", agent="network", tool="decode", output=DECODED, chars_dropped=5000
        )
        judge._mediation_ledger = [cut.model_dump(mode="json")]

        asyncio.run(judge.execute_tool_loop(PROMPT))

        said = next(str(m.content) for m in judge.llm.seen[1] if getattr(m, "type", "") == "tool")
        assert "the platform left out 5,000 characters of this answer" in said


class TestAModelThatCannotBindRecordsNoReads:
    def test_no_efficiency_record_is_made_for_a_read_never_offered(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.ledger_reads import ledger_reads_record

        container = SimpleNamespace()
        judge = JudgeAgent(llm=_ToolsFreeLlm(_bundle_json()))
        judge._container = container

        asyncio.run(judge.give_verdict(reports={"network": "x"}, history=[], ledger=LEDGER))

        assert judge.read_degradations
        assert ledger_reads_record(container) is None

    def test_a_model_that_binds_it_and_reads_nothing_records_none_made(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.ledger_reads import ledger_reads_record

        container = SimpleNamespace()
        judge = JudgeAgent(llm=_ReadingLlm(_bundle_json()))
        judge._container = container

        asyncio.run(judge.give_verdict(reports={"network": "x"}, history=[], ledger=LEDGER))

        assert ledger_reads_record(container) == {"reads": 0, "by_call": {}}


class TestTheStructuredTechniqueQuestionAtTheCeiling:
    def test_a_turn_after_a_read_the_ceiling_refuses_ends_the_question(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.spend import SpendCeilingStop

        monkeypatch.setattr(JudgeAgent, "_supports_structured_output", lambda self: True)
        admitted: list[str] = []

        def _admits(self: JudgeAgent, what: str, *_args: Any, **_kwargs: Any) -> Any:
            admitted.append(what)
            # The turn after the read alone is refused: a text question after
            # it would be admitted.
            if len(admitted) == 2:
                raise SpendCeilingStop("the job's spend ceiling is reached")
            return None

        monkeypatch.setattr(JudgeAgent, "_spend_admits", _admits)
        llm = _ReadingLlm(_read("ev_0013"), _technique_answer())

        review, _judge = _techniques(llm)

        # Not asked again in text past the ceiling: the question ends there.
        assert len(llm.calls) == 1
        assert review is not None
        assert str(review.unanswered).startswith("not asked: the job's spend ceiling")


class TestTheJudgeNodeSaysATechniqueQuestionsBindFailure:
    def test_the_reason_reaches_the_run_s_degradations(self) -> None:
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from maljan.schemas.stix_models import TechniqueReview
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(bundle=_bundle(), violations=[], retries=0, fed_back={})
        )
        reason = not_bound_reason("judge")

        async def _decide(*_args: Any, **_kwargs: Any) -> Any:
            judge.read_degradations.append(reason)
            return TechniqueReview(asked=[], decisions=[])

        judge.decide_techniques = _decide

        update = asyncio.run(make_judge_node(container)(_state([])))

        assert update["degradation_reasons"].count(reason) == 1


class TestACallWhoseArgumentsDidNotParse:
    def test_a_reply_whose_only_read_did_not_parse_is_its_text_without_the_call(self) -> None:
        from maljan.llm.answer_text import structured_answer_text

        bad = {"name": READ_EVIDENCE_TOOL, "args": '{"evidence_id": "ev_00', "id": "c1"}
        reply = AIMessage(content="", invalid_tool_calls=[{**bad, "error": "unparsed"}])

        raw = _answered(reply)

        assert raw.tool_calls == [] and raw.invalid_tool_calls == []
        # The read's partial arguments are not taken as the answer's text.
        assert structured_answer_text(raw) == ""

    def test_a_schema_call_that_did_not_parse_beside_a_read_is_the_answer(self) -> None:
        from maljan.llm.answer_text import structured_answer_text

        sent = '{"decisions": [{"id": "T1568.002", "decision": "keep"'
        reply = AIMessage(
            content="",
            tool_calls=[_read("ev_0013").tool_calls[0]],
            invalid_tool_calls=[
                {"name": "TechniqueAnswer", "args": sent, "id": "s1", "error": "unparsed"}
            ],
        )
        turns: list[Any] = []

        async def send(conversation: list[Any]) -> Any:
            turns.append(conversation)
            return reply

        raw = asyncio.run(LedgerReads(LEDGER).answer(send, []))

        # Answered as it came, not read: the schema call's text is what is salvaged.
        assert len(turns) == 1
        assert raw.tool_calls == []
        assert [c["id"] for c in raw.invalid_tool_calls] == ["s1"]
        assert structured_answer_text(raw) == sent


class TestAPartialAnswerSaysSo:
    def test_the_entry_s_cut_is_stated_under_a_whole_read(self) -> None:
        cut = LedgerEntry(id="ev_0050", tool="decode", output="x" * 100, chars_dropped=5000)

        said = LedgerReads([cut]).read({"evidence_id": "ev_0050"})

        assert said.endswith(
            "Completeness: the platform left out 5,000 characters of this answer to fit the "
            "room for a tool answer. Anything not shown here is unknown, not absent; read "
            "further with `offset`, `limit`."
        )

    def test_a_whole_answer_carries_no_line(self) -> None:
        said = LedgerReads(LEDGER).read({"evidence_id": "ev_0013"})

        assert "Completeness:" not in said


class TestTheMediatorSaysWhichLedgerItReads:
    def test_with_the_run_s_ledger_an_unknown_id_names_it_and_the_tool_is_the_same(self) -> None:
        from langchain_core.utils.function_calling import convert_to_openai_tool

        from maljan.agents.tool_answer_clearing import THE_RUNS_LEDGER, read_evidence_tool
        from tests.unit.agents.test_the_mediator_decides_whether_to_read_or_ask import (
            MEDIATION,
            PROMPT,
            _call,
            _mediator,
        )

        judge, _container = _mediator(
            [_call(READ_EVIDENCE_TOOL, {"evidence_id": "ev_9999"}, "r1"), AIMessage(MEDIATION)],
            [],
        )
        asyncio.run(judge._initialize_mcp_client())
        judge._mediation_ledger = [entry.model_dump(mode="json") for entry in LEDGER]

        asyncio.run(judge.execute_tool_loop(PROMPT))

        said = next(str(m.content) for m in judge.llm.seen[1] if getattr(m, "type", "") == "tool")
        assert "ev_9999 is no evidence id the run's ledger holds" in said
        # The definition the model is sent is the one whichever ledger it reads.
        here = read_evidence_tool(lambda _id: None)
        run = read_evidence_tool(lambda _id: None, holds=THE_RUNS_LEDGER)
        assert json.dumps(convert_to_openai_tool(here)) == json.dumps(convert_to_openai_tool(run))
