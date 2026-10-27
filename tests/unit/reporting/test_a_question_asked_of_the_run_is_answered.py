"""A question asked of a run is answered in a fixed vocabulary, and the checks are code.

The report model picks the outcome (established, partial, limited negative,
not determinable from this run, out of scope) and cites the entries; the
platform refuses "established" with no answered entry cited, "limited
negative" with no record of what was looked at, and a limited negative that
rests on an analyst's open question. A refused word is printed as not
determinable, with the model's word and the reason beside it. A job asked
nothing runs no round and renders as it always did.

Every question, entry and answer here is made up for the test.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.core.spend import TAIL_CALLS, SpendCeilingStop
from maljan.pipeline.validation import FEEDBACK_PREAMBLE, ValidationTally, citation_violations
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import QUESTION_OUTCOMES, MalwareReport, QuestionAnswer
from maljan.reporting.narrative_agent import NarrativeAgent, build_prompt_text, findings_lines
from maljan.reporting.question_round import (
    ANSWERED_TWICE_CODE,
    ESTABLISHED_UNGROUNDED_CODE,
    NEGATIVE_ON_OPEN_QUESTION_CODE,
    NEGATIVE_WITHOUT_COVERAGE_CODE,
    QUESTION_CALL,
    SCHEMA_CODE,
    SYSTEM_PROMPT,
    UNANSWERED_CODE,
    UNISSUED_ID_CODE,
    UNKNOWN_NUMBER_CODE,
    UNKNOWN_OPEN_QUESTION_CODE,
    QuestionEvidence,
    QuestionReply,
    _answer_prose,
    answer_questions,
    asked_questions,
    build_messages,
    question_violations,
    settle,
)
from maljan.reporting.renderers import MarkdownRenderer
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, OpenQuestion
from tests.unit.reporting._report_shapes import hostile_report, rich_report, stored_old_shape

QUESTIONS = ["What is the C2 address?", "Does it persist through a Run key?"]

# A no-question report rendered at the base this change was cut from.
GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "reporting" / "no_question"

# Text that would restructure a Markdown report if written into it as is.
HOSTILE_TEXTS = [
    "```",
    "~~~",
    "# a heading",
    "> a quote",
    "---",
    "- - -",
    "___",
    "    an indented line",
    "1. a numbered line",
    "- a bullet",
    "<img src=x onerror=alert(1)>",
    "before\n```\nafter\n# heading\n> quote\n    indented",
]


def _entry(entry_id: str, *, ok: bool = True, **extra: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="static", tool="strings", args={}, output="x", ok=ok, **extra
    )


LEDGER = [
    _entry("ev_0001"),
    _entry("ev_0002", ok=False, error="timed out"),
    _entry("ev_0003"),
    # A guard's answer names itself: no tool ran.
    _entry("ev_0004", repeated_of="ev_0004"),
]

OPEN = OpenQuestion(
    question="Whether the Run key is written after a reboot",
    why_open="needs_sandbox_run",
    would_answer="a sandbox run",
)


def _evidence(isrs: Any = None) -> QuestionEvidence:
    return QuestionEvidence.of(LEDGER, [], None, isrs)


def _isrs() -> dict[str, AgentISR]:
    return {"static": AgentISR(agent_id="static", domain="static", open_questions=[OPEN])}


def _reply(number: int, outcome: str, **fields: Any) -> dict[str, Any]:
    return {"question": number, "outcome": outcome, "answer": "Said from the run.", **fields}


def _report() -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="d" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
    ).build_deterministic()


class TestTheVocabulary:
    def test_the_five_outcomes_are_the_set(self) -> None:
        assert QUESTION_OUTCOMES == (
            "established",
            "partial",
            "limited_negative",
            "not_determinable",
            "out_of_scope",
        )

    def test_the_system_prompt_names_every_outcome(self) -> None:
        for word in QUESTION_OUTCOMES:
            assert f"  - {word}: " in SYSTEM_PROMPT

    def test_an_outcome_spelt_as_words_is_the_sets_word(self) -> None:
        payload = {
            "answers": [
                _reply(1, "Not determinable from this run"),
                _reply(2, "limited negative", looked_at=["ev_0003"]),
            ]
        }

        (first, second) = settle(payload, QUESTIONS, _evidence())

        assert (first.outcome, second.outcome) == ("not_determinable", "limited_negative")


class TestTheChecks:
    def test_established_on_an_answered_entry_stands(self) -> None:
        payload = {"answers": [_reply(1, "established", evidence_ids=["ev_0001"])]}

        (answer,) = settle(payload, QUESTIONS[:1], _evidence())

        assert answer.outcome == "established"
        assert answer.answered is None
        assert answer.checks == []

    @pytest.mark.parametrize("cited", [[], ["ev_0002"], ["ev_0004"], ["ev_0099"]])
    def test_established_with_no_answered_entry_is_refused(self, cited: list[str]) -> None:
        payload = {"answers": [_reply(1, "established", evidence_ids=cited)]}

        (answer,) = settle(payload, QUESTIONS[:1], _evidence())
        codes = {v.code for v in question_violations(payload, QUESTIONS[:1], _evidence())}

        assert answer.outcome == "not_determinable"
        assert answer.answered == "established"
        assert any(check.startswith("refused: answered established") for check in answer.checks)
        assert ESTABLISHED_UNGROUNDED_CODE in codes
        assert answer.evidence_ids == cited

    def test_a_limited_negative_with_a_coverage_record_stands(self) -> None:
        payload = {"answers": [_reply(1, "limited_negative", looked_at=["ev_0003"])]}

        (answer,) = settle(payload, QUESTIONS[:1], _evidence())

        assert answer.outcome == "limited_negative"
        assert answer.looked_at == ["ev_0003"]

    @pytest.mark.parametrize("looked", [[], ["ev_0002"], ["ev_0004"]])
    def test_a_limited_negative_without_one_is_refused(self, looked: list[str]) -> None:
        payload = {"answers": [_reply(1, "limited_negative", looked_at=looked)]}

        (answer,) = settle(payload, QUESTIONS[:1], _evidence())
        codes = {v.code for v in question_violations(payload, QUESTIONS[:1], _evidence())}

        assert answer.outcome == "not_determinable"
        assert answer.answered == "limited_negative"
        assert NEGATIVE_WITHOUT_COVERAGE_CODE in codes

    def test_an_open_question_is_never_an_absence(self) -> None:
        payload = {
            "answers": [
                _reply(2, "limited_negative", looked_at=["ev_0003"], open_questions=["OQ1"])
            ]
        }
        evidence = _evidence(_isrs())

        (_, answer) = settle(payload, QUESTIONS, evidence)
        codes = {v.code for v in question_violations(payload, QUESTIONS, evidence)}

        assert answer.outcome == "not_determinable"
        assert answer.open_questions == [f"static: {OPEN.question}"]
        assert "an open question is an unknown, not an absence" in " ".join(answer.checks)
        assert NEGATIVE_ON_OPEN_QUESTION_CODE in codes

    def test_an_open_question_named_with_not_determinable_stands(self) -> None:
        payload = {"answers": [_reply(2, "not_determinable", open_questions=["OQ1"])]}

        (_, answer) = settle(payload, QUESTIONS, _evidence(_isrs()))

        assert answer.outcome == "not_determinable"
        assert answer.answered is None

    def test_an_id_the_run_did_not_issue_is_named_and_counts_for_nothing(self) -> None:
        payload = {"answers": [_reply(1, "partial", evidence_ids=["ev_0001", "ev_0777"])]}

        (answer,) = settle(payload, QUESTIONS[:1], _evidence())
        codes = {v.code for v in question_violations(payload, QUESTIONS[:1], _evidence())}

        assert answer.outcome == "partial"
        assert "ev_0777" in answer.checks[0]
        assert UNISSUED_ID_CODE in codes

    def test_out_of_scope_and_partial_stand_as_written(self) -> None:
        payload = {"answers": [_reply(1, "out_of_scope"), _reply(2, "partial")]}

        answers = settle(payload, QUESTIONS, _evidence())

        assert [a.outcome for a in answers] == ["out_of_scope", "partial"]

    def test_a_question_with_no_answer_is_not_determinable_and_said(self) -> None:
        payload = {"answers": [_reply(1, "out_of_scope")]}

        (_, second) = settle(payload, QUESTIONS, _evidence())
        codes = {v.code for v in question_violations(payload, QUESTIONS, _evidence())}

        assert second.outcome == "not_determinable"
        assert second.checks == ["the report model wrote no answer to this question"]
        assert UNANSWERED_CODE in codes

    def test_one_broken_reply_costs_its_own_question_only(self) -> None:
        payload = {"answers": [_reply(1, "certain"), _reply(2, "out_of_scope")]}

        (first, second) = settle(payload, QUESTIONS, _evidence())

        assert first.outcome == "not_determinable"
        assert "did not fit its schema" in first.checks[0]
        assert second.outcome == "out_of_scope"

    def test_an_unreadable_answer_leaves_every_question_not_determinable(self) -> None:
        answers = settle(None, QUESTIONS, _evidence())

        assert [a.outcome for a in answers] == ["not_determinable", "not_determinable"]

    def test_a_number_not_asked_and_a_second_answer_are_named(self) -> None:
        payload = {
            "answers": [
                _reply(1, "out_of_scope"),
                _reply(1, "partial"),
                _reply(2, "out_of_scope"),
                _reply(7, "partial"),
            ]
        }

        codes = [v.code for v in question_violations(payload, QUESTIONS, _evidence())]
        answers = settle(payload, QUESTIONS, _evidence())

        assert codes == [ANSWERED_TWICE_CODE, UNKNOWN_NUMBER_CODE]
        assert [a.outcome for a in answers] == ["out_of_scope", "out_of_scope"]

    def test_an_open_question_the_analysts_did_not_leave_is_named(self) -> None:
        payload = {"answers": [_reply(1, "partial", open_questions=["OQ9"]), _reply(2, "partial")]}

        codes = {v.code for v in question_violations(payload, QUESTIONS, _evidence(_isrs()))}
        (first, _) = settle(payload, QUESTIONS, _evidence(_isrs()))

        assert codes == {UNKNOWN_OPEN_QUESTION_CODE}
        assert first.open_questions == []
        assert "OQ9" in first.checks[0]

    def test_a_question_number_is_never_a_boolean(self) -> None:
        with pytest.raises(ValueError):
            QuestionReply(question=True, outcome="partial", answer="x")  # type: ignore[arg-type]

    def test_an_open_question_label_in_the_prose_is_no_citation(self) -> None:
        payload = {
            "answers": [
                _reply(
                    2,
                    "not_determinable",
                    answer="It rests on [OQ1] and on [oq1, ev_0001].",
                    evidence_ids=["ev_0001"],
                    open_questions=["[OQ1]"],
                )
            ]
        }
        evidence = _evidence(_isrs())

        (_, answer) = settle(payload, QUESTIONS, evidence)
        codes = {v.code for v in question_violations(payload, QUESTIONS, evidence)}
        prose = _answer_prose(payload)
        found = citation_violations(prose, sorted(evidence.issued), prose=("answers",))

        assert answer.open_questions == [f"static: {OPEN.question}"]
        assert codes == {UNANSWERED_CODE}
        assert found == []

    def test_only_the_answer_text_is_read_as_prose(self) -> None:
        payload = {"answers": [_reply(1, "partial", looked_at=["[ev_0777]"])]}

        assert _answer_prose(payload) == {
            "answers": [{"answer": "Said from the run.", "evidence_ids": []}]
        }

    def test_the_questions_a_job_was_given_are_read_with_blanks_left_out(self) -> None:
        assert asked_questions(["  What  is\nit? ", "", "   "]) == ["What is it?"]
        assert asked_questions(None) == []
        assert asked_questions("one question") == []


class _Reporter:
    """The narrative agent as the round uses it: one ``ask`` per call."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.turns: list[list[Any]] = []

    async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
        self.turns.append(list(turns))
        return AIMessage(content=json.dumps(self.answers.pop(0)))


class TestTheRound:
    @pytest.mark.asyncio
    async def test_a_refused_word_is_asked_about_once_and_the_fix_stands(self) -> None:
        reporter = _Reporter(
            {"answers": [_reply(1, "established", evidence_ids=["ev_0002"])]},
            {"answers": [_reply(1, "established", evidence_ids=["ev_0001"])]},
        )

        result = await answer_questions(reporter, _report(), QUESTIONS[:1], ledger=LEDGER)

        (answer,) = result.answers
        assert answer.outcome == "established"
        assert result.tally.retries == 1
        assert result.tally.by_code[ESTABLISHED_UNGROUNDED_CODE] == 1
        assert result.tally.unresolved == []
        feedback = str(reporter.turns[1][-1].content)
        assert FEEDBACK_PREAMBLE in feedback
        assert "established" in feedback

    @pytest.mark.asyncio
    async def test_a_word_still_refused_after_the_retry_is_printed_as_not_determinable(
        self,
    ) -> None:
        refused = {"answers": [_reply(1, "limited_negative")]}
        reporter = _Reporter(refused, refused)

        result = await answer_questions(reporter, _report(), QUESTIONS[:1], ledger=LEDGER)

        (answer,) = result.answers
        assert (answer.outcome, answer.answered) == ("not_determinable", "limited_negative")
        assert [row["code"] for row in result.tally.unresolved] == [NEGATIVE_WITHOUT_COVERAGE_CODE]

    @pytest.mark.asyncio
    async def test_what_the_reporter_records_of_the_round_is_the_rounds(self) -> None:
        class _Overflowing(_Reporter):
            degradations = ["said by the narrative round"]

            async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
                self.degradations = [*self.degradations, f"the {what} prompt overflows"]
                return await super().ask(turns, call=call, what=what)

        reporter = _Overflowing({"answers": [_reply(1, "out_of_scope")]})

        result = await answer_questions(reporter, _report(), QUESTIONS[:1], ledger=LEDGER)

        assert result.degradations == ["the question round's prompt overflows"]

    @pytest.mark.asyncio
    async def test_a_spend_ceiling_leaves_each_question_not_determinable_and_said(
        self,
    ) -> None:
        class _Stopped:
            async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
                raise SpendCeilingStop("the job's spend ceiling of 1.00 USD is reached")

        result = await answer_questions(_Stopped(), _report(), QUESTIONS, ledger=LEDGER)

        assert [a.outcome for a in result.answers] == ["not_determinable"] * 2
        assert result.answers[0].checks[0].startswith("the question round was not written")
        assert result.degradations == [
            "The question round was not written: the job's spend ceiling of 1.00 USD is reached."
        ]

    @pytest.mark.asyncio
    async def test_a_value_quoted_beside_the_wrong_entry_is_asked_about_once(self) -> None:
        from maljan.pipeline.validation import CITATION_WRONG_ENTRY_CODE, EntryTexts

        texts = EntryTexts(
            texts={"ev_0001": "nothing of note", "ev_0003": "beacon to c2.example.net"},
            tools={"ev_0001": "strings", "ev_0003": "strings"},
        )
        wrong = _reply(
            1,
            "established",
            answer="It beacons to `c2.example.net` [ev_0001].",
            evidence_ids=["ev_0001"],
        )
        right = _reply(
            1,
            "established",
            answer="It beacons to `c2.example.net` [ev_0003].",
            evidence_ids=["ev_0003"],
        )
        reporter = _Reporter({"answers": [wrong]}, {"answers": [right]})

        result = await answer_questions(
            reporter, _report(), QUESTIONS[:1], ledger=LEDGER, evidence_texts=texts
        )

        assert result.tally.by_code.get(CITATION_WRONG_ENTRY_CODE) == 1
        assert result.tally.retries == 1
        (answer,) = result.answers
        assert (answer.outcome, answer.evidence_ids) == ("established", ["ev_0003"])

    @pytest.mark.asyncio
    async def test_an_answer_off_its_schema_is_asked_about_once(self) -> None:
        reporter = _Reporter(
            {"answers": [{"question": 1, "outcome": "certain", "answer": "x"}]},
            {"answers": [_reply(1, "out_of_scope")]},
        )

        result = await answer_questions(reporter, _report(), QUESTIONS[:1], ledger=LEDGER)

        assert result.tally.by_code[SCHEMA_CODE] >= 1
        assert [a.outcome for a in result.answers] == ["out_of_scope"]

    @pytest.mark.asyncio
    async def test_no_question_is_no_call(self) -> None:
        reporter = _Reporter()

        result = await answer_questions(reporter, _report(), [], ledger=LEDGER)

        assert result.answers == []
        assert reporter.turns == []

    @pytest.mark.asyncio
    async def test_no_report_model_leaves_each_question_not_determinable(self) -> None:
        result = await answer_questions(None, _report(), QUESTIONS, ledger=LEDGER)

        assert [a.outcome for a in result.answers] == ["not_determinable"] * 2
        assert result.answers[0].checks == ["no report model ran in this run"]

    @pytest.mark.asyncio
    async def test_a_failed_round_leaves_each_question_not_determinable(self) -> None:
        class _Broken:
            async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
                raise RuntimeError("down")

        result = await answer_questions(_Broken(), _report(), QUESTIONS, ledger=LEDGER)

        assert [a.outcome for a in result.answers] == ["not_determinable"] * 2
        assert "the question round failed" in result.answers[0].checks[0]


class TestThePrompt:
    def test_the_human_turn_lists_the_calls_the_open_questions_and_the_questions(self) -> None:
        evidence = _evidence(_isrs())
        system, human = build_messages(
            _report(), QUESTIONS, evidence, LEDGER, _isrs(), facts_block="PACK", run_state=""
        )
        body = str(human.content)

        assert system.content == SYSTEM_PROMPT
        assert body.startswith("PACK\n\n")
        assert "  - ev_0001 [static] strings: answered" in body
        assert "  - ev_0002 [static] strings: failed" in body
        assert "  - ev_0004 [static] strings: answered by a guard; no tool ran" in body
        assert "  - OQ1 static: " in body
        assert "[OQ1]" not in body
        # The analyst's words are quoted as every value from outside is.
        assert '1. "What is the C2 address?"\n2. "Does it persist through a Run key?"' in body

    def test_the_narrative_prompt_is_the_findings_and_its_task_as_before(self) -> None:
        report = _report()

        text = build_prompt_text(report)

        assert text == "\n".join(
            [
                *findings_lines(report),
                "TASK",
                "----",
                "Write the three narrative fields described in the system prompt. "
                "Return ONLY the JSON object shown there, with those keys.",
            ]
        )


class TestTheReport:
    def _answered(self) -> MalwareReport:
        report = _report()
        report.question_answers = [
            QuestionAnswer(
                question="What is the C2 address?",
                outcome="established",
                answer="It connects to a host named in the strings.",
                evidence_ids=["ev_0001"],
            ),
            QuestionAnswer(
                question="Does it persist through a Run key?",
                outcome="not_determinable",
                answered="limited_negative",
                looked_at=[],
                checks=["refused: answered limited negative with no coverage record"],
            ),
        ]
        return report

    @pytest.mark.parametrize(
        "shape",
        [("rich", rich_report), ("stored", stored_old_shape), ("hostile", hostile_report)],
        ids=lambda value: value[0] if isinstance(value, tuple) else str(value),
    )
    def test_a_job_asked_nothing_dumps_and_renders_byte_for_byte_as_before(
        self, shape: tuple[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Rendered at 73efe759, the dev head this change was cut from, with
        # the generation time fixed: the dump and the Markdown of a report of
        # a job asked nothing must not move by a byte.
        name, build = shape
        golden = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
        # The build stamps today's date into the report number, and the
        # version history and each MISP attribute's uuid are derived from it;
        # the fixtures were rendered on 2026-10-22, so the build stamps that.
        held = golden["dump"].get("front_matter")
        if held:
            stamp = MalwareReportBuilder._build_front_matter

            def _stamped(builder: MalwareReportBuilder, report: MalwareReport) -> Any:
                front = stamp(builder, report)
                front.report_date = held["report_date"]
                front.report_number = held["report_number"]
                return front

            monkeypatch.setattr(MalwareReportBuilder, "_build_front_matter", _stamped)
        report = build()
        report.generated_at = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)

        assert report.model_dump(mode="json") == golden["dump"]
        assert MarkdownRenderer().render(report) == golden["markdown"]

    @pytest.mark.parametrize("hostile", HOSTILE_TEXTS)
    @pytest.mark.parametrize("where", ["answer", "question"])
    def test_a_written_answer_or_question_restructures_nothing(
        self, hostile: str, where: str
    ) -> None:
        report = _report()
        fields = {"question": "What is it?", "answer": "Said."}
        fields[where] = hostile
        report.question_answers = [QuestionAnswer(outcome="partial", **fields)]

        markdown = MarkdownRenderer().render(report)
        html = HtmlRenderer().render(report)

        section = markdown[markdown.index("## Questions") : markdown.index("\n## 1. ")]
        assert re.search(r"^## 1\. Key findings · _", markdown, re.MULTILINE)
        # Only the section's own heading lines open a block in it.
        for line in section.splitlines()[1:]:
            if line.startswith("### Q1. "):
                continue
            assert not re.match(r"^(#|>|```|~~~|    |\d+\. |- |\+ |\* |-{3,}$|_{3,}$)", line), line
        assert not re.search(r"(?<!\\)<img", markdown)
        assert re.search(r'<h2 id="sec-key-findings">1\. Key findings', html)
        assert "<pre" not in html.split('id="sec-key-findings"')[0]
        assert "<img" not in html

    def test_the_answers_lead_the_report_with_their_outcomes(self) -> None:
        markdown = MarkdownRenderer().render(self._answered())

        assert markdown.index("## Questions asked of this run") < markdown.index("## 1. ")
        assert "### Q1. What is the C2 address?" in markdown
        assert "**Outcome:** established" in markdown
        assert "- Evidence: ev_0001" in markdown
        assert (
            "**Outcome:** not determinable from this run _(the report model answered limited "
            "negative; the platform's check refused it)_"
        ) in markdown
        assert "_Platform check:_ refused: answered limited negative" in markdown

    def test_the_html_report_carries_the_section(self) -> None:
        html = HtmlRenderer().render(self._answered())

        assert "Questions asked of this run" in html
        assert "not determinable from this run" in html

    def test_a_stored_answer_reads_back(self) -> None:
        dumped = self._answered().model_dump(mode="json")

        again = MalwareReport.model_validate(dumped)

        assert again.question_answers == self._answered().question_answers
        assert "answered" not in dumped["question_answers"][0]


class TestTheReportersCall:
    """``NarrativeAgent.ask``: the round's one call, held and recorded as the narrative's are."""

    @staticmethod
    def _agent(reply: Any) -> tuple[NarrativeAgent, Any]:
        from unittest.mock import AsyncMock, MagicMock

        llm = MagicMock()
        llm.ainvoke = AsyncMock(side_effect=[reply] if not isinstance(reply, Exception) else reply)
        agent = NarrativeAgent(llm=llm, token_ledger=object(), model_label="m")
        return agent, llm

    @pytest.mark.asyncio
    async def test_the_call_is_recorded_under_its_name_and_held_to_its_bound(
        self, monkeypatch: Any
    ) -> None:
        recorded: list[str] = []
        released: list[Any] = []
        agent, llm = self._agent(AIMessage(content="{}"))
        monkeypatch.setattr(agent, "_call_limit", lambda turns, **kw: (321, "a bound"))
        monkeypatch.setattr(
            "maljan.llm.context_window.output_bound_kwargs",
            lambda llm, bound: {"max_tokens": bound},
        )
        monkeypatch.setattr(
            "maljan.core.token_ledger.record_response_usage",
            lambda ledger, reply, **kw: recorded.append(kw["call"]),
        )
        monkeypatch.setattr(
            "maljan.reporting.narrative_agent.spend_release",
            lambda ledger, slot: released.append(slot),
        )

        reply = await agent.ask([AIMessage(content="q")], call=QUESTION_CALL, what="round's")

        assert reply.content == "{}"
        assert recorded == [QUESTION_CALL]
        assert llm.ainvoke.await_args.kwargs == {"max_tokens": 321}
        assert len(released) == 1

    @pytest.mark.asyncio
    async def test_the_slot_is_released_when_the_call_fails(self, monkeypatch: Any) -> None:
        released: list[Any] = []
        agent, _ = self._agent(ValueError("refused"))
        monkeypatch.setattr(agent, "_call_limit", lambda turns, **kw: (None, "none"))
        monkeypatch.setattr(
            "maljan.reporting.narrative_agent.spend_release",
            lambda ledger, slot: released.append(slot),
        )

        with pytest.raises(ValueError):
            await agent.ask([AIMessage(content="q")], call=QUESTION_CALL, what="round's")

        assert len(released) == 1

    def test_the_rounds_answer_counts_toward_the_report_tail(self) -> None:
        assert TAIL_CALLS[QUESTION_CALL] == "report"

    def test_the_overflow_sentence_names_the_round(self) -> None:
        agent, _ = self._agent(AIMessage(content="{}"))
        agent.window_tokens = 10
        agent.token_ledger = None

        agent._call_limit([AIMessage(content="x" * 400)], preview=True, what="question round's")

        assert any("question round's" in said for said in agent.degradations)
        assert isinstance(agent.validation_tally, ValidationTally)
