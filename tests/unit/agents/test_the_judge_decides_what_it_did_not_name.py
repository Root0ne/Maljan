"""The judge decides the techniques the analysts named and its bundle does not carry.

A paid run published a technique one analyst claimed at 0.30 that the judge's
bundle left out, and listed three techniques that appeared only on findings,
which no check had ever asked about. After the verdict the judge is asked
once, in one question, about both kinds — keep or drop, with a reason — and the
report publishes per its answer. A dropped technique says so in the judge's
words; with no answer nothing is withheld, and the row says the judge did not
confirm it.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.agents.judge_agent import (
    TECHNIQUE_ANSWER_FORM,
    TECHNIQUE_ANSWER_UNREAD,
    TECHNIQUE_QUESTION_NOT_ASKED,
    TECHNIQUE_QUESTION_SYSTEM,
    JudgeAgent,
    read_technique_answer,
    technique_question_text,
)
from maljan.extractors.capability_matrix import (
    FINDING_ONLY_REASON,
    NOT_ASKED_UNKNOWN_ID,
    build_capability_matrix,
    judge_questions,
    techniques_for_the_judge,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import (
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
    Finding,
)
from maljan.schemas.stix_models import Bundle, TechniqueDecision, TechniqueReview

# In the bundle; claimed by one analyst and left out of it; named on a finding only.
IN_BUNDLE = "T1112"
LEFT_OUT = "T1568.002"
FINDING_ONLY = "T1003"


def _bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "Modify Registry",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": IN_BUNDLE}
                    ],
                }
            ]
        }
    )


def _isrs() -> dict[str, AgentISR]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(
                    claim="The sample generates its server names from the date",
                    evidence_ref="decoded routine [ev_0012] and [ev_0013]",
                    confidence=0.3,
                    technique_id=LEFT_OUT,
                ),
                ClaimEvidence(
                    claim="The sample writes a registry value",
                    evidence_ref="[ev_0002]",
                    confidence=0.8,
                    technique_id=IN_BUNDLE,
                ),
            ],
            findings=[
                Finding(
                    title="Reads credentials from process memory",
                    detail="opens the credential store process",
                    technique_ids=[FINDING_ONLY, IN_BUNDLE],
                    evidence_ids=["ev_0007"],
                )
            ],
        )
    }


class _Llm:
    """Answers each call from a queue, and remembers what it was sent."""

    def __init__(self, *answers: Any) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        answer = self._answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return MagicMock(content=answer)


REPORTS = {"network": "The network analyst's report on the sample."}
EVIDENCE = {
    "ev_0012": "decoded routine: builds names from the current date",
    "ev_0013": "resolver calls for each generated name",
    "ev_0007": "OpenProcess on the credential store process",
}


def _ask(
    *answers: Any, timed_out: bool = False, judge: JudgeAgent | None = None
) -> tuple[TechniqueReview | None, _Llm]:
    llm = _Llm(*answers)
    if judge is None:
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    else:
        judge.llm = llm  # type: ignore[assignment]
    review = asyncio.run(
        judge.decide_techniques(
            _bundle(),
            _isrs(),
            reports=REPORTS,
            evidence_summary="EVIDENCE SUMMARY — the summary block",
            evidence_texts=EVIDENCE,
            facts_block="=== PACK ===\nthe pack",
            run_state="the run state",
            verdict_timed_out=timed_out,
        )
    )
    return review, llm


def _published(review: TechniqueReview | None) -> tuple[dict[str, Any], set[str]]:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    return {c.technique_id: c for c in cells}, {m.technique_id for m in mappings}


def _markdown(review: TechniqueReview | None) -> str:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        capability_matrix=cells,
        ttp_mappings=mappings,
    )
    return MarkdownRenderer().render(report)


class TestWhatIsAsked:
    def test_a_left_out_claim_and_a_finding_only_technique_are_asked_the_bundle_s_are_not(
        self,
    ) -> None:
        questions = techniques_for_the_judge(_bundle().model_dump(), _isrs())

        assert [(q.technique_id, q.kind) for q in questions] == [
            (LEFT_OUT, "claimed"),
            (FINDING_ONLY, "finding"),
        ]
        assert questions[0].mentions == [
            (
                "network",
                "The sample generates its server names from the date",
                ["ev_0012", "ev_0013"],
            )
        ]
        assert questions[1].mentions == [
            (
                "network",
                "Reads credentials from process memory — opens the credential store process",
                ["ev_0007"],
            )
        ]

    def test_one_tool_free_question_with_the_run_state_and_the_pack(self) -> None:
        _review, llm = _ask(f"{LEFT_OUT}: keep: the routine is shown\n{FINDING_ONLY}: drop: no")

        assert len(llm.calls) == 1
        system, human = llm.calls[0]
        assert system.content == TECHNIQUE_QUESTION_SYSTEM
        assert human.type == "human"
        text = str(human.content)
        assert text.index("the run state") < text.index("the pack") < text.index(LEFT_OUT)
        assert "ev_0012, ev_0013" in text and "ev_0007" in text
        assert text.endswith(TECHNIQUE_ANSWER_FORM)

    def test_nothing_to_ask_asks_nothing(self) -> None:
        llm = _Llm()
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        review = asyncio.run(judge.decide_techniques(_bundle(), {}))

        assert review is None
        assert llm.calls == []


class TestTheAnswerIsRead:
    def test_keep_and_drop_with_their_reasons_whole(self) -> None:
        reason = "the decoded routine at [ev_0012] builds the names; " + "and more " * 60
        answer = (
            f"Here you go.\n- **{LEFT_OUT}**: KEEP — {reason}\n2. {FINDING_ONLY}: drop: no call"
        )

        decisions = read_technique_answer(answer, [LEFT_OUT, FINDING_ONLY])

        assert decisions == [
            TechniqueDecision(technique_id=LEFT_OUT, decision="keep", reason=reason.strip()),
            TechniqueDecision(technique_id=FINDING_ONLY, decision="drop", reason="no call"),
        ]

    def test_a_line_about_a_technique_not_asked_is_not_read(self) -> None:
        assert read_technique_answer("T1999: drop: not asked", [LEFT_OUT]) == []


class TestKeep:
    def test_both_are_published_and_the_rows_say_the_judge_kept_them(self) -> None:
        review, _llm = _ask(
            f"{LEFT_OUT}: keep: the routine is shown\n{FINDING_ONLY}: keep: the call is there"
        )

        cells, published = _published(review)

        assert {LEFT_OUT, FINDING_ONLY, IN_BUNDLE} <= published
        assert cells[LEFT_OUT].note == "kept by the judge when asked (the routine is shown)"
        assert cells[FINDING_ONLY].not_published == ""


class TestDrop:
    def test_a_dropped_technique_is_not_published_and_says_why(self) -> None:
        review, _llm = _ask(
            f"{LEFT_OUT}: drop: one analyst at 0.30 and no routine in the evidence\n"
            f"{FINDING_ONLY}: drop: nothing opens that process"
        )

        cells, published = _published(review)

        assert LEFT_OUT not in published and FINDING_ONLY not in published
        assert IN_BUNDLE in published
        assert cells[LEFT_OUT].not_published == (
            "the judge dropped it (one analyst at 0.30 and no routine in the evidence)"
        )

    def test_the_report_says_the_judge_dropped_it(self) -> None:
        review, _llm = _ask(f"{LEFT_OUT}: drop: no routine in the evidence")

        markdown = _markdown(review)

        assert "not published: the judge dropped it (no routine in the evidence)" in markdown


class TestNoAnswer:
    @pytest.mark.parametrize(
        ("answers", "timed_out", "unanswered"),
        [
            ((TimeoutError(),), False, "the question timed out after"),
            ((RuntimeError("down"),), False, "the question failed (RuntimeError)"),
            (("I cannot tell.",), False, TECHNIQUE_ANSWER_UNREAD),
            ((), True, TECHNIQUE_QUESTION_NOT_ASKED),
        ],
    )
    def test_nothing_is_withheld_and_the_claim_is_marked_unconfirmed(
        self, answers: tuple[Any, ...], timed_out: bool, unanswered: str
    ) -> None:
        review, _llm = _ask(*answers, timed_out=timed_out)

        assert review is not None
        assert str(review.unanswered).startswith(unanswered)
        cells, published = _published(review)
        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
        # A finding-only technique is what it was without the question.
        assert cells[FINDING_ONLY].not_published == FINDING_ONLY_REASON

    def test_a_technique_the_answer_skipped_is_marked_unconfirmed(self) -> None:
        review, _llm = _ask(f"{FINDING_ONLY}: keep: the call is there")

        cells, published = _published(review)

        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
        assert "not confirmed by the judge" in _markdown(review)

    def test_a_bundle_asked_nothing_publishes_as_before(self) -> None:
        cells, published = _published(None)

        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == ""
        assert cells[FINDING_ONLY].not_published == FINDING_ONLY_REASON


class TestTheJudgeNodeKeepsTheAnswer:
    def test_the_answer_is_on_the_judge_s_bundle(self) -> None:
        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(bundle=_bundle(), violations=[], retries=0, fed_back={})
        )
        review = TechniqueReview(
            asked=["T1055"],
            decisions=[TechniqueDecision(technique_id="T1055", decision="drop", reason="r")],
        )
        judge.decide_techniques = AsyncMock(return_value=review)

        update = asyncio.run(make_judge_node(container)(_state([])))

        assert update["stix_output"]["x_maljan_technique_review"] == review.model_dump()
        kwargs = judge.decide_techniques.await_args.kwargs
        assert kwargs["verdict_timed_out"] is False
        assert kwargs["run_state"]
        # What the verdict was drawn from goes with the question.
        assert kwargs["reports"] == {"static": "static findings"}
        assert "evidence_texts" in kwargs and "routed" in kwargs


def _read(text: str) -> list[tuple[str, str, str]]:
    return [
        (d.technique_id, d.decision, d.reason)
        for d in read_technique_answer(text, [LEFT_OUT, FINDING_ONLY])
    ]


class TestEachLineStandsAlone:
    def test_reasonless_lines_one_after_another(self) -> None:
        assert _read(f"{LEFT_OUT}: drop\n{FINDING_ONLY}: keep: shown") == [
            (LEFT_OUT, "drop", ""),
            (FINDING_ONLY, "keep", "shown"),
        ]

    def test_reasonless_lines_with_a_blank_line_between(self) -> None:
        assert _read(f"{LEFT_OUT}: keep\n\n{FINDING_ONLY}: drop: absent") == [
            (LEFT_OUT, "keep", ""),
            (FINDING_ONLY, "drop", "absent"),
        ]


class TestTheAnswerShapes:
    def test_the_json_array_asked_for(self) -> None:
        answer = (
            f'[{{"id": "{LEFT_OUT}", "decision": "drop", "reason": "no routine"}}, '
            f'{{"id": "{FINDING_ONLY}", "decision": "keep", "reason": "the call is there"}}]'
        )
        assert _read(answer) == [
            (LEFT_OUT, "drop", "no routine"),
            (FINDING_ONLY, "keep", "the call is there"),
        ]

    def test_a_fenced_array_after_prose_that_cites_an_entry(self) -> None:
        answer = (
            "Looking at [ev_0012] again.\n```json\n"
            f'[{{"id": "{LEFT_OUT}", "decision": "keep", "reason": "shown at [ev_0012]"}}]\n```'
        )
        assert _read(answer) == [(LEFT_OUT, "keep", "shown at [ev_0012]")]

    def test_an_object_keyed_by_id_and_one_holding_decisions(self) -> None:
        keyed = f'{{"{LEFT_OUT}": {{"decision": "drop", "reason": "weak"}}}}'
        held = f'{{"decisions": [{{"id": "{LEFT_OUT}", "decision": "keep", "reason": "ok"}}]}}'
        assert _read(keyed) == [(LEFT_OUT, "drop", "weak")]
        assert _read(held) == [(LEFT_OUT, "keep", "ok")]

    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            (f"| {LEFT_OUT} | drop | weak |", "weak"),
            (f"{LEFT_OUT} (Domain Generation Algorithms): drop: no routine", "no routine"),
            (f"**{LEFT_OUT} — Domain Generation Algorithms**: drop — no routine", "no routine"),
            (f"- {LEFT_OUT} → drop", ""),
            (f"{LEFT_OUT}: Decision: drop.", ""),
        ],
    )
    def test_free_lines(self, line: str, reason: str) -> None:
        assert _read(line) == [(LEFT_OUT, "drop", reason)]

    def test_a_reasoning_block_is_not_the_answer(self) -> None:
        answer = f"<think>{LEFT_OUT}: keep: maybe</think>\n{LEFT_OUT}: drop: nothing shows it"
        assert _read(answer) == [(LEFT_OUT, "drop", "nothing shows it")]

    def test_the_last_answer_for_an_id_wins(self) -> None:
        answer = f"{LEFT_OUT}: keep: first thought\n{LEFT_OUT}: drop: on reflection"
        assert _read(answer) == [(LEFT_OUT, "drop", "on reflection")]

    def test_a_structured_answer_is_read_from_the_schema(self, monkeypatch) -> None:
        from maljan.agents.judge_agent import TechniqueAnswer, TechniqueAnswerRow

        parsed = TechniqueAnswer(
            decisions=[TechniqueAnswerRow(id=LEFT_OUT, decision="drop", reason="schema")]
        )

        class _Structured:
            async def ainvoke(self, messages: list[Any]) -> Any:
                return {"raw": MagicMock(content="{}"), "parsed": parsed, "parsing_error": None}

        judge = JudgeAgent(llm=MagicMock())
        monkeypatch.setattr(judge, "_supports_structured_output", lambda: True)
        judge.llm.with_structured_output = lambda *a, **k: _Structured()

        review = asyncio.run(judge.decide_techniques(_bundle(), _isrs()))

        assert review is not None
        assert [(d.technique_id, d.decision, d.reason) for d in review.decisions] == [
            (LEFT_OUT, "drop", "schema")
        ]


class TestTheQuestionShowsWhatItAsksAbout:
    def test_the_reports_the_verdict_and_the_cited_entries_are_shown(self) -> None:
        _review, llm = _ask(f"{LEFT_OUT}: keep: shown")

        text = str(llm.calls[0][1].content)
        assert REPORTS["network"] in text
        assert "EVIDENCE SUMMARY — the summary block" in text
        assert "YOUR VERDICT:" in text
        assert f"TECHNIQUES YOUR BUNDLE CARRIES: {IN_BUNDLE}" in text
        for entry_text in EVIDENCE.values():
            assert entry_text in text

    def test_the_system_text_says_what_is_shown(self) -> None:
        for shown in ("reports", "verdict", "evidence entry"):
            assert shown in TECHNIQUE_QUESTION_SYSTEM

    def test_evidence_that_does_not_fit_is_shortened_said_and_recorded(self) -> None:
        judge = JudgeAgent(llm=MagicMock())
        judge._question_room = lambda fixed, cap: 60  # type: ignore[method-assign]

        review, llm = _ask(f"{LEFT_OUT}: keep: shown", judge=judge)

        text = str(llm.calls[0][1].content)
        assert review is not None and review.shortened
        assert review.shortened in text
        assert EVIDENCE["ev_0012"] not in text

    def test_the_room_is_the_window_less_the_cap_and_the_rest(self) -> None:
        from types import SimpleNamespace

        judge = JudgeAgent(llm=MagicMock())
        budget = SimpleNamespace(
            derives=True, chars_per_token=4, window=SimpleNamespace(tokens=1000)
        )
        judge._context_budget = lambda: budget  # type: ignore[method-assign]

        assert judge._question_room(500, 200) == (1000 - 200) * 4 - 500

    def test_no_learned_window_shows_everything_whole(self) -> None:
        from maljan.agents.judge_agent import _fit_evidence

        assert _fit_evidence(dict(EVIDENCE), None) == (dict(EVIDENCE), "")


class TestWhatCannotBePublishedIsNotAsked:
    def test_an_unknown_id_and_a_flagged_claim_are_recorded_not_asked(self) -> None:
        isrs = _isrs()
        isrs["network"].findings[0].technique_ids.append("T1999")
        isrs["network"].claims[0].technique_id_valid = False

        questions, not_asked = judge_questions(_bundle().model_dump(), isrs)

        assert [q.technique_id for q in questions] == [FINDING_ONLY]
        assert not_asked == {LEFT_OUT: NOT_ASKED_UNKNOWN_ID, "T1999": NOT_ASKED_UNKNOWN_ID}

    def test_a_technique_the_platform_cannot_host_is_not_asked(self) -> None:
        questions, not_asked = judge_questions(
            _bundle().model_dump(), _isrs(), {"platform": "android", "file_type": "apk"}
        )

        assert FINDING_ONLY not in [q.technique_id for q in questions]
        assert not_asked[FINDING_ONLY].startswith("not asked: ")


class TestTheDecisionIsReadFromItsPosition:
    def test_a_decision_word_inside_the_reason_is_not_the_decision(self) -> None:
        line = "T1105 — the second stage is dropped to disk by the loader; keep"

        assert [
            (d.technique_id, d.decision, d.reason) for d in read_technique_answer(line, ["T1105"])
        ] == [("T1105", "keep", "the second stage is dropped to disk by the loader")]

    def test_a_negated_word_before_the_decision_is_not_the_decision(self) -> None:
        line = f"{LEFT_OUT}: I would not keep this; drop — nothing shows it"

        assert _read(line) == [(LEFT_OUT, "drop", "nothing shows it")]

    def test_a_json_decision_that_is_not_one_word_states_none(self) -> None:
        answer = f'[{{"id": "{LEFT_OUT}", "decision": "do not keep; drop", "reason": "x"}}]'

        assert _read(answer) == []

    def test_kept_and_dropped_count_only_in_the_decision_position(self) -> None:
        assert _read(f"{LEFT_OUT}: dropped: gone") == [(LEFT_OUT, "drop", "gone")]
        assert _read(f"{LEFT_OUT} was kept by the analyst; drop") == [
            (LEFT_OUT, "drop", "was kept by the analyst")
        ]

    def test_a_slash_written_sub_technique_is_the_same_id(self) -> None:
        assert _read(f"{LEFT_OUT.replace('.', '/')}: drop: x") == [(LEFT_OUT, "drop", "x")]
        assert _read(f'{{"{LEFT_OUT.replace(".", "/")}": "keep"}}') == [(LEFT_OUT, "keep", "")]


class TestTheEvidenceIsShownAsStored:
    def test_stored_case_the_tool_and_the_marks(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.judge_agent import (
            LOWERED_ENTRY_MARK,
            PARTIAL_ENTRY_MARK,
            question_evidence,
        )

        ledger = [
            SimpleNamespace(
                id="ev_0012", output="Key HKCU\\Run = C:\\A.exe", tool="reg", truncated=True
            ),
            SimpleNamespace(id="ev_0013", output="", tool="dns", truncated=False),
        ]
        corpus = SimpleNamespace(
            text_for=lambda entry_id: "resolver copy" if entry_id == "ev_0013" else ""
        )

        shown = question_evidence(ledger, corpus)
        text = technique_question_text(
            techniques_for_the_judge(_bundle().model_dump(), _isrs()), shown
        )

        assert "[ev_0012] (reg) — " + PARTIAL_ENTRY_MARK + "\nKey HKCU\\Run = C:\\A.exe" in text
        assert "[ev_0013] (dns) — " + LOWERED_ENTRY_MARK + "\nresolver copy" in text

    def test_an_id_cited_in_capitals_finds_its_entry(self) -> None:
        isrs = _isrs()
        isrs["network"].findings[0].evidence_ids = ["EV_0007"]

        text = technique_question_text(
            techniques_for_the_judge(_bundle().model_dump(), isrs), {"ev_0007": "OpenProcess"}
        )

        assert "[ev_0007]\nOpenProcess" in text
        assert "no text recorded" not in text.split("[ev_0007]")[1][:40]


class TestTheStructuredPathsEdges:
    def _judge(self, monkeypatch, structured: Any, plain: Any = None) -> tuple[JudgeAgent, list]:
        asked: list[str] = []

        class _Model:
            def with_structured_output(self, *a: Any, **k: Any) -> Any:
                return structured

            async def ainvoke(self, messages: list[Any]) -> Any:
                asked.append("text")
                return MagicMock(content=plain)

        judge = JudgeAgent(llm=_Model())  # type: ignore[arg-type]
        monkeypatch.setattr(judge, "_supports_structured_output", lambda: True)
        return judge, asked

    def test_a_function_call_answer_is_read_from_its_arguments(self, monkeypatch) -> None:
        from langchain_core.messages import AIMessage

        raw = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "TechniqueAnswer",
                    "args": {"decisions": [{"id": LEFT_OUT, "decision": "drop", "reason": "r"}]},
                    "id": "c1",
                }
            ],
        )

        class _Structured:
            async def ainvoke(self, messages: list[Any]) -> Any:
                return {"raw": raw, "parsed": None, "parsing_error": ValueError("no")}

        judge, _asked = self._judge(monkeypatch, _Structured())
        review = asyncio.run(judge.decide_techniques(_bundle(), _isrs()))

        assert review is not None
        assert [(d.technique_id, d.decision) for d in review.decisions] == [(LEFT_OUT, "drop")]

    def test_a_refused_schema_is_asked_once_in_text(self, monkeypatch) -> None:
        class _Refused:
            async def ainvoke(self, messages: list[Any]) -> Any:
                raise ValueError("400: response_format is not supported")

        judge, asked = self._judge(monkeypatch, _Refused(), plain=f"{LEFT_OUT}: keep: shown")
        review = asyncio.run(judge.decide_techniques(_bundle(), _isrs()))

        assert asked == ["text"]
        assert review is not None
        assert [(d.technique_id, d.decision) for d in review.decisions] == [(LEFT_OUT, "keep")]

    def test_an_answer_in_another_shape_is_still_a_call_on_the_ledger(self, monkeypatch) -> None:
        from maljan.core.token_ledger import TokenLedger

        class _Bare:
            async def ainvoke(self, messages: list[Any]) -> Any:
                return MagicMock(content="")

        judge, _asked = self._judge(monkeypatch, _Bare())
        judge.token_ledger = TokenLedger()

        asyncio.run(judge.decide_techniques(_bundle(), _isrs()))

        assert judge.token_ledger.snapshot()["llm_calls"] == 1
