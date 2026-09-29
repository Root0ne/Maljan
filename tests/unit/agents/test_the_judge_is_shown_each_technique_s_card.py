"""The judge's technique question shows each technique's card, and asks once where a card says so.

A local run published Match Legitimate Resource Name or Location for "uses API
hashing to dynamically resolve Windows API calls at runtime": the sentence is
the sibling technique Dynamic API Resolution by that card's criterion, and no
claim or cited entry shows a name imitating a legitimate one. The card states
both facts; the judge is asked once, in the question it is already asked after
its verdict, and its answer stands. A technique whose claims cite no entry
holding the behaviour is marked unanchored in the report, and nothing is
dropped for it.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import (
    TECHNIQUE_QUESTION_SYSTEM,
    JudgeAgent,
    technique_question_text,
)
from maljan.extractors.capability_matrix import build_capability_matrix, judge_questions
from maljan.memory.technique_cards import card_lines, technique_card
from maljan.pipeline.validation import card_check_finding, unanchored_technique_finding
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from maljan.schemas.stix_models import Bundle, TechniqueReview
from maljan.tools import knowledge

CONFUSED = "T1036.005"  # Match Legitimate Resource Name or Location, carried by the bundle
CARD_ONLY = "T1027.005"  # Indicator Removal from Tools: described, and its card not met
SOUND = "T1055"  # Process Injection, carried and met by its card
NO_CARD = "T1112"  # Modify Registry: no card, asked as before

HASHING = (
    "The sample uses API hashing (CRC32) to dynamically resolve Windows API calls at runtime, "
    "evading static signature detection."
)
STRINGS = "The sample uses RC4 encryption and XOR encoding to protect its strings."
HASHES_ENTRY = "164 resolved hashes: kernel32.dll!VirtualAllocEx, kernel32.dll!WriteProcessMemory"
TEXTS = {
    "ev_0020": HASHES_ENTRY,
    "ev_0004": "PE: 5 imports from 2 libraries",
    "ev_0009": "kernel32!CreateRemoteThread called on a handle to explorer.exe",
}


def _pattern(tid: str, name: str, n: int) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-65544333221{n}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                _pattern(CONFUSED, "Match Legitimate Resource Name or Location", 1),
                _pattern(SOUND, "Process Injection", 2),
                _pattern(NO_CARD, "Modify Registry", 3),
                _pattern(CARD_ONLY, "Indicator Removal from Tools", 4),
            ]
        }
    )


def _claim(text: str, tid: str, ref: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.9, technique_id=tid)


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                _claim(HASHING, CONFUSED, "[ev_0004], [ev_0020]"),
                _claim(
                    "The sample injects code into explorer with WriteProcessMemory",
                    SOUND,
                    "[ev_0020], [ev_0009]",
                ),
                _claim("The sample writes a registry value", NO_CARD, "[ev_0004]"),
                _claim(STRINGS, CARD_ONLY, "[ev_0020]"),
            ],
        )
    }


class _Llm:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


def _ask(answer: str, isrs: dict[str, AgentISR] | None = None) -> tuple[Any, _Llm]:
    llm = _Llm(answer)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    review = asyncio.run(
        judge.decide_techniques(
            _bundle(), isrs or _isrs(), reports={"static": "r"}, evidence_texts=TEXTS
        )
    )
    return review, llm


def _cells(review: TechniqueReview | None) -> tuple[dict[str, Any], set[str]]:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    return {c.technique_id: c for c in cells}, {m.technique_id for m in mappings}


class TestTheCardCheck:
    def test_the_finding_names_the_sibling_and_the_unmet_components(self) -> None:
        claims = _isrs()["static"].claims[:1]

        finding = card_check_finding(CONFUSED, claims, TEXTS)

        assert "T1027.007 Dynamic API Resolution" in finding
        assert "a name or location of the sample imitates a legitimate one" in finding
        assert "the claim states the imitation is meant to pass as legitimate" in finding

    def test_a_technique_its_claims_meet_carries_no_finding(self) -> None:
        claims = _isrs()["static"].claims[1:2]

        assert card_check_finding(SOUND, claims, TEXTS) == ""

    def test_a_technique_with_no_card_carries_no_finding(self) -> None:
        assert card_check_finding(NO_CARD, _isrs()["static"].claims[2:], TEXTS) == ""

    def test_an_unknown_entry_leaves_a_component_undecided(self) -> None:
        claim = _claim("The sample does something to another program", SOUND, "[ev_0999]")

        assert card_check_finding(SOUND, [claim], TEXTS) == ""

    def test_a_claim_that_reads_as_absence_is_left_to_its_own_question(self) -> None:
        claim = _claim("The sample does not inject into any process", SOUND, "[ev_0004]")

        assert card_check_finding(SOUND, [claim], TEXTS) == ""


class TestWhatIsAsked:
    def test_a_carried_technique_its_card_questions_is_asked_once_as_a_card_question(
        self,
    ) -> None:
        questions, _ = judge_questions(
            _bundle().model_dump(), _isrs(), attck=knowledge, evidence_texts=TEXTS
        )
        by_id = {q.technique_id: q for q in questions}

        assert set(by_id) == {CONFUSED, CARD_ONLY}
        assert by_id[CARD_ONLY].kind == "card"
        assert by_id[CARD_ONLY].check == ""
        assert "T1027.013 Encrypted/Encoded File" in by_id[CARD_ONLY].card_check

    def test_a_technique_the_describe_check_asks_about_carries_the_card_check_too(
        self,
    ) -> None:
        questions, _ = judge_questions(
            _bundle().model_dump(), _isrs(), attck=knowledge, evidence_texts=TEXTS
        )
        confused = next(q for q in questions if q.technique_id == CONFUSED)

        assert confused.kind == "undescribed"
        assert confused.check
        assert confused.card_check == card_check_finding(
            CONFUSED, _isrs()["static"].claims[:1], TEXTS
        )

    def test_without_the_evidence_texts_nothing_new_is_asked(self) -> None:
        questions, _ = judge_questions(_bundle().model_dump(), _isrs(), attck=knowledge)

        assert [q.technique_id for q in questions] == [CONFUSED]
        assert all(q.card_check == "" for q in questions)

    def test_a_technique_named_only_on_a_finding_carries_the_card_check_it_earns(
        self,
    ) -> None:
        isrs = _isrs()
        isrs["static"].findings = [
            Finding(
                title="Reads the volume's serial number",
                detail="GetVolumeInformationW on the system drive",
                technique_ids=["T1006"],
                evidence_ids=["ev_0004"],
            )
        ]

        questions, _ = judge_questions(
            _bundle().model_dump(), isrs, attck=knowledge, evidence_texts=TEXTS
        )
        finding = next(q for q in questions if q.technique_id == "T1006")

        assert finding.kind == "finding"
        assert "T1082 System Information Discovery" in finding.card_check

    def test_the_question_shows_the_card_and_the_card_check(self) -> None:
        questions, _ = judge_questions(
            _bundle().model_dump(), _isrs(), attck=knowledge, evidence_texts=TEXTS
        )

        text = technique_question_text(questions)

        card = technique_card(CARD_ONLY)
        assert card is not None
        for line in card_lines(card, CARD_ONLY):
            assert f"   {line}" in text
        card_only = next(q for q in questions if q.technique_id == CARD_ONLY)
        assert f"   card check: {card_only.card_check}" in text
        assert "in your bundle; its card's check found the claims naming it do not meet it" in text
        assert "card" in TECHNIQUE_QUESTION_SYSTEM

    def test_every_asked_technique_with_a_card_shows_it(self) -> None:
        isrs = _isrs()
        isrs["static"].claims.append(
            _claim("The binary reports to a remote server", "T1573", "[ev_0004]")
        )
        questions, _ = judge_questions(
            _bundle().model_dump(), isrs, attck=knowledge, evidence_texts=TEXTS
        )

        text = technique_question_text(questions)

        assert "card T1573 Encrypted Channel" in text

    def test_the_judge_is_asked_once_and_the_answer_records_the_card_check(self) -> None:
        review, llm = _ask(f"{CONFUSED}: drop: the claim describes API resolution")

        assert len(llm.calls) == 1
        assert isinstance(review, TechniqueReview)
        assert review.asked == [CONFUSED, CARD_ONLY]
        assert review.card[CONFUSED] == card_check_finding(
            CONFUSED, _isrs()["static"].claims[:1], TEXTS
        )


class TestAnchoring:
    def test_a_technique_whose_cited_entries_hold_no_term_of_it_is_unanchored(self) -> None:
        finding = unanchored_technique_finding(
            CONFUSED, _isrs()["static"].claims[:1], TEXTS, knowledge
        )

        assert "ev_0004" in finding and "ev_0020" in finding
        assert "holds" in finding

    def test_a_technique_with_one_anchored_claim_is_anchored(self) -> None:
        claims = [
            _claim("The sample writes code into explorer", SOUND, "[ev_0004]"),
            _claim("The sample injects code", SOUND, "[ev_0009]"),
        ]

        assert unanchored_technique_finding(SOUND, claims, TEXTS, knowledge) == ""

    def test_an_entry_holding_an_identifier_the_claim_names_anchors_it(self) -> None:
        # A decompiled routine holds its code, not the technique's words.
        claim = _claim("FUN_1400c2c4 hides its files from the user", "T1564", "[ev_0050]")
        texts = {"ev_0050": "void FUN_1400c2c4(void) { uVar1 = FUN_14000ae78(DAT_10030); }"}

        assert unanchored_technique_finding("T1564", [claim], texts, knowledge) == ""
        assert unanchored_technique_finding(
            "T1564", [claim], {"ev_0050": "void other(void) {}"}, knowledge
        ).endswith("nor an identifier the claims name")

    def test_a_sibling_is_not_named_while_a_cited_entry_uses_the_card_s_own_words(
        self,
    ) -> None:
        claim = _claim(HASHING, CONFUSED, "[ev_0050]")

        finding = card_check_finding(
            CONFUSED, [claim], {"ev_0050": "copied as svchost.exe under System32"}
        )

        assert "T1027.007" not in finding

    def test_a_claim_citing_nothing_is_unanchored(self) -> None:
        claim = _claim("The sample injects code", SOUND, "static analysis")

        assert unanchored_technique_finding(SOUND, [claim], TEXTS, knowledge) == (
            "no claim naming T1055 Process Injection cites an evidence id"
        )

    def test_an_entry_whose_text_is_unknown_decides_nothing(self) -> None:
        claim = _claim("The sample injects code", SOUND, "[ev_0999]")

        assert unanchored_technique_finding(SOUND, [claim], TEXTS, knowledge) == ""

    def test_the_answer_records_every_unanchored_technique_asked_or_not(self) -> None:
        review, _ = _ask(f"{CONFUSED}: keep: the name is copied")

        assert isinstance(review, TechniqueReview)
        # The registry claim cites an import list, which holds no word of it.
        assert set(review.unanchored) == {CONFUSED, NO_CARD, CARD_ONLY}


class TestTheReportShowsIt:
    def test_a_kept_technique_is_published_with_the_card_check_and_the_mark(self) -> None:
        review, _ = _ask(f"{CONFUSED}: keep: the name is copied")

        cells, published = _cells(review)

        assert CONFUSED in published
        note = cells[CONFUSED].note
        assert "T1027.007 Dynamic API Resolution" in note
        assert "unanchored:" in note
        assert "kept by the judge when asked (the name is copied)" in note

    def test_a_dropped_technique_says_the_card_check_it_was_asked_after(self) -> None:
        review, _ = _ask(f"{CONFUSED}: drop: the claim describes API resolution")

        cells, published = _cells(review)

        assert CONFUSED not in published
        assert "; the technique card check found" in cells[CONFUSED].not_published
        assert "unanchored:" in cells[CONFUSED].note

    def test_an_unanchored_technique_nobody_asked_about_is_marked_not_dropped(self) -> None:
        isrs = _isrs()
        isrs["static"].claims[0] = _claim(
            "The sample copies itself as svchost.exe to masquerade as a legitimate file",
            CONFUSED,
            "[ev_0004]",
        )
        isrs["static"].claims = [c for c in isrs["static"].claims if c.technique_id != CARD_ONLY]
        review, llm = _ask("", isrs)

        assert llm.calls == []
        assert isinstance(review, TechniqueReview)
        bundle = _bundle()
        bundle.x_maljan_technique_review = review
        cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=isrs)
        row = next(c for c in cells if c.technique_id == CONFUSED)
        assert CONFUSED in {m.technique_id for m in mappings}
        assert row.note.startswith("unanchored:")
