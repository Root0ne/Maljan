"""An analyst that removes a rejected id from a technique list has answered, and lost nothing.

A block whose TECHNIQUE line lists two ids is two claims. Asked about one of
them (an unknown id, a claim that reads as its absence), the analyst's natural
answer is the same block with that id taken off its line, which is one claim
against two. The rule that keeps the first answer when a retry comes back with
fewer claims read that as lost work, kept the first answer, and published the
id the analyst had just removed. Answers are compared by the claim blocks the
analyst wrote, so taking an id off a line loses no claim. The questions about
one id of a list say to take that id off the line, not to write NONE, which
would take the others with it. A finding about the block as a whole is raised
once per block, and every path names the block the analyst wrote.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst, read_claim_blocks
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    claim_block_indexes,
    mark_invalid_technique_ids,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


class _Analyst(BaseAnalyst):
    def __init__(self, first: AgentISR, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self._first = first
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def analyze_isr(self, data: str) -> AgentISR:
        return self._first

    def _invoke_llm_with_timeout(self, messages: list, timeout: int, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        return self._replies.pop(0)


@pytest.fixture(autouse=True)
def _no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    """The closest-technique ranking needs the ATT&CK index; these tests need none."""
    monkeypatch.setattr(
        knowledge, "resolve_technique", lambda text, k=5: {"candidates": []}, raising=False
    )


def _block(sentence: str, line: str) -> str:
    return (
        f"CLAIM: {sentence}\nEVIDENCE: [ev_0004] decoder routine\n"
        f"CONFIDENCE: 0.8\nTECHNIQUE: {line}\n"
    )


def _first(text: str) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)


def test_an_unknown_id_removed_from_its_list_is_not_kept() -> None:
    sentence = "The loader injects code into a remote process."
    analyst = _Analyst(_first(_block(sentence, "T1055, T9999")), [_block(sentence, "T1055")])

    result = analyst.safe_analyze_isr("raw data")

    assert [c.technique_id for c in result.claims] == ["T1055"]


def test_an_id_asked_as_absent_and_removed_from_its_list_is_not_published() -> None:
    sentence = (
        "The loader decodes its strings at run time and does not inject code into another process."
    )
    analyst = _Analyst(_first(_block(sentence, "T1140, T1055")), [_block(sentence, "T1140")])

    result = analyst.safe_analyze_isr("raw data")

    feedback = str(analyst.seen_turns[0][-1].content)
    assert "remove T1055 from this claim's TECHNIQUE line" in feedback
    assert [c.technique_id for c in result.claims] == ["T1140"]


def _codes_and_paths(isr: AgentISR) -> list[tuple[str, str]]:
    return [(v.code, v.path) for v in validate_isr(isr, attck=knowledge, sample=PE)]


def test_a_question_about_one_id_of_a_list_asks_to_take_it_off_the_line() -> None:
    sentence = "The loader decodes its strings and does not inject code into another process."
    isr = _first(_block(sentence, "T1140, T1055"))
    found = validate_isr(isr, attck=knowledge, sample=PE)

    (absence,) = [v for v in found if v.code == ABSENCE_CLAIM_CODE]
    assert "remove T1055 from this claim's TECHNIQUE line" in absence.message
    assert "TECHNIQUE: NONE" not in absence.message


def test_a_single_id_claim_is_still_asked_to_write_none() -> None:
    isr = _first(_block("The loader does not inject code into another process.", "T1055"))
    (absence,) = [
        v for v in validate_isr(isr, attck=knowledge, sample=PE) if v.code == ABSENCE_CLAIM_CODE
    ]

    assert "TECHNIQUE: NONE" in absence.message


def test_the_describe_question_on_a_list_asks_to_take_the_id_off_the_line() -> None:
    isr = _first(_block("The loader obfuscates its strings.", "T1027, T1003"))
    (asked,) = [
        v
        for v in validate_isr(isr, attck=knowledge, sample=PE)
        if v.code == CLAIM_DOES_NOT_DESCRIBE_CODE
    ]

    assert "remove T1003 from this claim's TECHNIQUE line" in asked.message
    assert "TECHNIQUE: NONE" not in asked.message


def test_a_finding_about_the_whole_block_is_raised_once_and_paths_name_the_blocks() -> None:
    single = ClaimEvidence(
        claim="The loader resolves imports by hash.",
        evidence_ref="[ev_0002]",
        confidence=0.7,
        technique_id="T1027.007",
    )
    listed = [
        ClaimEvidence(
            claim="The loader injects code into a remote process.",
            evidence_ref="",
            confidence=0.7,
            technique_id=tid,
        )
        for tid in ("T1055", "T1620")
    ]
    isr = AgentISR(agent_id="static", domain="static", claims=[single, *listed])

    assert claim_block_indexes(isr.claims) == [0, 1, 1]
    empty = [p for code, p in _codes_and_paths(isr) if code == "isr.empty_evidence"]
    assert empty == ["static.claims[1]"]


def test_an_unknown_id_in_a_list_marks_only_its_own_claim() -> None:
    claims = read_claim_blocks(
        _block("The loader resolves imports by hash.", "NONE")
        + "\n"
        + _block("The loader injects code into a remote process.", "T1055, T9999")
    ).claims
    isr = AgentISR(agent_id="static", domain="static", claims=claims)
    found = validate_isr(isr, attck=knowledge, sample=PE)

    (unknown,) = [v for v in found if v.code == "attck.unknown_id"]
    assert unknown.path.startswith("static.claims[1]")
    mark_invalid_technique_ids(isr, [unknown])
    assert [(c.technique_id, c.technique_id_valid) for c in isr.claims] == [
        (None, True),
        ("T1055", True),
        ("T9999", False),
    ]


def test_two_blocks_written_alike_are_two_blocks() -> None:
    """The block is recorded where the claim is read, not inferred from its words."""
    from maljan.pipeline.validation import count_claim_blocks

    sentence = "The loader injects code into a remote process."
    read = read_claim_blocks(_block(sentence, "T1055") + "\n---\n" + _block(sentence, "T1620"))

    assert read.read == 2
    assert [c.block for c in read.claims] == [0, 1]
    assert claim_block_indexes(read.claims) == [0, 1]
    assert count_claim_blocks(read.claims) == 2


def test_a_list_is_one_recorded_block() -> None:
    claims = read_claim_blocks(_block("The loader injects code.", "T1055, T1620")).claims

    assert [c.block for c in claims] == [0, 0]
    assert claim_block_indexes(claims) == [0, 0]


def test_claims_built_without_a_read_fall_back_to_their_words() -> None:
    listed = [
        ClaimEvidence(
            claim="The loader injects code.", evidence_ref="[ev_1]", confidence=0.7, technique_id=t
        )
        for t in ("T1055", "T1620")
    ]

    assert all(c.block is None for c in listed)
    assert claim_block_indexes(listed) == [0, 0]
