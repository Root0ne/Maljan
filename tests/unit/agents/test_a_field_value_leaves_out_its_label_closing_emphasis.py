"""A field value leaves out the emphasis its label closes after the colon (T-550).

Models mark a label colon and all: ``**EVIDENCE:** [ev_…]``. The ``**``
after the colon closes the label's emphasis and is no part of the value, so
the evidence reads ``[ev_…]`` and not ``** [ev_…]``, a CONFIDENCE value the
reader cannot read is quoted without it, and a TECHNIQUE line asked about is
asked as the analyst wrote it. A field that holds nothing but that emphasis
is an empty field. Emphasis that opens the value ("EVIDENCE: **[ev_…]**")
stays part of it.

Every value here is made up for the test.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from malspark.agents import base_agent
from malspark.agents.base_agent import read_claim_blocks
from tests.linear_cost import assert_scales

SENTENCE = "Routine 0x4100 decodes its strings at run time."

# A label marked colon and all, as models write it.
MARKS = ["**{}:**", "__{}:__", "*{}:*", "_{}:_", "{}:**"]


def _read(text: str) -> list[tuple[str, str, float, str | None, str | None]]:
    read = read_claim_blocks(text, require_evidence=True)
    return [
        (
            claim.claim,
            claim.evidence_ref,
            claim.confidence,
            claim.technique_id,
            claim.technique_line,
        )
        for claim in read.claims
    ]


@pytest.mark.parametrize("mark", MARKS)
def test_the_evidence_leaves_out_the_closing_emphasis(mark: str) -> None:
    evidence = mark.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\n{evidence} [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, None)]


@pytest.mark.parametrize("mark", MARKS)
def test_an_inline_evidence_leaves_out_the_closing_emphasis(mark: str) -> None:
    evidence = mark.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.8 {evidence} [ev_0002] TECHNIQUE: T1027\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


def test_every_field_marked_colon_and_all_reads_as_written_plain() -> None:
    text = (
        f"CLAIM: {SENTENCE}\n**EVIDENCE:** [ev_0002]\n**CONFIDENCE:** 0.8\n"
        "**TECHNIQUE:** T1027 (likely)\n"
    )
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, "T1027 (likely)")]


@pytest.mark.parametrize("mark", MARKS)
def test_an_unread_confidence_is_quoted_without_the_closing_emphasis(mark: str) -> None:
    confidence = mark.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\n{confidence} high\n"
    read = read_claim_blocks(text, require_evidence=True)
    assert read.claims == []
    assert list(read.confidence_unreadable) == ["high"]


@pytest.mark.parametrize("mark", MARKS)
def test_an_inline_technique_line_leaves_out_the_closing_emphasis(mark: str) -> None:
    technique = mark.format("TECHNIQUE")
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.8\nEVIDENCE: [ev_0002] {technique} T1027 or T1140\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, "T1027 or T1140")]


@pytest.mark.parametrize("after", ["\n**CONFIDENCE:** 0.8\n", " **CONFIDENCE:** 0.8\n"])
def test_an_evidence_field_of_only_the_closing_emphasis_is_empty(after: str) -> None:
    text = f"CLAIM: {SENTENCE}\n**EVIDENCE:**{after}"
    read = read_claim_blocks(text, require_evidence=True)
    assert read.claims == []
    assert read.without_evidence == 1
    cited = f"CLAIM: {SENTENCE} [ev_0003]\n**EVIDENCE:**{after}"
    assert [claim.evidence_ref for claim in read_claim_blocks(cited).claims] == ["[ev_0003]"]


@pytest.mark.parametrize("after", ["\n", " EVIDENCE: [ev_0002]\n"])
def test_a_confidence_field_of_only_the_closing_emphasis_is_empty(after: str) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\n**CONFIDENCE:**{after}"
    assert list(read_claim_blocks(text).confidence_unreadable) == ["(empty)"]


def test_a_technique_field_of_only_the_closing_emphasis_claims_none() -> None:
    text = f"CLAIM: {SENTENCE}\n**TECHNIQUE:** **EVIDENCE:** [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, None)]


@pytest.mark.parametrize(
    ("written", "evidence"),
    [
        ("EVIDENCE: **[ev_0002]** strings", "**[ev_0002]** strings"),
        ("**EVIDENCE:** **[ev_0002]** strings", "**[ev_0002]** strings"),
        ("EVIDENCE: ** [ev_0002]", "** [ev_0002]"),
        ("**EVIDENCE:**[ev_0002]", "**[ev_0002]"),
        ("EVIDENCE: _[ev_0002]_", "_[ev_0002]_"),
        ("EVIDENCE:*see* [ev_0002]", "*see* [ev_0002]"),
    ],
)
def test_emphasis_that_opens_the_value_stays_in_it(written: str, evidence: str) -> None:
    text = f"CLAIM: {SENTENCE}\n{written}\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, evidence, 0.8, None, None)]


@pytest.mark.parametrize("end", ["x", " x", ""])
@pytest.mark.parametrize(
    "run",
    [
        lambda size: "*" * size,
        lambda size: "_" * size,
        lambda size: "*_" * size,
        lambda size: "**" + " " * size,
        lambda size: "**" + " *" * size,
    ],
    ids=["stars", "underscores", "mixed", "spaces", "space-star"],
)
@pytest.mark.parametrize(
    ("name", "start"),
    [
        ("_BLOCK_EVIDENCE_LABEL_RE", "x EVIDENCE:"),
        ("_LINE_CONFIDENCE_RE", "CONFIDENCE:"),
        ("_BLOCK_CONFIDENCE_RE", "x CONFIDENCE:"),
        ("_LINE_TECHNIQUE_RE", "TECHNIQUE:"),
        ("_BLOCK_TECHNIQUE_LINE_RE", "x TECHNIQUE:"),
    ],
)
def test_a_long_run_after_a_label_colon_is_read_in_linear_time(
    name: str, start: str, run: Callable[[int], str], end: str
) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        return start + run(size) + end

    assert_scales(build, 4000, pattern.search)


@pytest.mark.parametrize("mark", ["**", "__", "*"])
def test_a_block_of_many_marked_labels_is_read_in_linear_time(mark: str) -> None:
    def build(rows: int) -> str:
        line = f" {mark}EVIDENCE:{mark} x {mark}CONFIDENCE:{mark}" * rows
        return f"CLAIM: {SENTENCE}\nEVIDENCE:{mark}{line}\nTECHNIQUE:{mark}{line}\n"

    assert_scales(build, 2000, read_claim_blocks)
