"""A technique value ends at a label written after it with opening emphasis (T-548).

Models write a claim's fields on one line and mark a label with emphasis:
``TECHNIQUE: T1027 **EVIDENCE**: [ev_…]``. The technique value ends at such a
CONFIDENCE or EVIDENCE label as it ends at one written plain, as the evidence
value already ends at a marked label after it. The same words in prose
("**important** evidence", "**Evidence**: see above") stay part of the value.

Every value here is made up for the test.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from maljan.agents import base_agent
from maljan.agents.base_agent import read_claim_blocks
from tests.linear_cost import assert_scales

SENTENCE = "Routine 0x4100 decodes its strings at run time."


def _read(text: str) -> list[tuple[str, str, float, str | None, str | None]]:
    read = read_claim_blocks(text, require_evidence=True)
    assert read.without_confidence == 0
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


# A label with opening emphasis, in the spellings of its colon a label at a
# line start is read in.
SPELLINGS = ["**{}**:", "**{}** :", "**{}**\t:", "**{}:", "*{}:", "_{}:", "__{}:", "***{}**:"]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_technique_line_ends_at_an_emphasised_evidence_label(spelling: str) -> None:
    label = spelling.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {label} [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_technique_line_ends_at_an_emphasised_confidence_label(spelling: str) -> None:
    label = spelling.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {label} 0.8\nEVIDENCE: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_an_inline_technique_ends_at_an_emphasised_evidence_label(spelling: str) -> None:
    label = spelling.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.8 TECHNIQUE: T1027 {label} [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_an_inline_technique_ends_at_an_emphasised_confidence_label(spelling: str) -> None:
    label = spelling.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] TECHNIQUE: T1027 {label} 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


def test_a_technique_ends_before_a_label_whose_emphasis_closes_after_the_colon() -> None:
    # The emphasis closing after the colon is no part of the evidence (T-550).
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 **EVIDENCE:** [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize(
    "rest",
    [
        "**important** evidence",
        "**important** EVIDENCE",
        "**Evidence**: see above",
        "**evidence**: see above",
        "*Confidence*: high",
        "__confidence__: high",
        "**EVIDENCE** shows it",
        "_EVIDENCE_ shows it",
    ],
)
def test_such_words_in_prose_stay_in_the_technique_line(rest: str) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\nTECHNIQUE: T1027 {rest}\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, f"T1027 {rest}")]


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize(
    "run",
    [
        lambda size: " " * size + "**",
        lambda size: " " + "*" * size,
        lambda size: " " + "_" * size,
        lambda size: " " * size + "_" * size,
        lambda size: " *" * size,
        lambda size: " _" * size + " **",
    ],
    ids=["spaces", "stars", "underscores", "spaces-underscores", "space-star", "space-underscore"],
)
@pytest.mark.parametrize(
    ("name", "start"),
    [("_LINE_TECHNIQUE_RE", "TECHNIQUE: a"), ("_BLOCK_TECHNIQUE_LINE_RE", "x TECHNIQUE: a")],
)
@pytest.mark.parametrize("label", ["EVIDENCE", "CONFIDENCE"])
def test_a_long_run_of_marks_before_a_label_is_read_in_linear_time(
    name: str, start: str, run: Callable[[int], str], label: str, end: str
) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        return start + run(size) + label + end

    assert_scales(build, 4000, pattern.search)


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize("mark", ["**", "*", "_", "__"])
def test_a_technique_line_of_many_marked_labels_is_read_in_linear_time(mark: str, end: str) -> None:
    def build(rows: int) -> str:
        line = f" {mark}EVIDENCE  {end} {mark}CONFIDENCE{mark}{end}" * rows
        return f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0001]\nTECHNIQUE: T1027{line}\n"

    assert_scales(build, 2000, read_claim_blocks)
