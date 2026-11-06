"""A technique value ends at a label a list, quote or heading mark leads (T-549).

Models write a claim's fields on one line and lead a label with a mark a line
may begin with: ``TECHNIQUE: T1027 - EVIDENCE: [ev_…]``. The technique value
ends at such a CONFIDENCE or EVIDENCE label as the evidence value already
ends at one, so the line reads ``T1027`` and not ``T1027 -``. The labels are
read in capitals with their colon there, so prose ("T1027 - see note",
"T1059.001 > 2 EVIDENCE", "# EVIDENCE shows") stays part of the value.

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


# What a line may begin with, written before a label after the technique; a
# number there ends a sentence instead (T-551).
LEADS = ["- ", "+ ", "> ", "# ", "## ", "> - ", "* ", "** **", "- **"]


@pytest.mark.parametrize("lead", LEADS)
def test_a_technique_line_ends_at_a_led_evidence_label(lead: str) -> None:
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {lead}EVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("lead", LEADS)
def test_a_technique_line_ends_at_a_led_confidence_label(lead: str) -> None:
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {lead}CONFIDENCE : 0.8\nEVIDENCE: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("lead", LEADS)
def test_an_inline_technique_ends_at_a_led_label(lead: str) -> None:
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.8 TECHNIQUE: T1027 {lead}EVIDENCE: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("label", ["CONFIDENCE: 0.8", "EVIDENCE: [ev_0002]"])
def test_a_number_closing_a_note_is_no_list_mark(label: str) -> None:
    # "2)" closes the note, so the note stays whole and the id is read.
    text = (
        f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\n"
        f"TECHNIQUE: T1027 (step 2) {label}\nCONFIDENCE: 0.8\n"
    )
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


def test_a_line_of_two_ids_ends_before_the_led_label() -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\nTECHNIQUE: T1027 or T1140 - CONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, "T1027 or T1140")]


@pytest.mark.parametrize(
    "rest",
    [
        "- see note",
        "> 2 EVIDENCE",
        "# EVIDENCE shows it",
        "1. EVIDENCE shows it",
        "- Evidence: see above",
        "- evidence: see above",
        "> confidence: high",
        "-EVIDENCE: [ev_0003]",
        "1.EVIDENCE: [ev_0003]",
    ],
)
def test_such_words_in_prose_stay_in_the_technique_line(rest: str) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\nTECHNIQUE: T1027 {rest}\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, f"T1027 {rest}")]


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize(
    "run",
    [
        lambda size: " *" * size,
        lambda size: " >" * size,
        lambda size: " #" * size,
        lambda size: " ** " * size,
        lambda size: " _" * size + " **",
        lambda size: " - *" * size,
        lambda size: " 1." * size,
        lambda size: " " + "1" * size + ".",
        lambda size: " " * size + "> " * size,
    ],
    ids=[
        "space-star",
        "space-quote",
        "space-hash",
        "space-stars-space",
        "space-underscore",
        "dash-star",
        "numbered",
        "long-number",
        "spaces-quotes",
    ],
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


@pytest.mark.parametrize("lead", ["- ", "> ", "1. ", "# "])
def test_a_technique_line_of_many_led_labels_is_read_in_linear_time(lead: str) -> None:
    def build(rows: int) -> str:
        line = f" {lead}EVIDENCE x {lead}CONFIDENCE{lead}:" * rows
        return f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0001]\nTECHNIQUE: T1027{line}\n"

    assert_scales(build, 2000, read_claim_blocks)
