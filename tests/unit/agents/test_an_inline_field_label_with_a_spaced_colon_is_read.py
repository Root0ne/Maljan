"""A field label written on the line of another field is read with a spaced colon too (T-546).

Models write a claim's fields on one line ("EVIDENCE: [ev_…] CONFIDENCE: 0.8")
and spell a label as ``CONFIDENCE : 0.8`` or ``**TECHNIQUE**: T1027`` as well
as ``CONFIDENCE: 0.8``. Such a label after whitespace ends the value before it
and is read as its field, as it is at a line start (T-541). The same words in
lower case ("the confidence : high") stay part of the value.

Every value here is made up for the test.
"""

from __future__ import annotations

import re

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


# The spellings of the colon; a technique value that ends at a label with
# opening emphasis is read in its own tests (T-548).
COLONS = ["{} ", "{}\t", "{}**", "{} ** "]
SPELLINGS = [*COLONS, "**{}**", "**{}** "]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_confidence_label_after_the_evidence_is_the_confidence(spelling: str) -> None:
    label = spelling.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] {label}: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, None, None)]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_technique_label_after_the_evidence_is_the_technique(spelling: str) -> None:
    label = spelling.format("TECHNIQUE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] CONFIDENCE: 0.8 {label}: T1027\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_the_evidence_ends_at_a_technique_label(spelling: str) -> None:
    label = spelling.format("TECHNIQUE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] {label}: T1027 CONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", COLONS)
def test_an_evidence_label_after_the_technique_is_the_evidence(spelling: str) -> None:
    label = spelling.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.8 TECHNIQUE: T1027 {label}: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", COLONS)
def test_a_technique_line_ends_at_a_confidence_label(spelling: str) -> None:
    label = spelling.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {label}: 0.8\nEVIDENCE: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", COLONS)
def test_a_technique_line_ends_at_an_evidence_label(spelling: str) -> None:
    label = spelling.format("EVIDENCE")
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027 {label}: [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize("spelling", COLONS)
def test_a_technique_after_the_evidence_ends_at_a_confidence_label(spelling: str) -> None:
    label = spelling.format("CONFIDENCE")
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] TECHNIQUE: T1027 {label}: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027", None)]


@pytest.mark.parametrize(
    ("line", "evidence", "technique_line"),
    [
        (
            "EVIDENCE: [ev_0002] the confidence : high, per the tool",
            "[ev_0002] the confidence : high, per the tool",
            None,
        ),
        ("EVIDENCE: [ev_0002] the technique : XOR", "[ev_0002] the technique : XOR", None),
        (
            "EVIDENCE: [ev_0002]\nTECHNIQUE: T1027 evidence : see above",
            "[ev_0002]",
            "T1027 evidence : see above",
        ),
        (
            "EVIDENCE: [ev_0002]\nTECHNIQUE: T1027 the confidence : high",
            "[ev_0002]",
            "T1027 the confidence : high",
        ),
        (
            "EVIDENCE: [ev_0002] the tool said CONFIDENCE : 0.2 [ev_0003]",
            "[ev_0002] the tool said CONFIDENCE : 0.2 [ev_0003]",
            None,
        ),
    ],
)
def test_such_words_in_prose_stay_in_the_value(
    line: str, evidence: str, technique_line: str | None
) -> None:
    # The last case: a CONFIDENCE line that follows ends the evidence first.
    text = f"CLAIM: {SENTENCE}\n{line}\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, evidence, 0.8, None, technique_line)]


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize(
    ("name", "start", "label"),
    [
        ("_BLOCK_EVIDENCE_LABEL_RE", "x", "EVIDENCE"),
        ("_EVIDENCE_ENDS_INLINE_RE", "[ev_0001]", "CONFIDENCE"),
        ("_EVIDENCE_ENDS_INLINE_RE", "[ev_0001]", "TECHNIQUE"),
        ("_BLOCK_CONFIDENCE_RE", "x", "CONFIDENCE"),
        ("_LINE_TECHNIQUE_RE", "TECHNIQUE: a", "CONFIDENCE"),
        ("_LINE_TECHNIQUE_RE", "TECHNIQUE: a", "EVIDENCE"),
        ("_BLOCK_TECHNIQUE_LINE_RE", "x", "TECHNIQUE"),
        ("_BLOCK_TECHNIQUE_LINE_RE", "x TECHNIQUE: a", "EVIDENCE"),
    ],
)
def test_a_long_run_of_spaces_around_an_inline_label_is_read_in_linear_time(
    name: str, start: str, label: str, end: str
) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        run = " " * size
        return start + run + label + run + "**" + run + end

    assert_scales(build, 4000, pattern.search)


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize("label", ["CONFIDENCE", "TECHNIQUE", "EVIDENCE"])
def test_a_line_of_many_spaced_labels_is_read_in_linear_time(label: str, end: str) -> None:
    def build(rows: int) -> str:
        line = f" {label}    **  {end}" * rows
        return f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0001]{line}\nTECHNIQUE: T1027{line}\n"

    assert_scales(build, 2000, read_claim_blocks)
