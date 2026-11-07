"""A field label written with closing emphasis or a space before its colon is the field (T-541).

Models write a field label as ``**Technique**: T1027`` or ``EVIDENCE : [ev_…]``
as well as ``TECHNIQUE: T1027``. Such a label at a line start ends the claim's
sentence and is read as its field, as a label is when its colon follows it.
The same words inside the sentence ("uses the technique : XOR") stay in it.

Every value here is made up for the test.
"""

from __future__ import annotations

import re

import pytest

from malspark.agents import base_agent
from malspark.agents.base_agent import read_claim_blocks
from tests.linear_cost import assert_scales

SENTENCE = "Routine 0x4100 decodes its strings at run time."


def _read(text: str) -> list[tuple[str, str, float, str | None]]:
    read = read_claim_blocks(text, require_evidence=True)
    return [
        (claim.claim, claim.evidence_ref, claim.confidence, claim.technique_id)
        for claim in read.claims
    ]


@pytest.mark.parametrize(
    "label",
    [
        "**Technique**",
        "**TECHNIQUE**",
        "Technique ",
        "TECHNIQUE ",
        "- **Technique** ",
        "**Technique **",
    ],
)
def test_a_technique_label_ends_the_sentence_and_is_its_technique(label: str) -> None:
    text = f"CLAIM: {SENTENCE}\n{label}: T1027\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027")]


@pytest.mark.parametrize("label", ["**EVIDENCE**", "EVIDENCE ", "- **EVIDENCE** ", "> EVIDENCE\t"])
def test_an_evidence_label_ends_the_sentence_and_is_its_evidence(label: str) -> None:
    text = f"CLAIM: {SENTENCE}\n{label}: [ev_0002]\nCONFIDENCE: 0.8\nTECHNIQUE: T1140\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1140")]


@pytest.mark.parametrize("label", ["**CONFIDENCE**", "CONFIDENCE ", "- **CONFIDENCE** "])
def test_a_confidence_label_ends_the_sentence_and_is_its_confidence(label: str) -> None:
    text = f"CLAIM: {SENTENCE}\n{label}: 0.8\nEVIDENCE: [ev_0002]\nTECHNIQUE: T1140\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1140")]


@pytest.mark.parametrize("label", ["**CONFIDENCE**", "CONFIDENCE ", "**Technique**", "Technique "])
def test_the_evidence_runs_to_such_a_label_and_no_further(label: str) -> None:
    value = "0.8" if "CONFIDENCE" in label else "T1140"
    text = (
        f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] (strings output),\n  [ev_0003]\n"
        f"{label}: {value}\nCONFIDENCE: 0.8\nTECHNIQUE: T1140\n"
    )
    assert _read(text) == [(SENTENCE, "[ev_0002] (strings output),\n  [ev_0003]", 0.8, "T1140")]


def test_all_three_labels_in_these_spellings_are_read_together() -> None:
    text = (
        f"CLAIM: {SENTENCE}\n**EVIDENCE**: [ev_0002]\n**CONFIDENCE** : 0.7\n"
        "- **Technique** : T1027\n"
    )
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.7, "T1027")]


@pytest.mark.parametrize(
    "sentence",
    [
        "The sample uses the technique : XOR [ev_0001].",
        "The sample uses the **technique**: XOR [ev_0001].",
        "Its strings say EVIDENCE : none, CONFIDENCE : 0.2 [ev_0001].",
    ],
)
def test_such_a_label_inside_the_sentence_stays_in_the_sentence(sentence: str) -> None:
    text = f"CLAIM: {sentence}\nTECHNIQUE: T1140\nCONFIDENCE: 0.8\n"
    assert _read(text) == [(sentence, "[ev_0001]", 0.8, "T1140")]


@pytest.mark.parametrize(
    "name",
    [
        "_BLOCK_CLAIM_RE",
        "_TAIL_START_RE",
        "_BLOCK_EVIDENCE_LABEL_RE",
        "_EVIDENCE_ENDS_AT_LINE_START_RE",
        "_LINE_CONFIDENCE_RE",
        "_LINE_TECHNIQUE_RE",
    ],
)
def test_a_long_run_of_spaces_after_a_label_is_read_in_linear_time(name: str) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        line = "\n**TECHNIQUE" + " " * size + "x"
        return "CLAIM: a" + line + "\nEVIDENCE" + " " * size + "x\nCONFIDENCE" + " " * size + "x"

    assert_scales(build, 4000, pattern.search)


def test_the_sentence_reads_many_label_lines_in_linear_time() -> None:
    def build(rows: int) -> str:
        return "CLAIM: a" + "\n**TECHNIQUE  **  x" * rows

    assert_scales(build, 4000, base_agent._BLOCK_CLAIM_RE.search)


def test_a_long_run_of_spaced_labels_is_read_in_linear_time() -> None:
    def build(rows: int) -> str:
        return f"CLAIM: {SENTENCE}\n" + "EVIDENCE   **   x\n" * rows + "CONFIDENCE: 0.8\n"

    assert_scales(build, 2000, read_claim_blocks)


@pytest.mark.parametrize("run", ["\n", "\n  ", " ", "\t\n"])
def test_a_long_run_of_whitespace_in_the_sentence_is_read_in_linear_time(run: str) -> None:
    # A model stuck repeating newlines writes one; the sentence's end is
    # looked for where the run begins, not at every character of it.
    def build(size: int) -> str:
        return "CLAIM: a" + run * size + "b"

    assert_scales(build, 4000, base_agent._BLOCK_CLAIM_RE.search)


@pytest.mark.parametrize(
    ("name", "label"),
    [("_LINE_TECHNIQUE_RE", "**Technique**:"), ("_BLOCK_TECHNIQUE_LINE_RE", " TECHNIQUE:")],
)
def test_a_long_run_of_spaces_in_a_technique_value_is_read_in_linear_time(
    name: str, label: str
) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        return label + "a" + " " * size + "b"

    assert_scales(build, 4000, pattern.search)


def test_a_technique_value_still_ends_at_a_label_after_spaces() -> None:
    text = f"CLAIM: {SENTENCE}\nTECHNIQUE: T1027   CONFIDENCE: 0.8 EVIDENCE: [ev_0002]\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.8, "T1027")]
