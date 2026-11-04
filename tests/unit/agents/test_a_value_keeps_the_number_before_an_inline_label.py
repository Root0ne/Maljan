"""A value keeps the number written before a label on its line (T-551).

Models end a sentence or a note with a number and write the next label on the
same line: ``EVIDENCE: [ev_0014] (seen on port 443) CONFIDENCE: 0.9``,
``TECHNIQUE: T1071 over port 443. EVIDENCE: [ev_0002]``. The evidence value
read ``443)`` and the technique value read ``443.`` as a list mark leading the
label, so the stored evidence ended at ``(seen on port`` and the technique line
at ``T1071 over port``. A number leads a label as a list mark only at a line's
start; after words on a line it is the end of a sentence or a note and stays
in the value. Any other mark a line may begin with still ends the value
there, and a long run of marks is read once.

Every value here is made up for the test.
"""

from __future__ import annotations

import random
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


# How the stored answers end an evidence value with a number before the next
# label: a note or a sentence closed right after it.
EVIDENCE_ENDS = [
    "[ev_0014] (seen on port 443)",
    "[ev_0025] (0x6aa4 called by 3)",
    "[ev_0004] (DLL, machine 34404)",
    "[ev_0015] (sandbox dropped files: 0)",
    "[ev_0004] (5 imports + 4 exports = 9)",
    "[ev_0007] (checks uVar2 < 6)",
    "[ev_0025] 0xae78 called by 34.",
    "[ev_0130] no pid 3648.",
    "[ev_0015] sandbox dropped files: 0.",
    "[ev_0157] taken in order 3, 21, 4, 5.",
]


@pytest.mark.parametrize("label", ["CONFIDENCE:", "**CONFIDENCE:**", "CONFIDENCE :"])
@pytest.mark.parametrize("evidence", EVIDENCE_ENDS)
def test_the_evidence_keeps_its_last_number_before_a_confidence_label(
    evidence: str, label: str
) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: {evidence} {label} 0.9\n"
    assert _read(text) == [(SENTENCE, evidence, 0.9, None, None)]


@pytest.mark.parametrize("evidence", EVIDENCE_ENDS)
def test_the_evidence_keeps_its_last_number_before_a_technique_label(evidence: str) -> None:
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.9\nEVIDENCE: {evidence} TECHNIQUE: T1071\n"
    assert _read(text) == [(SENTENCE, evidence, 0.9, "T1071", None)]


@pytest.mark.parametrize(
    ("line", "technique_line"),
    [
        ("T1071 over port 443.", "T1071 over port 443."),
        ("T1218.011 via ordinal #1.", "T1218.011 via ordinal #1."),
        ("T1071.001 (no contact seen, see claim 7)", "T1071.001 (no contact seen, see claim 7)"),
    ],
)
@pytest.mark.parametrize("label", ["EVIDENCE: [ev_0002]", "CONFIDENCE: 0.9"])
def test_the_technique_line_keeps_its_last_number_before_a_label(
    line: str, technique_line: str, label: str
) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.9\nTECHNIQUE: {line} {label}\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.9, None, technique_line)]


def test_a_technique_note_closed_by_a_number_still_gives_its_id() -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002]\nTECHNIQUE: T1027 (step 2) CONFIDENCE: 0.9\n"
    assert _read(text) == [(SENTENCE, "[ev_0002]", 0.9, "T1027", None)]


@pytest.mark.parametrize("mark", ["2. ", "12) ", "> 2. ", "## 3) "])
def test_a_number_before_a_label_on_the_line_is_the_evidence_last_word(mark: str) -> None:
    # The label still ends the value, right after the number.
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] {mark}CONFIDENCE: 0.9\n"
    assert _read(text) == [(SENTENCE, f"[ev_0002] {mark.rstrip()}", 0.9, None, None)]


@pytest.mark.parametrize("mark", ["2. ", "12) ", "> 2. ", "## 3) "])
def test_a_numbered_label_on_its_own_line_ends_the_evidence(mark: str) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] seen on port 443.\n{mark}CONFIDENCE: 0.9\n"
    assert _read(text) == [(SENTENCE, "[ev_0002] seen on port 443.", 0.9, None, None)]


@pytest.mark.parametrize("mark", ["", "- ", "+ ", "> ", "# ", "** ", "> - ", "- **"])
@pytest.mark.parametrize("label", ["CONFIDENCE: 0.9", "TECHNIQUE: none"])
def test_any_other_mark_before_a_label_still_ends_the_evidence(mark: str, label: str) -> None:
    evidence = "[ev_0014] (seen on port 443)"
    text = f"CLAIM: {SENTENCE}\nCONFIDENCE: 0.9 EVIDENCE: {evidence} {mark}{label}\n"
    assert _read(text) == [(SENTENCE, evidence, 0.9, None, None)]


@pytest.mark.parametrize(
    "rest",
    [
        "seen on port 443. Confidence: high",
        "seen on port 443. 2. confidence: high",
        "(step 2) the technique: T1055",
        "1. CONFIDENCE shows nothing",
        "2) TECHNIQUE T1055 is not claimed",
    ],
)
def test_such_words_in_prose_stay_in_the_evidence(rest: str) -> None:
    text = f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0002] {rest}\nCONFIDENCE: 0.9\n"
    assert _read(text) == [(SENTENCE, f"[ev_0002] {rest}", 0.9, None, None)]


RUNS: list[Callable[[int], str]] = [
    lambda size: " " * size,
    lambda size: " *" * size,
    lambda size: " * *" * size + " 2.",
    lambda size: " - -" * size,
    lambda size: " 2) 2)" * size,
    lambda size: " 1." * size,
    lambda size: " >" * size,
    lambda size: " #" * size,
    lambda size: " ** " * size,
    lambda size: "\xa0*" * size,
    lambda size: " \xa0 *" * size,
    lambda size: " _" * size + " **",
    lambda size: " " + "1" * size + ")",
    lambda size: " " * size + "> " * size,
]
RUN_IDS = [
    "spaces",
    "space-star",
    "stars-number",
    "space-dashes",
    "numbers-closed",
    "numbered",
    "space-quote",
    "space-hash",
    "space-stars-space",
    "nbsp-star",
    "space-nbsp-star",
    "space-underscore",
    "long-number",
    "spaces-quotes",
]


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize("run", RUNS, ids=RUN_IDS)
@pytest.mark.parametrize("label", ["CONFIDENCE", "TECHNIQUE"])
def test_a_long_run_of_marks_in_an_evidence_value_is_read_in_linear_time(
    run: Callable[[int], str], label: str, end: str
) -> None:
    pattern: re.Pattern[str] = base_agent._EVIDENCE_ENDS_INLINE_RE

    def build(size: int) -> str:
        return "[ev_0001]" + run(size) + label + end

    assert_scales(build, 4000, pattern.match)


PLAIN_EVIDENCE_END = re.compile(
    r"(?<!\s)\s++"
    + base_agent._INLINE_LABEL_LEAD
    + r"(?:CONFIDENCE|TECHNIQUE)"
    + base_agent._LABEL_COLON
)
PIECES = [
    "[ev_1]",
    "x",
    "443",
    "2",
    "12",
    ".",
    ")",
    "(",
    ":",
    "-",
    "+",
    ">",
    "#",
    "*",
    "**",
    "_",
    " ",
    " ",
    " ",
    "\t",
    "\n",
    "\r",
    "\xa0",
    "CONFIDENCE",
    "TECHNIQUE",
    "Confidence",
]


def test_the_evidence_end_is_where_a_plain_search_of_it_begins() -> None:
    # The match from the value's start only reads a long run once: it ends
    # where the first end the plain form finds begins, on every text.
    rng = random.Random(551)
    for _ in range(5000):
        text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 24)))
        found = base_agent._EVIDENCE_ENDS_INLINE_RE.match(text)
        plain = PLAIN_EVIDENCE_END.search(text)
        assert (found and found.end()) == (plain and plain.start()), repr(text)


@pytest.mark.parametrize("run", RUNS, ids=RUN_IDS)
def test_an_evidence_value_of_many_runs_is_read_in_linear_time(
    run: Callable[[int], str],
) -> None:
    def build(rows: int) -> str:
        line = (run(8) + " CONFIDENCE x") * rows
        return f"CLAIM: {SENTENCE}\nEVIDENCE: [ev_0001]{line} CONFIDENCE: 0.9\n"

    assert_scales(build, 400, read_claim_blocks)


@pytest.mark.parametrize("end", ["x", ":"])
@pytest.mark.parametrize(
    ("name", "start"),
    [("_LINE_TECHNIQUE_RE", "TECHNIQUE: a"), ("_BLOCK_TECHNIQUE_LINE_RE", "x TECHNIQUE: a")],
)
@pytest.mark.parametrize(
    "run",
    [lambda size: " 2) 2)" * size, lambda size: " - -" * size, lambda size: " 1. *" * size],
    ids=["numbers-closed", "space-dashes", "numbered-star"],
)
def test_a_long_run_of_numbers_in_a_technique_value_is_read_in_linear_time(
    name: str, start: str, run: Callable[[int], str], end: str
) -> None:
    pattern: re.Pattern[str] = getattr(base_agent, name)

    def build(size: int) -> str:
        return start + run(size) + "EVIDENCE" + end

    assert_scales(build, 4000, pattern.search)
