"""A claim citing ids in its sentence is read; a number on a line of its own heads one claim.

A paid run's dynamic analyst wrote its revision as 24 claim blocks, the first
with an ``EVIDENCE:`` line and the other 23 with their ids in the claim
sentence (``... carry the command line ... [ev_0028, ev_0012]``) and no
EVIDENCE line. The static, dynamic and network analysts' stricter reading
turned every block without the line away, so one claim was read and 23 were
recorded as not read. A block with no EVIDENCE line, or one that cleaned to
nothing, now has the ids its sentence cites in brackets as its evidence; an id
named in the prose is no citation. A block that cites no ledger id is still not
the stricter reading's claim, and the sentence that records the claims not read
names it.

The retry that fixes claims by number asks for each "under its number (CLAIM
7:) as its own block of CLAIM, EVIDENCE: ..." lines, and models write the
number on a line of its own with the ``CLAIM:`` line under it. That was read as
two headings: an empty claim begun and not read, and a claim with no number,
so every such retry was recorded as having claims not read and was not merged.
"""

from __future__ import annotations

import pytest

from maljan.agents.base_agent import (
    claims_unread_sentence,
    ledger_ids_cited,
    read_claim_blocks,
)
from maljan.agents.claim_headings import claims_headed, count_claims_begun
from maljan.pipeline.validation import UNGROUNDED_TECHNIQUE_CODE, validate_isr
from maljan.schemas.isr_models import AgentISR
from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

# The shape of the paid run's round-4 answer, cut to three of its claims.
CITED_IN_THE_SENTENCE = """Visible ledger: ev_0001 to ev_0028. No tools were run in this round.

**REVISIONS FROM ROUND 0 AND ROUND 2**
- Claim 14 (self-rename) is lowered from 0.65 to 0.50 [ev_0021].

---

**CLAIM 1 (identity):** 60,928-byte AMD64 DLL, 5 sections, 4 exports, unsigned.
EVIDENCE: [ev_0001], [ev_0003], [ev_0004]
CONFIDENCE: 0.95
TECHNIQUE: none

**CLAIM 2 (rundll32 launches, observed):** Two `rundll32.exe` processes carry the
command line `rundll32.exe sample.dll,#1` [ev_0028, ev_0012]. Sigma and LOLBin rules
fire on this form [ev_0009, ev_0011, ev_0012].
CONFIDENCE: 0.85 that both run the sample DLL by ordinal 1; 0.40 that either is a relaunch
TECHNIQUE: T1218.011 (form observed; attribution open)

**CLAIM 3 (sandbox coverage):** The report lists no API-call or registry section, and
0 dropped files [EV_0026, ev_0015]. Behaviour in those areas is unobserved.
CONFIDENCE: 0.90 that these are unobserved
TECHNIQUE: none

DISPUTES: NONE
"""


@pytest.mark.parametrize("strict", [True, False])
def test_every_claim_that_cites_in_its_sentence_is_read(strict: bool) -> None:
    read = read_claim_blocks(CITED_IN_THE_SENTENCE, require_evidence=strict)

    assert (read.begun, read.read, read.unread, read.without_evidence) == (3, 3, 0, 0)
    assert [c.evidence_ref for c in read.claims] == [
        "[ev_0001], [ev_0003], [ev_0004]",
        # Each id once, in the order the sentence writes them.
        "[ev_0028], [ev_0012], [ev_0009], [ev_0011]",
        "[ev_0026], [ev_0015]",
    ]
    assert [c.confidence for c in read.claims] == [0.95, 0.85, 0.90]
    assert read.claims[1].technique_line == "T1218.011 (form observed; attribution open)"


def test_an_evidence_line_is_read_as_written_and_never_joined_by_the_sentence_s_ids() -> None:
    text = "CLAIM: the loader resolves its imports [ev_0007]\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.7"
    (claim,) = read_claim_blocks(text, require_evidence=True).claims
    assert claim.evidence_ref == "[ev_0002]"


def test_a_block_that_cites_nothing_is_not_the_stricter_reading_s_claim_and_is_named() -> None:
    text = (
        "CLAIM: the sample is a DLL\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n---\n"
        "CLAIM: the export runs a beacon loop\nCONFIDENCE: 0.6\nTECHNIQUE: none"
    )
    strict = read_claim_blocks(text, require_evidence=True)
    assert [c.claim for c in strict.claims] == ["the sample is a DLL"]
    assert (strict.begun, strict.unread, strict.without_evidence) == (2, 1, 1)
    assert claims_unread_sentence("dynamic", strict, 4) == (
        "The dynamic analyst's answer (round 4) began 2 claim(s), and 1 were read; 1 could "
        "not be read as a claim and are not in its findings. 1 of them cite no ledger id."
    )
    # Everywhere else it is a finding, recorded as unsourced.
    loose = read_claim_blocks(text)
    assert [c.evidence_ref for c in loose.claims] == ["[ev_0001]", ""]
    assert loose.without_evidence == 0


def test_a_block_with_its_ids_and_no_confidence_is_asked_about_not_lost() -> None:
    text = "CLAIM: [ev_0020] (0xf068; field &systeminfo=). TECHNIQUE T1082. CONFIDENCE 0.7."
    read = read_claim_blocks(text, require_evidence=True)
    assert (read.read, read.without_confidence, read.unread) == (0, 1, 0)


@pytest.mark.parametrize(
    "sentence",
    [
        "Unlike ev_0012 suggests, the export runs a beacon loop.",
        "ev_0020 holds the field &systeminfo= at 0xf068.",
    ],
)
def test_an_id_named_in_the_prose_is_no_evidence(sentence: str) -> None:
    text = f"CLAIM: {sentence}\nCONFIDENCE: 0.6\nTECHNIQUE: none"
    strict = read_claim_blocks(text, require_evidence=True)
    assert (strict.read, strict.without_evidence, strict.unread) == (0, 1, 1)
    (loose,) = read_claim_blocks(text).claims
    assert loose.evidence_ref == ""


def test_an_evidence_line_of_scaffolding_alone_falls_back_to_the_sentence_s_citation() -> None:
    text = (
        "CLAIM: the beacon posts to /live/ [ev_0021]\n"
        'EVIDENCE: <tool_call>{"name": "read_evidence"}</tool_call>\n'
        "CONFIDENCE: 0.7\nTECHNIQUE: T1071.001"
    )
    (claim,) = read_claim_blocks(text, require_evidence=True).claims
    assert claim.evidence_ref == "[ev_0021]"
    assert claim.technique_id == "T1071.001"


def test_an_id_the_run_never_issued_is_still_no_grounding() -> None:
    text = "CLAIM: the sample injects into explorer [ev_9999]\nCONFIDENCE: 0.5\nTECHNIQUE: T1055"
    claims = read_claim_blocks(text, require_evidence=True).claims
    assert [c.evidence_ref for c in claims] == ["[ev_9999]"]
    isr = AgentISR(agent_id="dynamic", domain="dynamic", claims=claims)

    violations = validate_isr(isr, ledger_ids=["ev_0001", "ev_0002"])

    assert UNGROUNDED_TECHNIQUE_CODE in {v.code for v in violations}


@pytest.mark.parametrize(
    "text",
    [
        "The capture holds 14 conversations [ev_0017]; none is tied to a process [ev_0012].",
        "CLAIMS: two, below [ev_0001]\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.5",
        "- Claim 14 (self-rename) is lowered from 0.65 to 0.50 [ev_0021].\nCONFIDENCE: 0.5",
        "My claim: the sample beacons [ev_0003].\nCONFIDENCE: 0.8",
    ],
)
def test_text_that_is_no_claim_never_becomes_one(text: str) -> None:
    for strict in (True, False):
        read = read_claim_blocks(text, require_evidence=strict)
        assert (read.claims, read.begun) == ([], 0)


def test_ledger_ids_cited() -> None:
    assert ledger_ids_cited("seen in [ev_0002] and (EV_0002, ev_0019; row 3), not ev_0030") == (
        "[ev_0002], [ev_0019]"
    )
    assert ledger_ids_cited("(see [ev_0005])") == "[ev_0005]"
    # Ids beside a nested note are read with it.
    assert ledger_ids_cited("[ev_0021 (blob 0xfac0)]") == "[ev_0021]"
    assert ledger_ids_cited("[ev_0008, ev_0024 (PEB)]") == "[ev_0008], [ev_0024]"
    assert ledger_ids_cited("[see (ev_0012) and ev_0013]") == "[ev_0012], [ev_0013]"
    # Deeper than one nested pair, the innermost pair is read.
    assert ledger_ids_cited("[a (b [ev_0040] c) ev_0041]") == "[ev_0040]"
    assert ledger_ids_cited("no id, ev_0002 [prev_0002] (ev_12) [ev_0003") == ""


NUMBER_ON_ITS_OWN_LINE = """CLAIM 10:
CLAIM: The file carries the CRC-32 polynomial and the FNV-1 constants.
EVIDENCE: [ev_0023], [ev_0008]
CONFIDENCE: 0.7
TECHNIQUE: NONE
---

**CLAIM 11:**

CLAIM: The sample carries network-capable code.
EVIDENCE: [ev_0020]
CONFIDENCE: 0.85
TECHNIQUE: NONE
---

CLAIM 12 (REVISED): The routine at 0x2200 runs commands.
EVIDENCE: [ev_0021]
CONFIDENCE: 0.6
TECHNIQUE: T1059.003
"""


@pytest.mark.parametrize("strict", [True, False])
def test_a_number_written_on_its_own_line_heads_the_claim_under_it(strict: bool) -> None:
    read = read_claim_blocks(NUMBER_ON_ITS_OWN_LINE, require_evidence=strict)

    assert (read.begun, read.read, read.unread) == (3, 3, 0)
    assert [(c.number, c.claim) for c in read.claims] == [
        ("10", "The file carries the CRC-32 polynomial and the FNV-1 constants."),
        ("11", "The sample carries network-capable code."),
        ("12", "The routine at 0x2200 runs commands."),
    ]
    assert read.claims[2].heading_note == "(REVISED)"


@pytest.mark.parametrize(
    ("text", "begun", "read"),
    [
        # A bare heading with its fields under it and no CLAIM: line is begun
        # and not read, as before.
        ("CLAIM 7:\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5", 1, 0),
        # A heading that writes its own sentence keeps it, and the CLAIM: line
        # under it is a claim of its own.
        ("CLAIM 7: own sentence\nCLAIM: other\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5", 2, 1),
        # A numbered heading under it is a claim of its own.
        ("CLAIM 7:\nCLAIM 8: the second\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5", 2, 1),
        # So is a heading written after a line of prose.
        ("CLAIM 7:\nsee below\nCLAIM: the second\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5", 2, 1),
        # And a bare CLAIM: line under a bare heading is still one claim begun.
        ("CLAIM 7:\nCLAIM:\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5", 2, 0),
    ],
)
def test_only_a_bare_number_over_a_claim_line_is_joined(text: str, begun: int, read: int) -> None:
    found = read_claim_blocks(text, require_evidence=True)
    assert (found.begun, found.read) == (begun, read)
    assert count_claims_begun(text) == begun


def test_the_headed_text_writes_the_joined_heading_once() -> None:
    assert (
        claims_headed("CLAIM 7:\n\nCLAIM: one\nCONFIDENCE: 0.5")
        == "---\nCLAIM: one\nCONFIDENCE: 0.5"
    )


def _cited_answer(size: int) -> str:
    block = (
        "**CLAIM {n} (note):** Routine 0x{n:x} calls it [ev_{n:04d}, ev_0002] and so on "
        "[ev_0003].\nCONFIDENCE: 0.5\nTECHNIQUE: none\n\n"
    )
    return "".join(block.format(n=n) for n in range(1, size + 1))


def _numbered_answer(size: int) -> str:
    block = "CLAIM {n}:\n\nCLAIM: the {n}th\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\n---\n"
    return "".join(block.format(n=n) for n in range(1, size + 1))


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(_cited_answer, id="ids in the sentence"),
        pytest.param(_numbered_answer, id="numbers on their own lines"),
        pytest.param(lambda size: "CLAIM 1:\n" + "\n" * (size * 40) + "CLAIM: x", id="blank run"),
        pytest.param(lambda size: "CLAIM: " + "ev_" * (size * 20), id="unfinished ids"),
        pytest.param(lambda size: "CLAIM: " + "[(" * (size * 20), id="open brackets"),
        pytest.param(lambda size: "CLAIM: [" + "ev_0001 " * (size * 10), id="unclosed citation"),
        pytest.param(lambda size: "CLAIM: " + "[(ev_0001)" * (size * 20), id="nested, unclosed"),
        pytest.param(lambda size: "CLAIM: " + "([ev_0001] " * (size * 20), id="nested, other way"),
        pytest.param(lambda size: "CLAIM: [" + "(x) " * (size * 20), id="nested in one open"),
    ],
)
def test_the_read_costs_time_linear_in_the_answer(answer) -> None:  # type: ignore[no-untyped-def]
    small_text, large_text = answer(400), answer(1600)

    def small() -> object:
        return read_claim_blocks(small_text, require_evidence=True)

    def large() -> object:
        return read_claim_blocks(large_text, require_evidence=True)

    assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
    assert calls(large) <= calls(small) * 4 * 1.2 + 100
