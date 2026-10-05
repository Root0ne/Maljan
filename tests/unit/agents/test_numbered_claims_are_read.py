"""Claims a model numbers and writes one after another are each read.

A revision in a paid run wrote ``CLAIM 1: …``, ``CLAIM 2: …`` and
``CLAIM 4 (REVISED — round-0 claim withdrawn): …`` with no ``---`` line between
them. The parser looked for ``CLAIM:`` and split only on ``---``, so it read
none of the nine, and the revision replaced the analyst's first answer with an
empty one.
"""

from __future__ import annotations

from maljan.agents.static_analyst import _parse_claim_blocks

NUMBERED = """[STATIC ANALYST — negotiation round 1]

Round-0 self-corrections applied.

---

CLAIM 1: The artifact is a 64-bit Windows DLL.
EVIDENCE: [ev_0004] dll, machine 34404
CONFIDENCE: 0.95
TECHNIQUE: —

CLAIM 2: Execution is proxied by rundll32.exe in ordinal form.
EVIDENCE: [ev_0012] two rundll32 processes
CONFIDENCE: 0.95
TECHNIQUE: T1218.011

CLAIM 4 (REVISED — round-0 claim withdrawn): the stored blobs are not RC4-decrypted.
EVIDENCE: [ev_0198] decompiled decoder
CONFIDENCE: 0.85
TECHNIQUE: T1027

**CLAIM 5 —** persistence is a COM Task Scheduler registration.
EVIDENCE: [ev_0220]
CONFIDENCE: 0.8
TECHNIQUE: T1053.005

DISPUTES: NONE
"""


def test_every_numbered_claim_is_read_with_its_technique() -> None:
    claims = _parse_claim_blocks(NUMBERED)
    assert [c.technique_id for c in claims] == [None, "T1218.011", "T1027", "T1053.005"]
    assert claims[2].claim.startswith("the stored blobs are not RC4-decrypted")
    assert claims[3].claim.startswith("persistence is a COM Task Scheduler")


def test_the_plain_form_reads_as_it_did() -> None:
    plain = (
        "CLAIM: one\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5\nTECHNIQUE: NONE\n---\n"
        "CLAIM: two\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1055"
    )
    assert [c.claim for c in _parse_claim_blocks(plain)] == ["one", "two"]


def test_a_word_that_begins_with_claim_is_not_a_heading() -> None:
    text = "CLAIMS: listed below\nCLAIM: one\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5"
    assert [c.claim for c in _parse_claim_blocks(text)] == ["one"]


def test_a_claim_heading_inside_evidence_opens_its_own_block() -> None:
    # The first claim keeps no confidence it did not state; the line that reads
    # as a heading is its own block, with the CONFIDENCE written under it.
    from maljan.agents.base_agent import read_claim_blocks

    text = "CLAIM 1: one\nEVIDENCE: first line\nCLAIM 2 - see also ev_0002\nCONFIDENCE: 0.8"
    read = read_claim_blocks(text)
    assert [(c.claim, c.confidence) for c in read.claims] == [("see also ev_0002", 0.8)]
    assert read.without_confidence == 1 and read.unread == 0
    # The stricter reading wants an EVIDENCE line on each: neither block is its claim.
    assert _parse_claim_blocks(text) == []


def test_a_peer_claim_quoted_under_disputes_is_not_this_analyst_s() -> None:
    text = (
        "CLAIM 1: own finding\nEVIDENCE: ev_0001\nCONFIDENCE: 0.9\n\n"
        "DISPUTES:\n* CLAIM 3: the peer's claim\n  EVIDENCE: ev_0009\n  CONFIDENCE: 0.7\n"
    )
    assert [c.claim for c in _parse_claim_blocks(text)] == ["own finding"]
