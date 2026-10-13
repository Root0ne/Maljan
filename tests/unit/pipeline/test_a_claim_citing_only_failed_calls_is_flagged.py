"""A claim whose every cited entry is a failed tool call is flagged, never dropped.

"The list_exports answer records what it read from the sample [ev_0068]"
cited a call that answered ``{"tool_error": ...}`` and stood as any claim
did: grounding reads token overlap, and a tool's name is in its own error
text. Such a claim is now flagged (``cites_only_failed_calls``) once the run's
ledger is known, and the flag travels to the judge's summary, the upstream
findings and the ATT&CK table. The claim, its id and its publication are
unchanged.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

from maljan.pipeline.validation import mark_claims_citing_only_failed_calls
from maljan.schemas.isr_models import (
    FAILED_CALLS_MARKER,
    AgentISR,
    ClaimEvidence,
    claim_summary_line,
)


def _entry(ident: str, ok: bool) -> SimpleNamespace:
    return SimpleNamespace(id=ident, ok=ok)


def _claim(text: str, ref: str, tid: str | None = None) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.6, technique_id=tid)


LEDGER = [_entry("ev_0067", True), _entry("ev_0068", False), _entry("ev_0069", False)]


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="reverser", domain="reverser", claims=list(claims))


def test_only_a_claim_whose_every_cited_entry_failed_is_flagged() -> None:
    isr = _isr(
        _claim("The list_exports answer records what it read", "[ev_0068]"),
        _claim("Two failed reads", "ev_0068, ev_0069"),
        _claim("One failed, one answered", "ev_0068 ev_0067"),
        _claim("Cites an entry the ledger does not hold", "ev_0099"),
        _claim("Cites nothing", "the strings"),
    )
    flagged = mark_claims_citing_only_failed_calls({"reverser": isr}, LEDGER)
    assert flagged == ["reverser claim 1", "reverser claim 2"]
    assert [c.cites_only_failed_calls for c in isr.claims] == [True, True, False, False, False]
    # Kept exactly as written.
    assert isr.claims[0].claim == "The list_exports answer records what it read"


def test_the_flag_is_said_beside_the_claim_and_absent_from_an_unflagged_dump() -> None:
    claim = _claim("Reads the exports", "ev_0068", "T1106")
    plain = claim_summary_line(1, claim)
    assert FAILED_CALLS_MARKER not in plain
    assert "cites_only_failed_calls" not in json.loads(claim.model_dump_json())
    claim.cites_only_failed_calls = True
    assert claim_summary_line(1, claim) == plain.replace(
        "| Evidence: ev_0068", f"| Evidence: ev_0068 ({FAILED_CALLS_MARKER})"
    )
    assert json.loads(claim.model_dump_json())["cites_only_failed_calls"] is True


def test_the_attack_table_notes_a_technique_resting_only_on_such_claims() -> None:
    from maljan.extractors.capability_matrix import build_capability_matrix

    failed = _claim("Reads the exports", "ev_0068", "T1106")
    failed.cites_only_failed_calls = True
    answered = _claim("Reads the exports again", "ev_0067", "T1106")
    alone, published = build_capability_matrix(
        stix_output=None, isr_reports={"reverser": _isr(failed)}
    )
    both, published_both = build_capability_matrix(
        stix_output=None, isr_reports={"reverser": _isr(failed, answered)}
    )
    note = next(c.note for c in alone if c.technique_id == "T1106")
    assert FAILED_CALLS_MARKER in note
    assert all(FAILED_CALLS_MARKER not in c.note for c in both if c.technique_id == "T1106")
    # Published either way.
    assert [m.technique_id for m in published] == [m.technique_id for m in published_both]
    assert "T1106" in [m.technique_id for m in published]


def test_marking_stays_linear() -> None:
    def took(size: int) -> float:
        ledger = [_entry(f"ev_{n:05d}", n % 2 == 0) for n in range(size)]
        isr = _isr(*(_claim("c", f"ev_{n:05d}") for n in range(size)))
        start = time.perf_counter()
        mark_claims_citing_only_failed_calls({"a": isr}, ledger)
        return time.perf_counter() - start

    small, large = took(500), took(5_000)
    assert large < small * 30, (small, large)
