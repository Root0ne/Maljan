"""The evidence no claim cites is counted from the ledger and the analysts' final claims.

Of the entries whose tool ran, the ones no analyst's final claim names in its
text or its evidence field. A repeat and a guard's answer are not evidence of
their own; a cited repeat counts for the entry holding its answer. The ledger
may be models or the dicts a state channel holds.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from maljan.analysis.efficiency import efficiency_lines, efficiency_record, uncited_record
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _entry(seq: int, tool: str = "pe_info", agent: str = "static", **extra: object) -> LedgerEntry:
    return LedgerEntry(id=f"ev_{seq:04d}", agent=agent, tool=tool, seq=seq, **extra)


def _isr(*refs: str, agent: str = "static") -> AgentISR:
    claims = [ClaimEvidence(claim="x", evidence_ref=ref, confidence=0.5) for ref in refs]
    return AgentISR(agent_id=agent, domain=agent, claims=claims)


def test_an_entry_no_claim_names_is_uncited() -> None:
    ledger = [_entry(1), _entry(2, "strings"), _entry(3, "strings", agent="")]
    record = uncited_record(ledger, {"static": _isr("pe_info [ev_0001]")})

    assert record == {
        "entries": 3,
        "cited": 1,
        "uncited": 2,
        "by_agent": {"pipeline": 1, "static": 1},
        "by_tool": {"strings": 2},
        "ids": ["ev_0002", "ev_0003"],
    }


def test_a_claim_text_cites_too_and_a_cited_repeat_counts_for_its_holder() -> None:
    ledger = [_entry(1), _entry(2), _entry(3, repeated_of="ev_0002")]
    claim = ClaimEvidence(claim="as EV_0001 shows", evidence_ref="see [ev_0003]", confidence=0.5)
    report = AgentISR(agent_id="static", domain="static", claims=[claim])

    record = uncited_record(ledger, {"static": report})
    assert record is not None
    assert (record["entries"], record["uncited"]) == (2, 0)


def test_a_guard_answer_is_not_evidence_and_dict_rows_are_read() -> None:
    ledger = [
        _entry(1).model_dump(mode="json"),
        _entry(2, repeated_of="ev_0002").model_dump(mode="json"),
    ]
    record = uncited_record(ledger, {"static": _isr().model_dump(mode="json")})

    assert record is not None
    assert (record["entries"], record["uncited"], record["ids"]) == (1, 1, ["ev_0001"])


def test_no_entry_that_ran_is_no_part() -> None:
    assert uncited_record([], {}) is None


def test_the_record_and_the_report_carry_it() -> None:
    record = efficiency_record(
        SimpleNamespace(), entries=[_entry(1), _entry(2, "strings")], isr_reports={}
    )
    assert record is not None
    assert "inputs" not in record
    assert efficiency_lines(record)[0] == (
        "Evidence no claim cites: 2 of the 2 ledger entries whose tool ran are cited by no "
        "analyst's final claim (by agent: `static` 2; by tool: `pe_info` 1, `strings` 1)."
    )


def test_the_count_is_linear_in_the_ledger() -> None:
    def timed(scale: int) -> float:
        ledger = [_entry(i) for i in range(1, 500 * scale)]
        refs = " ".join(f"ev_{i:04d}" for i in range(1, 500 * scale, 2))
        reports = {"static": _isr(refs)}
        start = time.perf_counter()
        uncited_record(ledger, reports)
        return time.perf_counter() - start

    small = max(timed(1), 1e-4)
    assert timed(10) < small * 40
