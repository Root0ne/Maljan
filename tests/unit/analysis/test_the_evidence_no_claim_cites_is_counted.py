"""The evidence nothing cites is counted from the ledger and the analysts' final answers.

Of the entries whose tool answered, the ones no claim names in its text or its
evidence field and no finding or artifact names in its ``evidence_ids``. A
repeat and a guard's answer are not evidence of their own, and a failed call
is counted apart, not as evidence; a cited repeat counts for the entry holding
its answer. The ledger may be models or the dicts a state channel holds.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from maljan.analysis.efficiency import efficiency_lines, efficiency_record, uncited_record
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, Artifact, ClaimEvidence, Finding


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
        "failed": 0,
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


def test_a_finding_or_an_artifact_cites_by_its_evidence_ids_and_a_failed_call_is_apart() -> None:
    ledger = [
        _entry(1),
        _entry(2),
        _entry(3),
        _entry(4, ok=False, error="the server did not answer"),
        _entry(5),
    ]
    report = AgentISR(
        agent_id="static",
        domain="static",
        findings=[
            Finding(
                title="imports",
                evidence_ids=["ev_0001"],
                artifacts=[Artifact(kind="imports", rows=[["a"]], evidence_ids=["EV_0002"])],
            )
        ],
        artifacts=[Artifact(kind="strings", rows=[["b"]], evidence_ids=["ev_0003"])],
    )
    record = uncited_record(ledger, {"static": report.model_dump(mode="json")})

    assert record is not None
    assert (record["entries"], record["cited"], record["failed"]) == (4, 3, 1)
    assert record["ids"] == ["ev_0005"]
    assert efficiency_lines({"v": 2, "uncited": record})[0].endswith(
        "; 1 failed call not counted as evidence."
    )


def test_no_entry_that_ran_is_no_part() -> None:
    assert uncited_record([], {}) is None


def test_the_record_and_the_report_carry_it() -> None:
    record = efficiency_record(
        SimpleNamespace(), entries=[_entry(1), _entry(2, "strings")], isr_reports={}
    )
    assert record is not None
    assert "inputs" not in record
    assert efficiency_lines(record)[0] == (
        "Evidence nothing cites: 2 of the 2 ledger entries whose tool answered are named by no "
        "claim, finding or artifact of an analyst's final answer (by maker: `static` 2; by "
        "tool: `pe_info` 1, `strings` 1); no call failed."
    )


def _field_reads(monkeypatch: pytest.MonkeyPatch, build: Callable[[], object]) -> int:
    """How many entry fields ``build`` reads: the record's unit of work, not a clock."""
    import maljan.analysis.efficiency as efficiency

    counted = [0]
    real = efficiency._field

    def field(entry: object, name: str) -> object:
        counted[0] += 1
        return real(entry, name)

    monkeypatch.setattr(efficiency, "_field", field)
    try:
        build()
    finally:
        monkeypatch.setattr(efficiency, "_field", real)
    return counted[0]


def test_the_count_is_linear_in_the_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    def work(scale: int) -> int:
        ledger = [_entry(i) for i in range(1, 500 * scale + 1)]
        refs = " ".join(f"ev_{i:04d}" for i in range(1, 500 * scale + 1, 2))
        reports = {"static": _isr(refs)}
        return _field_reads(monkeypatch, lambda: uncited_record(ledger, reports))

    # Linear: one more unit of ledger costs as much at ten units as at one.
    assert work(11) - work(10) <= (work(2) - work(1)) * 1.1
