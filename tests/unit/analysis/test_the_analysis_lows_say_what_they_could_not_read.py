"""AUD-46: the analysis Low findings (A-L1..A-L5). Every value is synthetic."""

from __future__ import annotations

import time
from typing import Any

from maljan.analysis.evidence_roots import _gather, _Stated, answer_facts, statement_values
from maljan.schemas.evidence import LedgerEntry


def test_a_l1_a_summary_with_no_negotiation_states_no_confidence() -> None:
    from maljan.analysis.run_summary import RunSummaryBuilder

    summary = RunSummaryBuilder(start_time=time.time()).build()

    assert summary.negotiation.final_confidence is None
    assert "final_confidence" not in summary.to_dict()["negotiation"]
    assert "Final confidence" not in summary.to_markdown()


def test_a_l2_a_failed_coverage_or_efficiency_build_says_it_was_not_built() -> None:
    from maljan.analysis.coverage import coverage_record
    from maljan.analysis.disclosure import NOT_BUILT_UNREAD, not_built
    from maljan.analysis.efficiency import efficiency_record

    broken: Any = 5  # not a ledger: reading it raises
    assert coverage_record(entries=broken, isr_reports=broken) == not_built(NOT_BUILT_UNREAD)
    assert efficiency_record(object(), entries=broken, isr_reports=broken) == not_built(
        NOT_BUILT_UNREAD
    )


def test_a_l3_hex_string_section_fields_do_not_break_the_layout() -> None:
    section = {
        "name": ".text",
        "virtual_address": "0x1000",
        "virtual_size": "0x4000",
        "raw_offset": "0x400",
        "raw_size": "0x4000",
    }
    entry = LedgerEntry(
        id="ev_0001", tool="pe_info", structured={"sections": [section]}, agent="pipeline"
    )
    stated = _Stated()

    _gather(entry, stated)

    held = stated.sections[".text"]
    assert (held.size, held.raw, held.raw_size) == (0x4000, 0x400, 0x4000)


def test_a_l4_a_number_equal_to_a_count_places_nothing_without_what_it_counts() -> None:
    facts = answer_facts({"decoded_strings": 3})
    layout: Any = None  # only addresses read it

    assert facts.written_in(statement_values("It loads 3 modules."), layout) is False
    assert facts.written_in(statement_values("FLOSS decoded 3 strings."), layout) is True


def test_a_l5_the_cli_fallback_summary_keeps_the_degradation(tmp_path: Any) -> None:
    from maljan.cli import _write_markdown_report

    summary = {
        "final_decision": "Malware",
        "elapsed_seconds": 1.0,
        "stix_object_count": 1,
        "negotiation": {},
        "agent_stats": [],
        "degraded_mode": True,
        "degradation_reasons": ["the sandbox never attached"],
    }
    out = tmp_path / "r.md"

    _write_markdown_report({"run_summary": summary}, str(out))

    assert "the sandbox never attached" in out.read_text(encoding="utf-8")
