"""capa and YARA reach the report the way every other tool does.

The provider has no tool loop, so nothing writes its passes to the evidence
ledger as they run. ``ledger_entries`` does it afterwards, and from there the
rows travel the ordinary route: the section builders print them and the ledger
projection keeps the capability counters and technique hits in front of the
layers that read ``report.static``.
"""

from __future__ import annotations

from maljan.providers.base import StaticEvidenceBundle
from maljan.providers.static.capa_yara import ledger_entries
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter

_CAPA_ROW = {
    "namespace": "data-manipulation/encryption/rc4",
    "rule": "encrypt data using RC4",
    "attck": ["Defense Evasion::Obfuscated Files or Information [T1027]"],
    "mbc": [],
    "match_count": 2,
}
_YARA_HIT = {"rule": "ransom_note", "strings": ["$note at 0x2040"], "technique": "T1486"}


def _bundle(**kwargs) -> StaticEvidenceBundle:
    return StaticEvidenceBundle(**kwargs)


class TestEntries:
    def test_capa_rows_become_a_capa_entry(self):
        entries = ledger_entries(_bundle(capa_rules=[_CAPA_ROW]), EvidenceCounter())
        assert [e.tool for e in entries] == ["capa"]
        assert entries[0].agent == "capa_yara"
        assert entries[0].server is None
        assert entries[0].id == "ev_0001"
        assert entries[0].structured["capabilities"][0]["rule"] == "encrypt data using RC4"

    def test_yara_hits_become_a_yara_entry(self):
        entries = ledger_entries(_bundle(yara_matches=[_YARA_HIT]), EvidenceCounter())
        assert [e.tool for e in entries] == ["yara_scan"]
        assert entries[0].structured["matches"][0]["rule"] == "ransom_note"

    def test_an_empty_bundle_records_nothing(self):
        assert ledger_entries(_bundle(), EvidenceCounter()) == []

    def test_the_ids_come_from_the_job_counter(self):
        counter = EvidenceCounter()
        counter.next_id()
        entries = ledger_entries(_bundle(capa_rules=[_CAPA_ROW], yara_matches=[_YARA_HIT]), counter)
        assert [e.id for e in entries] == ["ev_0002", "ev_0003"]


def _builder(ledger) -> MalwareReportBuilder:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Suspicious",
        overall_confidence=0.5,
        evidence_ledger=ledger,
    )


class TestReachesTheReport:
    def test_capa_capabilities_still_reach_the_static_block(self):
        ledger = ledger_entries(_bundle(capa_rules=[_CAPA_ROW]), EvidenceCounter())
        report = _builder(ledger).build_deterministic()
        assert report.static is not None
        assert report.static.api_capabilities.get("data-manipulation") == 1
        assert any(h["technique_id"] == "T1027" for h in report.static.api_technique_hits)

    def test_capa_and_yara_print_as_evidence_sections(self):
        ledger = ledger_entries(
            _bundle(capa_rules=[_CAPA_ROW], yara_matches=[_YARA_HIT]), EvidenceCounter()
        )
        report = _builder(ledger).build_deterministic()
        keys = {section.key for section in report.sections}
        assert {"capa_capabilities", "yara_matches"} <= keys
        markdown = MarkdownRenderer().render(report)
        assert "encrypt data using RC4" in markdown
        assert "ransom_note" in markdown
        assert "ev_0001" in markdown

    def test_no_evidence_leaves_the_static_block_empty(self):
        report = _builder([]).build_deterministic()
        assert report.static is None
