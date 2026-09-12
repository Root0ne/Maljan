"""The contract: no section of a report says anything it cannot point at.

This is the check the whole phase exists for. A section either names the
ledger entries it was built from or names the source that produced it, and the
run summary counts any that do neither — so a regression here is visible in a
number the report itself carries, not only in this test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.ledger_report import build_sections, section_is_grounded
from maljan.reporting.models import EvidenceSection
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, Artifact, Finding
from tests.unit._ledger_helpers import entry

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"


def _full_ledger() -> list[Any]:
    """One entry per fixture, which is one entry per tool the report knows."""
    counter = EvidenceCounter()
    out = []
    for path in sorted(_FIXTURES.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        out.append(entry(path.stem, payload, counter))
    # A tool no builder knows, so the generic fallbacks are in the sample too.
    out.append(entry("frobnicate", {"depth": 3}, counter))
    out.append(entry("narrate", "a paragraph of prose", counter))
    return out


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            artifacts=[
                Artifact(
                    kind="iocs",
                    label="C2",
                    columns=["Kind", "Value"],
                    rows=[["domain", "c2.evil.tld"]],
                    evidence_ids=["ev_0006"],
                )
            ],
            findings=[
                Finding(
                    title="Beacons to a hard-coded host", confidence=0.7, evidence_ids=["ev_0006"]
                )
            ],
        )
    }


@pytest.fixture
def report():
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isrs(),
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_file_type="PE",
        sample_platform="windows",
        evidence_ledger=_full_ledger(),
    ).build_deterministic()


def test_every_section_names_its_evidence_or_its_source(report) -> None:
    assert [s.key for s in report.sections if not section_is_grounded(s)] == []


def test_every_tool_section_cites_an_entry_the_index_knows(report) -> None:
    known = {row.id for row in report.evidence_index}
    cited = {eid for section in report.sections for eid in section.evidence_ids}
    # An id a section cites but the index does not carry is a citation that
    # resolves to nothing, which is worse than no citation at all.
    assert cited - known == set()


def test_the_rendered_report_prints_the_evidence_ids(report) -> None:
    markdown = MarkdownRenderer().render(report)
    assert "## Evidence" in markdown
    assert "_Evidence: ev_0001" in markdown


def test_a_section_built_from_nothing_is_not_produced() -> None:
    # An empty ledger yields only the routing identity block, which carries a
    # source rather than an entry id and is grounded by that.
    sections = build_sections([], {}, "PE", "windows")
    assert [section.key for section in sections] == ["identity"]
    assert sections[0].source == "routing"


class TestTheCheckCanFail:
    """The number is only worth reading if something can make it non-zero."""

    def _section(self, **over) -> EvidenceSection:
        return EvidenceSection(key="k", title="T", kind="table", rows=[["a"]], **over)

    def test_a_section_that_names_nothing_is_ungrounded(self) -> None:
        assert section_is_grounded(self._section()) is False

    def test_naming_a_tool_is_not_grounding(self) -> None:
        # A builder that produced rows without recording which call they came
        # from is exactly the defect this counter exists to surface.
        assert section_is_grounded(self._section(source="tool:pe_info")) is False

    def test_citing_an_entry_is_grounding(self) -> None:
        assert section_is_grounded(self._section(evidence_ids=["ev_0001"])) is True

    def test_a_finding_an_artifact_and_the_routing_minimum_are_grounding(self) -> None:
        for source in ("finding", "artifact:static", "routing"):
            assert section_is_grounded(self._section(source=source)) is True, source

    def test_the_run_summary_counts_an_ungrounded_section(self, report) -> None:
        report.sections.append(self._section())
        ungrounded = sum(1 for s in report.sections if not section_is_grounded(s))
        assert ungrounded == 1

    def test_a_real_run_leaves_the_count_at_zero(self, report) -> None:
        assert sum(1 for s in report.sections if not section_is_grounded(s)) == 0
