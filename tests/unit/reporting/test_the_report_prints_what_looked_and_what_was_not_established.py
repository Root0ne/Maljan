"""The report prints the run's coverage in Appendix B, and only where it was recorded.

A run summary that carries ``coverage`` prints what the run could not
establish, what each tool looked for and over which input, and each negative
claim's coverage, in the markdown and the HTML made from it. A capability
subsection's "nothing recorded" line then says where that is. A summary stored
without the record prints none of it, so every stored run renders byte for
byte as it did.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from maljan.analysis.coverage import (
    ABSENCE_POINTER,
    LOOKED_INTRO,
    NEGATIVES_INTRO,
    NOT_ESTABLISHED_INTRO,
    coverage_lines,
    coverage_record,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.unit.reporting.test_the_report_says_what_left_the_machine import STORED_RENDERS

GENERATED_AT = datetime(2026, 9, 1, tzinfo=UTC)
SAMPLE = "/jobs/j1/sample.exe"


def _record() -> dict:
    entries = [
        LedgerEntry(
            id="ev_0001",
            seq=1,
            agent="static",
            tool="hashes",
            server="analysis",
            source="mcp:analysis",
            args={"path": SAMPLE},
            facts={"v": 1, "kind": "identity", "arguments": {"path": "path"}},
            structured={"sha256": "ab"},
        )
    ]
    claim = ClaimEvidence(
        claim="No URLs were found [ev_0001] `x` [click](https://example.org)",
        evidence_ref="[ev_0001]",
        confidence=0.6,
    )
    record = coverage_record(
        entries=entries,
        isr_reports={"static": AgentISR(agent_id="static", domain="static", claims=[claim])},
        sample_path=SAMPLE,
        fills_staged_sample=lambda entry: False,
    )
    assert record is not None
    return record


def _report(run_summary: dict) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=run_summary,
        generated_at=GENERATED_AT,
    )


def _appendix(markdown: str) -> str:
    return markdown.split("Run summary", 1)[1].split("\n## Appendix C", 1)[0]


def test_a_recorded_coverage_prints_its_three_blocks_in_the_run_summary_appendix() -> None:
    record = _record()
    markdown = MarkdownRenderer().render(_report({"final_decision": "Malware", "coverage": record}))
    appendix = _appendix(markdown)

    for intro in (NOT_ESTABLISHED_INTRO, LOOKED_INTRO, NEGATIVES_INTRO):
        assert intro in appendix
    missing, looked, _negatives = coverage_lines(record)
    for line in (*missing, *looked):
        assert f"- {line}" in appendix
    assert "coverage full" in appendix


def test_a_model_s_claim_cannot_open_a_link_or_a_code_span() -> None:
    markdown = MarkdownRenderer().render(
        _report({"final_decision": "Malware", "coverage": _record()})
    )
    (line,) = [line for line in markdown.splitlines() if "coverage full" in line]
    assert "](https://" not in line
    assert "\\[click\\]" in line


def test_the_html_report_carries_the_blocks() -> None:
    from maljan.reporting.renderers import HtmlRenderer

    html = HtmlRenderer().render(
        _report({"final_decision": "Malware", "coverage": _record()}), nonce="fixed"
    )
    assert "What this run could not establish:" in html
    assert "Negative findings and what looked</strong> (a claim is read as negative" in html


def test_a_summary_without_the_record_prints_no_block_and_no_pointer() -> None:
    markdown = MarkdownRenderer().render(_report({"final_decision": "Malware"}))

    assert NOT_ESTABLISHED_INTRO not in markdown
    assert ABSENCE_POINTER not in markdown


def test_a_nothing_recorded_line_points_to_the_coverage_where_it_was_recorded() -> None:
    from maljan.reporting.renderers.markdown import _Context

    with_record = _Context(_report({"final_decision": "Malware", "coverage": _record()}))
    without = _Context(_report({"final_decision": "Malware"}))
    with_record.file_tools = without.file_tools = ["strings"]

    assert with_record.absence("persistence mechanism", sandbox=False).endswith(ABSENCE_POINTER)
    assert ABSENCE_POINTER not in without.absence("persistence mechanism", sandbox=False)


def test_the_analysts_come_from_the_report_s_own_analyst_record() -> None:
    summary = {
        "final_decision": "Malware",
        "coverage": _record(),
        "failed_analysts": ["static"],
        "stages": [{"key": "analysis", "agent_reasons": {"network": "no capture"}}],
        "agent_stats": [{"agent_id": "intel", "claim_count": 0}],
    }
    report = _report(summary)
    report.degradation_reasons = ["analyst failures: dynamic"]
    appendix = _appendix(MarkdownRenderer().render(report))

    assert "- Analyst `static` failed" in appendix
    assert "- Analyst `dynamic` failed" in appendix
    assert "- Analyst `network` was skipped (`no capture`)." in appendix
    assert "- Analyst `intel` ran and made no claims." in appendix


@pytest.mark.usefixtures("no_model_endpoint_configured")
@pytest.mark.parametrize("run", sorted(STORED_RENDERS))
def test_a_stored_run_renders_as_it_did_before_the_blocks(run: str) -> None:
    from maljan.reporting.renderers import HtmlRenderer
    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
        _benchmark,
    )

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    data = json.loads((root / run / "report.json").read_text())
    assert "coverage" not in (data.get("run_summary") or {})
    report = MalwareReport.model_validate(data)

    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")

    digests = tuple(hashlib.sha256(text.encode()).hexdigest()[:16] for text in (markdown, html))
    assert digests == STORED_RENDERS[run]
    assert NOT_ESTABLISHED_INTRO not in markdown
    assert ABSENCE_POINTER not in markdown
