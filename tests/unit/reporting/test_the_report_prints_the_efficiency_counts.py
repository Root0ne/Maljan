"""The report prints the run's efficiency counts in Appendix B, and only where they were recorded.

A run summary that carries ``efficiency`` prints its sentences after the
other run-summary lines, in the markdown and in the HTML made from it; one
stored without it prints no block, so every stored run renders byte for byte
as it did.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from maljan.analysis.efficiency import INTRO_SENTENCE, efficiency_lines
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.unit.reporting.test_the_report_says_what_left_the_machine import STORED_RENDERS

GENERATED_AT = datetime(2026, 9, 1, tzinfo=UTC)

RECORD = {
    "v": 1,
    "inputs": {
        "unit": "characters",
        "loops": [
            {
                "agent": "static",
                "stage": "analysis",
                "kind": "tool loop",
                "requests": 2,
                "parts": {"system_prompt": 10, "tool_answers": 30},
                "reported_requests": 2,
                "input_tokens": 12,
            }
        ],
        "calls": {"static": 2},
    },
}


def _report(run_summary: dict) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=run_summary,
        generated_at=GENERATED_AT,
    )


def _appendix(markdown: str) -> str:
    return markdown.split("Run summary", 1)[1].split("\n## Appendix C", 1)[0]


def test_a_recorded_block_prints_in_the_run_summary_appendix() -> None:
    markdown = MarkdownRenderer().render(
        _report({"final_decision": "Malware", "efficiency": RECORD})
    )
    appendix = _appendix(markdown)

    assert INTRO_SENTENCE in appendix
    for line in efficiency_lines(RECORD):
        assert f"- {line}" in appendix


def test_the_html_report_carries_the_block() -> None:
    from maljan.reporting.renderers import HtmlRenderer

    html = HtmlRenderer().render(
        _report({"final_decision": "Malware", "efficiency": RECORD}), nonce="fixed"
    )
    assert "Efficiency:" in html


def test_a_summary_without_the_record_prints_no_block() -> None:
    markdown = MarkdownRenderer().render(_report({"final_decision": "Malware"}))

    assert INTRO_SENTENCE not in markdown


@pytest.mark.parametrize("run", sorted(STORED_RENDERS))
def test_a_stored_run_renders_as_it_did_before_the_block(run: str) -> None:
    from maljan.reporting.renderers import HtmlRenderer
    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
        _benchmark,
    )

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    data = json.loads((root / run / "report.json").read_text())
    assert "efficiency" not in (data.get("run_summary") or {})
    report = MalwareReport.model_validate(data)

    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")

    digests = tuple(hashlib.sha256(text.encode()).hexdigest()[:16] for text in (markdown, html))
    assert digests == STORED_RENDERS[run]
    assert INTRO_SENTENCE not in markdown
