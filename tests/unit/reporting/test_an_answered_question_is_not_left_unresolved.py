"""A question the producer answered as it allows is recorded as its answer, not left unresolved.

An analyst asked about claim headings under its DISPUTES section is told that a
peer's claim it disputes stays there. One that keeps them there has answered,
so the row it leaves carries ``"answered": "true"``: the report lists it marked
and leaves it out of the count of findings left unresolved.
"""

from __future__ import annotations

import re

from maljan.pipeline.nodes import _violations_from_rows
from maljan.pipeline.validation import (
    ValidationTally,
    claims_kept_under_disputes_finding,
    validation_metrics,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.unit.reporting._report_shapes import rich_report


def test_the_kept_under_disputes_row_carries_answered_on_every_path() -> None:
    finding = claims_kept_under_disputes_finding(1)
    assert finding.answered is True
    assert finding.to_dict()["answered"] == "true"
    # Across the state channel and into the run summary, the flag stays.
    (rebuilt,) = _violations_from_rows([finding.to_dict()])
    assert rebuilt.answered is True
    (row,) = validation_metrics(0, [("reverser", rebuilt)])["unresolved"]
    assert row["answered"] == "true"
    tally = ValidationTally()
    tally.record_unresolved("reverser", [finding])
    assert tally.unresolved[0]["answered"] == "true"


def test_an_ordinary_row_carries_no_answered_key() -> None:
    from maljan.pipeline.validation import claims_under_disputes_violation

    assert "answered" not in claims_under_disputes_violation(1).to_dict()


def test_the_report_lists_an_answered_row_marked_and_does_not_count_it() -> None:
    report = rich_report()
    unresolved = report.run_summary["validation"]["unresolved"]
    before = len([r for r in unresolved if not str(r.get("code", "")).startswith("stix.")])
    unresolved.append(
        {
            "agent": "reverser",
            "code": "isr.claims_under_disputes",
            "message": claims_kept_under_disputes_finding(1).message,
            "answered": "true",
        }
    )
    markdown = MarkdownRenderer().render(report)
    (count,) = re.findall(r"(\d+) finding\(s\) left unresolved", markdown)
    assert int(count) == before
    assert (
        "`isr.claims_under_disputes` (reverser) (answered): Asked, the analyst kept 1 CLAIM "
        "heading(s) under its DISPUTES section; they are not read as its own claims."
    ) in markdown
