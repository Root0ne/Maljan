"""An identical unresolved finding is listed once, with how many times it was left.

Several claims with one sentence and one id each leave the same finding, and
the run summary and the report's section 13 printed it once per claim. Each
identical (agent, finding) row is now listed once with its count; ``by_code``
still counts every one, and a row left once reads as it always did.
"""

from __future__ import annotations

from maljan.pipeline.validation import Violation, folded_rows, validation_metrics
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer

CODE = "attck.claim_does_not_describe"


def _violation(message: str) -> Violation:
    return Violation(code=CODE, message=message, subject="T1001")


def test_the_run_summary_lists_an_identical_row_once_with_its_count() -> None:
    same = _violation("CLAIM 'x' carries TECHNIQUE T1001.")
    other = _violation("CLAIM 'y' carries TECHNIQUE T1001.")
    metrics = validation_metrics(
        1, [("network", same), ("network", same), ("network", other), ("network", same)]
    )

    rows = metrics["unresolved"]
    assert [(row["message"], row.get("count")) for row in rows] == [
        (same.message, "3"),
        (other.message, None),
    ]
    assert metrics["by_code"][CODE] == 4


def test_the_same_message_from_two_agents_is_two_rows() -> None:
    same = _violation("CLAIM 'x' carries TECHNIQUE T1001.")
    rows = validation_metrics(0, [("network", same), ("static", same)])["unresolved"]

    assert [row["agent"] for row in rows] == ["network", "static"]
    assert all("count" not in row for row in rows)


def test_folding_twice_changes_nothing() -> None:
    rows = [{"agent": "a", "code": CODE, "message": "m"}] * 3
    once = folded_rows(rows)

    assert once == [{"agent": "a", "code": CODE, "message": "m", "count": "3"}]
    assert folded_rows(once) == once


def test_section_13_lists_a_stored_repeated_row_once_with_its_count() -> None:
    row = {"agent": "network", "code": CODE, "message": "CLAIM 'x' carries TECHNIQUE T1001."}
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"validation": {"retries": 1, "unresolved": [row, row, row]}},
    )
    markdown = MarkdownRenderer().render(report)

    assert markdown.count("CLAIM 'x' carries TECHNIQUE T1001.") == 1
    assert f"`{CODE}` (network) (left 3 times): " in markdown
    # The headline counts every finding left, as it always did.
    assert "3 finding(s) left unresolved" in markdown


def test_the_run_summary_counts_every_finding_left() -> None:
    from maljan.analysis.run_summary import RunSummaryBuilder

    same = _violation("CLAIM 'x' carries TECHNIQUE T1001.")
    other = _violation("CLAIM 'y' carries TECHNIQUE T1001.")
    metrics = validation_metrics(1, [("network", same)] * 7 + [("static", other)])
    text = RunSummaryBuilder(start_time=0.0).set_validation(metrics).build().to_markdown()

    assert "| Unresolved findings | 8 |" in text
    assert "(left 7 times)" in text
