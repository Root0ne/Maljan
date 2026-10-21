"""The validation line states the advisory rows as one number.

An advisory row is marked where it stands; a reader had to count the marks.
The headline now says how many of the findings left were advisory (the
platform dropped nothing over them), and says nothing where there were none.
"""

from __future__ import annotations

from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _render(*rows: dict[str, str]) -> str:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"validation": {"retries": 0, "unresolved": list(rows)}},
    )
    return MarkdownRenderer().render(report)


def _row(code: str, **over: str) -> dict[str, str]:
    return {"agent": "judge", "code": code, "message": f"{code} message", **over}


def test_the_headline_counts_the_advisory_findings_by_their_folded_count() -> None:
    markdown = _render(
        _row("attck.advisory_a", advisory="true", count="3"),
        _row("attck.advisory_b", advisory="true"),
        _row("attck.claim_does_not_describe"),
    )

    assert "left unresolved, 4 of them advisory (nothing was dropped over them)" in markdown


def test_no_advisory_finding_adds_nothing_to_the_headline() -> None:
    markdown = _render(_row("attck.claim_does_not_describe"))

    assert "1 finding(s) left unresolved." in markdown
    assert "advisory (nothing" not in markdown
