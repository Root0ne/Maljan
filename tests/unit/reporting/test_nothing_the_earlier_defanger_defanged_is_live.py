"""Every value the earlier, multi-pass defanger defanged is still defanged, with no exception.

``tests/fixtures/defang/earlier_defanger.json`` was written by the defanger the
single reading replaced, over the reviewers' probe payloads (the encoded,
traversal and nested reference forms, the schemeless and image targets, the
autolink starts and the file-shaped names): for each payload, the
network-shaped tokens it did not print as written, and the anchors and images
its HTML held. Each payload goes through a report's prose and an indicator's
context cell now. No token it defanged is printed as written, and the HTML has
no anchor and no image it did not have.
"""

from __future__ import annotations

import json
import re

import pytest

from maljan.core.paths import resolve_data
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer

ROWS = json.loads(
    resolve_data("tests/fixtures/defang/earlier_defanger.json").read_text(encoding="utf-8")
)["rows"]


def _report(text: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=text)
        ),
        static=StaticAnalysis(
            interesting_strings=[StringIOC(value="/a C", kind="path", notes=text)]
        ),
    )


@pytest.mark.parametrize("row", ROWS, ids=[str(index) for index in range(len(ROWS))])
def test_a_value_defanged_before_is_defanged_now(row: dict[str, object]) -> None:
    report = _report(f"Before {row['payload']} after.")
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)
    anchors = set(re.findall(r'<a\s[^>]*href="([^"]*)"', html))

    assert [token for token in row["defanged"] if token in markdown] == []  # type: ignore[union-attr]
    assert anchors <= set(row["anchors"])  # type: ignore[arg-type]
    assert html.count("<img") <= row["images"]  # type: ignore[operator]
