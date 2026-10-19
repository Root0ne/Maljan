"""A stored run's export, rebuilt over the judge's own bundle, keeps its bytes.

The export is rendered the way the report node renders it: over the judge's
stored bundle (``stix-judge.json``), so the judge's attack-patterns, their
technique ids and the indicator merge of the integrity pass all run on what the
run really answered. The digests are what ``origin/dev`` 5cd25b75 renders (ids
and timestamps normalised). haiku4's Markdown and HTML are pinned here too:
it carries reputation records, so the legacy-reputation digest test does not
hold it. Skipped where the stored runs are not on the machine.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from maljan.reporting.models import MalwareReport
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

# Normalised STIX over the judge's bundle, as dev 5cd25b75 renders it.
STORED_EXPORTS = {
    "run7": "7d838df92fd9d16d",
    "run5": "906f866271a2ba69",
    "run4": "e2a8494073ca71fa",
    "local8": "99fe30245c6e9213",
    "haiku4": "226f93bcdf45d447",
}
# ``(markdown, html with the nonce "fixed", normalised STIX)`` for haiku4. The
# Markdown and HTML were re-pinned when a sample's, a tool's or a finding's text
# came to print escaped (F7), and when an analyst's listing came to be read by
# its headings (AUD-43); the STIX did not change.
HAIKU4_RENDERS = ("230d0d43a8a40244", "269dc8fdf849c364", "7a36a22e070d70fd")

_UUID = re.compile(r"--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _normalised(bundle: object) -> str:
    stix = json.dumps(json.loads(bundle.model_dump_json()), indent=1, sort_keys=True)  # type: ignore[attr-defined]
    return _STAMP.sub("TS", _UUID.sub("--ID", stix))


def _report(run: str) -> MalwareReport:
    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    return MalwareReport.model_validate(json.loads((root / run / "report.json").read_text()))


@pytest.mark.parametrize("run", sorted(STORED_EXPORTS))
def test_the_export_over_the_judge_s_bundle_keeps_its_bytes(run: str) -> None:
    from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
    from maljan.schemas.stix_models import Bundle

    report = _report(run)
    root = _benchmark()
    assert root is not None
    stored = json.loads((root / run / "stix-judge.json").read_text())
    base = Bundle.model_validate(stored["bundle"])

    assert (
        _digest(_normalised(ExtendedSTIXRenderer().render(report, base))) == (STORED_EXPORTS[run])
    )


def test_haiku4_renders_as_dev_rendered_it() -> None:
    from maljan.reporting.renderers import HtmlRenderer, MarkdownRenderer
    from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

    report = _report("haiku4")
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")
    stix = _normalised(ExtendedSTIXRenderer().render(report))

    assert (_digest(markdown), _digest(html), _digest(stix)) == HAIKU4_RENDERS
