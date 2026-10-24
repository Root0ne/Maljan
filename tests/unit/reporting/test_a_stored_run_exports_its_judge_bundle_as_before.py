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
# Re-pinned when every IOC-table row came to carry a publish answer and the
# export to name the sample by its identity digests (T-344, T-345): a dropped file's
# digest row the record names no process for now prints its refusal, so does
# a command line, the sample's indicator adds its SHA-1 and MD5, its imphash
# is an anomalous-activity indicator of its own, and an indicator's reason is
# read from the rebuilt table.
STORED_EXPORTS = {
    "run7": "eff64a6fcc7d2c98",
    "run5": "618c6bdf28561f05",
    "run4": "9a3a7b4040b09b57",
    "local8": "23b5d33c962e03b7",
    "haiku4": "860e9bb2afe060ca",
}
# ``(markdown, html with the nonce "fixed", normalised STIX)`` for haiku4. The
# Markdown and HTML were re-pinned when a sample's, a tool's or a finding's text
# came to print escaped (F7), and when an analyst's listing came to be read by
# its headings (AUD-43); the STIX did not change.
HAIKU4_RENDERS = ("9e48dabb38b94d23", "4bda1b01fc6026a1", "ffef51adf3a2ebac")

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
