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
# Re-pinned when a process the sample's lineage rule leaves out of its tree
# came to say so (T-511): each desktop process carries
# ``x_maljan_sample_process_tree: false``, and nothing else changed.
STORED_EXPORTS = {
    "run7": "8ef468699faaa757",
    "run5": "5dcfdb861872d1c3",
    "run4": "a4ab66a0f4282d6c",
    "local8": "d4732f60257652b8",
    "haiku4": "1058469a77c8efa0",
}
# ``(markdown, html with the nonce "fixed", normalised STIX)`` for haiku4. The
# Markdown and HTML were re-pinned when a sample's, a tool's or a finding's text
# came to print escaped (F7), and when an analyst's listing came to be read by
# its headings (AUD-43); the STIX did not change. Re-pinned when §10.2's
# introduction came to say each draft rule's body is printed as written
# (T-357): that one line is the only change; the STIX did not change. The STIX
# re-pinned when the export's own malware object came to carry the types the
# published category names (T-337): ``downloader`` and ``backdoor`` after the
# category as written; the Markdown and HTML did not change.
# The Markdown and HTML re-pinned when Appendix A came to say where a cut value
# is whole and the methodology that code is never cut (T-384); the STIX did not
# change.
# The Markdown and HTML re-pinned when the host identifier table came to mark
# each row the IOC table publishes (T-386); the STIX did not change.
# Re-pinned when no table cell of the body came to be cut (T-399) and every
# indicator to indicate the malware object (T-402): the only Markdown and HTML
# changes are body cells that ended in … printed whole, the methodology's
# sentence about cut values and the HTML print stylesheet's fixed table layout;
# each STIX export, here and in ``STORED_EXPORTS``, gains one platform
# ``indicates`` edge per indicator related to no malware object (the similarity
# digests and benign-typed ones aside), each named by the report object, and
# nothing else (run4's export over the judge's bundle gains none).
# Re-pinned when the commands table came to list only what descends from a
# process running the sample (T-494): explorer.exe under sihost.exe leaves the
# table, which has no row left and is not printed; the STIX export did not change.
# The STIX re-pinned when the desktop processes outside the sample's tree came
# to say so (T-511: five carry ``x_maljan_sample_process_tree: false``); the
# Markdown and HTML did not change.
HAIKU4_RENDERS = ("06a395f0432b80a2", "eaaa767d3f812838", "59a81cbf1f25c42e")

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
