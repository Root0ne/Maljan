"""A report stored before reputation records renders byte for byte as it did.

The four stored benchmark runs carry no ``reputation`` records (the field is
absent from their JSON), so their reputation line is read by the legacy
reading of their section rows (``core.legacy_reputation``). Their Markdown,
their HTML and their STIX bundle (ids and timestamps normalised) are the
digests ``origin/dev`` 2c2522b2 renders. Skipped where the stored runs are not
on the machine.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from maljan.reporting.models import MalwareReport
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

# ``(markdown, html with the nonce "fixed", normalised STIX)`` as dev 2c2522b2 renders them.
# The Markdown and HTML were re-pinned when a sample's, a tool's or a finding's
# text came to print escaped (F7); the STIX did not change.
# Re-pinned when every IOC-table row came to carry a publish answer and the
# export to name the sample by its identity digests (T-344, T-345): a dropped file's
# digest row the record names no process for now prints its refusal, so does
# a command line, the sample's indicator adds its SHA-1 and MD5, its imphash
# is an anomalous-activity indicator of its own, and an indicator's reason is
# read from the rebuilt table.
# The Markdown and HTML re-pinned when §10.2's introduction came to say each
# draft rule's body is printed as written (T-357): that one line is the only
# change; the STIX did not change.
# The STIX re-pinned when the export's own malware object came to carry the
# types the published category names after the category as written (T-337):
# ``loader`` gains ``downloader``. run4's Markdown and HTML re-pinned with it:
# its eight key findings wrote their citations into the sentence, and each is
# no longer printed a second time after it; nothing else changed.
# The Markdown and HTML re-pinned when Appendix A came to draw held code whole
# as listings and to say where a cut value is whole (T-384): only Appendix A and
# Appendix D changed; the STIX did not change.
# The Markdown and HTML re-pinned when the host identifier table came to mark
# each row the IOC table publishes and its footer to say the table publishes
# nothing itself (T-386); the STIX did not change.
# Re-pinned when no table cell of the body came to be cut (T-399) and every
# indicator to indicate the malware object (T-402): the only Markdown and HTML
# changes are body cells that ended in … printed whole, the methodology's
# sentence about cut values and the HTML print stylesheet's fixed table layout;
# the STIX gains one platform ``indicates`` edge per indicator related to no
# malware object (the similarity digests aside), each named by the report
# object, and nothing else.
STORED_RENDERS = {
    "run7": ("b6b67d78ed8bfe45", "985ed08f2496b1e3", "c6313f103ee42d52"),
    "run5": ("3f3f15bbd3933f1f", "b376d7a47c654122", "276aad22c908ff48"),
    "run4": ("9da95bae69272ee5", "7c6021dbe84ce2ff", "b0060de27f126465"),
    "local8": ("9a23cffd548254ce", "ad6790825e501610", "bd6ac195bc590655"),
}

_UUID = re.compile(r"--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


@pytest.mark.parametrize("run", sorted(STORED_RENDERS))
def test_a_stored_run_renders_as_dev_rendered_it(run: str) -> None:
    from maljan.reporting.renderers import HtmlRenderer, MarkdownRenderer
    from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    data = json.loads((root / run / "report.json").read_text())
    assert "reputation" not in data
    report = MalwareReport.model_validate(data)
    assert report.reputation is None
    assert "reputation" not in json.loads(report.model_dump_json())

    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")
    bundle = ExtendedSTIXRenderer().render(report)
    stix = json.dumps(json.loads(bundle.model_dump_json()), indent=1, sort_keys=True)
    stix = _STAMP.sub("TS", _UUID.sub("--ID", stix))

    assert (_digest(markdown), _digest(html), _digest(stix)) == STORED_RENDERS[run]
