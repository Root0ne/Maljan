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
STORED_RENDERS = {
    "run7": ("56ba218bfdd38f0c", "b229d1d5d08362c0", "e24f2d1b2733f7a3"),
    "run5": ("e645b4e33f1e2046", "1d3964267514a2ca", "85795f39d2b17a77"),
    "run4": ("30e4d03751bb2760", "7c21afe931f2652d", "74381ef6ce484e2a"),
    "local8": ("f16aaba51ce874eb", "c18035f83e61303b", "d53c784002386286"),
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
