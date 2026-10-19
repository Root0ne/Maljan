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
STORED_RENDERS = {
    "run7": ("10450fac1da78b0d", "c898eb0ef67822cf", "91afd1649c923cbb"),
    "run5": ("5ccad835542f23f0", "a06ab76f09a2cb09", "901ef9efc8afb317"),
    "run4": ("1e0160478a729008", "e32e52a8e99b4a47", "84bc0f9a2a45529f"),
    "local8": ("9e6cf8ded02592af", "d1dce0f05d49d9d0", "ddc1552bd2bc0f89"),
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
