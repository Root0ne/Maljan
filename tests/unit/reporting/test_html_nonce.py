"""The report's ``<style>`` tag carries a caller-supplied CSP nonce (Task 12).

The HTML export is served with a strict per-response Content-Security-Policy
that has no ``'unsafe-inline'`` for styles; instead the report route mints a
nonce and this renderer stamps it onto the one ``<style>`` tag the document
emits. Passing no nonce (the PDF pipeline's case, and every existing caller)
must render exactly as before.
"""

from __future__ import annotations

from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer


def _report() -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))


def test_style_tag_carries_the_nonce() -> None:
    out = HtmlRenderer().render(_report(), embed_figures=False, nonce="abc123==")
    assert '<style nonce="abc123==">' in out
    assert "<script" not in out


def test_no_nonce_means_no_attribute() -> None:
    assert "<style>" in HtmlRenderer().render(_report(), embed_figures=False)
