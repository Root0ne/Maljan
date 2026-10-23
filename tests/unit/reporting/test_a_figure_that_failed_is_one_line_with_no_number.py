"""A figure that failed to draw shows its line once and takes no figure number (RC-14)."""

from __future__ import annotations

from maljan.reporting.models import Figure, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer


def _figure(n: int) -> Figure:
    return Figure(
        id=f"fig-listing-{n}",
        caption=f"Decompiled f{n}",
        kind="code_listing",
        content="<pre class='listing'>x</pre>",
    )


def test_the_line_is_said_once_and_the_numbers_do_not_skip() -> None:
    said = "Figure not drawn: network_graph (ValueError)"
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
    report.figures = [
        _figure(0),
        Figure(
            id="fig-not-drawn-network-graph",
            caption=said,
            kind="not_drawn",
            content=f'<p class="figure-not-drawn">{said}</p>',
        ),
        _figure(1),
    ]
    html = HtmlRenderer().render(report)
    assert html.count(said) == 1
    assert "<b>Figure 1.</b>" in html
    assert "<b>Figure 2.</b>" in html
    assert "<b>Figure 3.</b>" not in html
