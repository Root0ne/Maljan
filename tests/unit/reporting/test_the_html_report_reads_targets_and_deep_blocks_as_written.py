"""The HTML report's Markdown reader decides on what the source wrote, and drops nothing.

Two properties of the reader itself, independent of the Markdown writer:

* A link's or an image's target spelled with a character reference
  (``[a](https&#58;//x)``) is never an anchor. markdown-it decodes a target
  before it is validated, so the decision is taken on the target as written.
* A block markdown-it stops reading at its nesting bound is shown as its
  source in a ``<pre>``, so the text past the bound (a 25-deep quote's
  innermost line) is still in the report.
"""

from __future__ import annotations

import re

import pytest

from maljan.reporting.renderers.html import HtmlRenderer

_html = HtmlRenderer._markdown_to_html


@pytest.mark.parametrize(
    "markdown",
    [
        "[a](https&#58;//evil.example/)",
        "[a](https&#x3a;//evil.example/)",
        "[a](https&colon;//evil.example/)",
        "[a](javascript&#58;fetch('//evil.example'))",
        "[a](javascript&colon;fetch('//evil.example'))",
        "[a](<https&#58;//evil.example/>)",
        "[a](&#104;ttps://evil.example/)",
        "![i](https&#58;//evil.example/a.png)",
        "[a][r]\n\n[r]: https&#58;//evil.example/",
    ],
)
def test_a_target_spelled_with_a_reference_is_no_live_link(markdown: str) -> None:
    html = _html(markdown)
    assert "<a " not in html
    assert "<img" not in html
    assert "href" not in html
    # The link stays as its text, nothing of it dropped.
    assert "evil.example" in html


def test_a_reference_the_writer_escaped_is_no_link_either() -> None:
    assert "<a " not in _html("[a](https\\&#58;//evil.example/)")


@pytest.mark.parametrize(
    ("markdown", "href"),
    [
        (
            "[a](https://attack.mitre.org/techniques/T1055/)",
            "https://attack.mitre.org/techniques/T1055/",
        ),
        ("[a](http://example.org/p)", "http://example.org/p"),
        ("[a](mailto:soc@example.org)", "mailto:soc@example.org"),
        ("[a](#sec-indicators)", "#sec-indicators"),
        ("[a](evidence-bundle.html#ev_1)", "evidence-bundle.html#ev_1"),
        ("[a](<https://example.org/a b>)", "https://example.org/a%20b"),
        ("[a](https://example.org/\\(x\\))", "https://example.org/(x)"),
        ("[a][r]\n\n[r]: https://example.org/r", "https://example.org/r"),
        ("<https://example.org/auto>", "https://example.org/auto"),
    ],
)
def test_a_target_written_plainly_links_as_before(markdown: str, href: str) -> None:
    assert re.findall(r'<a href="([^"]*)"', _html(markdown)) == [href]


def _quote(depth: int, text: str) -> str:
    return ">" * depth + " " + text


def test_a_quote_past_the_nesting_bound_keeps_its_innermost_text() -> None:
    markdown = (
        "Before the quote.\n\n" + _quote(25, "innermost <b>text</b>") + "\n\n## After\n\nThe rest."
    )
    html = _html(markdown)
    # The quote is its source, escaped, so nothing in it is lost and no tag runs.
    assert "<pre>" + "&gt;" * 25 + " innermost &lt;b&gt;text&lt;/b&gt;</pre>" in html
    assert "<b>" not in html
    # The blocks around it render as Markdown.
    assert "<p>Before the quote.</p>" in html
    assert "<h2>After</h2>" in html
    assert "<p>The rest.</p>" in html


def test_a_list_past_the_nesting_bound_keeps_every_item() -> None:
    items = "".join("  " * level + f"- item {level}\n" for level in range(25))
    html = _html("Intro.\n\n" + items)
    assert "<p>Intro.</p>" in html
    for level in range(25):
        assert f"- item {level}" in html
    assert "<pre>" in html


@pytest.mark.parametrize("depth", [1, 5, 19])
def test_a_quote_within_the_nesting_bound_renders_as_it_did(depth: int) -> None:
    html = _html(_quote(depth, "inner text"))
    assert "<pre>" not in html
    assert html.count("<blockquote>") == depth
    assert "<p>inner text</p>" in html


def test_the_first_depth_past_the_bound_is_shown_as_its_source() -> None:
    assert "<pre>" in _html(_quote(20, "t"))


def test_the_target_check_belongs_to_the_report_reader_alone() -> None:
    from markdown_it import MarkdownIt

    # A plain reader still decodes and links: the check is not patched in globally.
    assert "href" in MarkdownIt().render("[a](https&#58;//x)")


def test_the_reader_internals_the_renderer_leans_on_are_importable() -> None:
    from markdown_it.common.utils import UNESCAPE_ALL_RE
    from markdown_it.rules_core.normalize import NEWLINES_RE, NULL_RE

    assert UNESCAPE_ALL_RE.search("&#58;") and NEWLINES_RE.search("\r\n") and NULL_RE.search("\0")
