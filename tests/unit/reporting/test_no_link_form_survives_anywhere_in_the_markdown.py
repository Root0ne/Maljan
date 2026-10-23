"""No form a viewer links is left live anywhere in the Markdown, whatever its host.

A viewer makes a link of text only by its form: a scheme followed by ``//``, a
scheme a link or autolink syntax opens (``<…>``, ``[x](…)``, ``[r]: …``), a
``mailto:``-style scheme, a ``www.`` prefix or a mailbox. Every such form is
defanged whatever its top-level domain, length or shape; only a reference
service's own lookup stays a link. So the check is one regular expression over
the whole output, with the kept lookups taken out first, and no rule of any
viewer can differ from it: every probe payload the reviews used goes through a
report's prose and an indicator's context cell, and none leaves a live form.
"""

from __future__ import annotations

import json
import re

import pytest

from maljan.core.paths import resolve_data
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer, _defanged_text

# A reference service's own lookup, the one form that stays a link.
_KEPT = re.compile(
    r"(?i)https://(?:www\.virustotal\.com/gui/(?:file|url|domain|ip-address)/[A-Za-z0-9.:-]+/?"
    r"|bazaar\.abuse\.ch/sample/[0-9a-f]{64}/?"
    r"|attack\.mitre\.org/(?:techniques|tactics|software|matrices)/[A-Za-z0-9/]+)"
)
_AUTHORITY = r"[^\s/?#\\<>()\[\]{}\"'`|]*"
_DEFANGED = ("hxxp", "hxxps", "fxp")
# A scheme before "//", read whole from its first letter.
_SCHEME = re.compile(r"(?i)(?<![a-z0-9+.-])[0-9+.-]*([a-z][a-z0-9+.-]*)://")
_LIVE_FORMS = (
    # A defanged scheme whose host still holds a bare dot.
    re.compile(r"(?i)(?:hxxps?|fxp)://" + _AUTHORITY + r"(?<!\[)\.(?!\])"),
    # A scheme a link or autolink syntax opens.
    re.compile(r"(?i)(?:<|\]\(<?|(?<!\[[.:@])\]:[ \t]*)(?!(?:hxxps?|fxp):)[a-z][a-z0-9+.-]{1,31}:"),
    # A scheme a viewer links without "//".
    re.compile(r"(?i)(?<![a-z0-9+.-])(?:mailto|xmpp|javascript|vbscript|data):(?=[^\s:])"),
    # A "www." prefix with its dot bare.
    re.compile(r"(?i)(?<![^\W_])www\."),
    # A mailbox with its "@" bare and a dot in its domain.
    re.compile(r"[\w.+-]@[\w-]+\.[\w-]"),
    # A "//" target whose host holds a bare dot.
    re.compile(r"//[\w-]+\.[\w-]"),
)


def live_forms(markdown: str) -> list[str]:
    text = _KEPT.sub("KEPT", markdown)
    found_at = [
        found for found in _SCHEME.finditer(text) if found.group(1).lower() not in _DEFANGED
    ]
    found_at += [found for pattern in _LIVE_FORMS for found in pattern.finditer(text)]
    return [text[max(0, found.start() - 16) : found.end() + 16] for found in found_at]


FORMS = (
    "ws://2130706433/x",
    "sftp://10.0.0.1/in",
    "a1://evil.example",
    "WS://EVIL.EXAMPLE",
    "<irc:evil.example>",
    "<HTTP:evil.example>",
    "[x](irc:evil.example)",
    "[x](<irc:evil.example>)",
    "[r]: irc:evil.example",
    "mailto:evil.example",
    "javascript:alert(1)",
    "xmpp:op@evil.example",
    "hxxp://evil.example/a",
    "HXXPS://203.0.113.9/x",
    "fxp://files.example.org/a",
    "op@evil.sh and www.evil.zip and http://evil.rs/x",
)


def _payloads() -> list[str]:
    from tests.unit.reporting.test_every_autolink_start_is_defanged import AUTOLINK_STARTS

    fixture = json.loads(
        resolve_data("tests/fixtures/defang/earlier_defanger.json").read_text(encoding="utf-8")
    )
    payloads = [row["payload"] for row in fixture["rows"]]
    return list(dict.fromkeys([*payloads, *AUTOLINK_STARTS, *FORMS]))


PAYLOADS = _payloads()


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


@pytest.mark.parametrize("payload", FORMS)
def test_a_link_form_is_defanged_whatever_its_host(payload: str) -> None:
    assert live_forms(_defanged_text(f"Before {payload} after.")) == []


def test_no_probe_payload_leaves_a_live_form_anywhere_in_the_markdown() -> None:
    live: dict[str, list[str]] = {}
    for payload in PAYLOADS:
        found = live_forms(MarkdownRenderer().render(_report(f"Before {payload} after.")))
        if found:
            live[payload] = found
    assert live == {}


def test_all_probe_payloads_at_once_leave_no_live_form() -> None:
    assert live_forms(MarkdownRenderer().render(_report("\n\n".join(PAYLOADS)))) == []


AS_WRITTEN = (
    "Data::Data::Modulo [C0058] and Cryptography::Encrypt Data::RC4",
    "data: 5 bytes, mailto: none",
    "It is an ASP.NET page handler; the crate ships lib.rs.",
    "FileVersion 10.0.0.1 is in its resources.",
)


@pytest.mark.parametrize("sentence", AS_WRITTEN)
def test_a_text_that_is_no_link_form_prints_as_written(sentence: str) -> None:
    assert sentence in MarkdownRenderer().render(_report(sentence))


# A link form spelled with character references, which a viewer decodes after
# the defanger has read the text: decimal, hexadecimal and named, for a link,
# an image and a bare URL.
REFERENCE_FORMS = (
    "https&#58;//evil&#46;example/a",
    "https&colon;//evil&period;example/a",
    "https&#x3a;//evil&#x2e;example/a",
    "https&#X3A;//evil&#X2E;example/a",
    "https&#0058;//evil&#00046;example/a",
    "[c](https&#58;//evil&#46;example/)",
    "[c](https&colon;//evil&period;example/)",
    "[c](https&#x3a;//evil&#x2e;example/)",
    "![i](https&#58;//evil&#46;example/a.png)",
    "![i](https&colon;//evil&period;example/a.png)",
    "![i](https&#x3A;//evil&#x2E;example/a.png)",
    "<https&#58;//evil&#46;example/a>",
    "op&#64;evil&#46;example and www&period;evil&period;example",
)
# A target that names a scheme or a host, which a link beside the page does not.
_ABSOLUTE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:|[/\\]{2}")
# A character reference left for a viewer to decode: an "&" no backslash escapes.
_LIVE_REFERENCE = re.compile(r"(?<!\\)&(?:#[0-9]|#[xX][0-9A-Fa-f]|colon;|period;|commat;)")


def _reference_report(text: str) -> MalwareReport:
    """``text`` in prose, a string's notes, a request's user agent and the PDB path."""
    report = _report(text)
    report.static.pdb_path = text
    report.network = NetworkIOCs(
        urls=[NetworkURL(url="http://a.example/p", source="sandbox", user_agent=text)]
    )
    return report


def _as_a_viewer_reads_it(markdown: str) -> tuple[str, list[str]]:
    """The text a CommonMark viewer shows, references decoded, and every link and image target."""
    from markdown_it import MarkdownIt

    shown: list[str] = []
    targets: list[str] = []
    for token in MarkdownIt("commonmark").enable("table").parse(markdown):
        for child in token.children or []:
            if child.type in ("text", "code_inline"):
                shown.append(child.content)
            elif child.type in ("link_open", "image"):
                targets.append(str(child.attrs.get("href") or child.attrs.get("src") or ""))
    return "\n".join(shown), targets


@pytest.mark.parametrize("payload", REFERENCE_FORMS)
def test_a_link_form_spelled_with_references_is_no_link_once_decoded(payload: str) -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    report = _reference_report(f"Before {payload} after.")
    markdown = MarkdownRenderer().render(report)
    # A reference left as written stands in a code span, where no viewer decodes it.
    shown, targets = _as_a_viewer_reads_it(markdown)
    assert live_forms(shown) == []
    # A viewer may still make a link of the escaped text: a path beside the
    # page, naming no scheme and no host.
    assert [target for target in targets if _ABSOLUTE.match(target) or live_forms(target)] == []
    html = HtmlRenderer().render(report, embed_figures=False)
    assert "evil" not in "".join(re.findall(r'<a href="[^"]*"', html))
    assert "<img" not in html


def test_the_html_report_links_no_target_whose_source_held_an_ampersand() -> None:
    from maljan.reporting.renderers.html import _report_link

    assert not _report_link("https&#58;//evil&#46;example/")
    assert not _report_link("https://evil.example/?a=1&b=2")
    assert _report_link("https://attack.mitre.org/techniques/T1055/")
    assert _report_link("#sec-indicators")
    assert not _report_link("payload.html")
    assert not _report_link("//evil.example/a")


@pytest.mark.parametrize(
    "text",
    [
        "x\n```text\nYour files &amp; &#169; &colon; here\n```\ny",
        "a `&amp;b&#169;` c",
        "a `` x`&amp; `` c",
        "| `a\\|&amp;` | b |",
    ],
)
def test_a_reference_in_code_prints_byte_for_byte(text: str) -> None:
    from maljan.reporting.renderers.markdown import _escaped_references

    assert _escaped_references(text) == text


@pytest.mark.parametrize(
    ("text", "written"),
    [
        ("a &amp; `b` &#58;", "a \\&amp; `b` \\&#58;"),
        # A run no run closes: the line is read as text.
        ("a ` &amp; `` b", "a ` \\&amp; `` b"),
        # A tag a viewer reads before the span.
        ('<x a="`">&#58;<y b="`">', '<x a="`">\\&#58;<y b="`">'),
        # A table row splits a span at an unescaped separator.
        ("| `a | &#58;` |", "| `a | \\&#58;` |"),
        # A line after one that did not hold its own spans.
        ("a `b\nc` &#58; `d`", "a `b\nc` \\&#58; `d`"),
        # An indented code block is read as text.
        ("    &amp;", "    \\&amp;"),
        # A fence in a list item is no fence at the line's start.
        ("- ```\n  &amp;", "- ```\n  \\&amp;"),
    ],
)
def test_a_reference_outside_code_or_where_code_is_unsure_is_escaped(
    text: str, written: str
) -> None:
    from maljan.reporting.renderers.markdown import _escaped_references

    assert _escaped_references(text) == written


def test_a_line_that_may_open_an_html_block_reads_no_code_anywhere() -> None:
    markdown = MarkdownRenderer().render(
        _report("<pre>\n\nBefore `https&#58;//evil&#46;example` after.")
    )
    assert not _LIVE_REFERENCE.findall(markdown)


def test_a_fence_and_a_code_span_holding_references_print_byte_for_byte() -> None:
    from maljan.reporting.models import RansomNote

    report = _report("plain")
    report.static.pdb_path = "C:\\a&amp;b&#169;.pdb"
    report.technical_analysis.ransom_note = RansomNote(verbatim_content="Files &amp; &#169; ZZQ")
    markdown = MarkdownRenderer().render(report)
    assert "`C:\\a&amp;b&#169;.pdb`" in markdown
    assert "Files &amp; &#169; ZZQ" in markdown


@pytest.mark.parametrize(
    ("text", "length", "written"),
    [
        ("abc", 5, "abc"),
        ("abcdef", 4, "abc…"),
        ("\\[a\\]bcd", 4, "\\[a\\]…"),
        ("ab\\*cd", 3, "ab…"),
        ("ab\\*", 3, "ab\\*"),
    ],
)
def test_an_escaped_text_is_cut_by_what_a_reader_sees(text: str, length: int, written: str) -> None:
    from maljan.reporting.renderers.markdown import _truncate_escaped

    assert _truncate_escaped(text, length) == written


# A "[" before a span, with a stray backtick later in the paragraph: a viewer
# reads the link text first and pairs no backtick on the first line.
BRACKET_BEFORE_A_SPAN = (
    "[ `x [c](https&#58;//evil&#46;example/) y`\n`",
    "[ `x [c](https&#58;//evil&#46;example/) y` `",
    "[note] `x [c](https&#58;//evil&#46;example/) y`\nand a stray ` here",
    "See [the beacon] `x ![i](https&#58;//evil&#46;example/a.png) y`\n`",
)


@pytest.mark.parametrize("prose", BRACKET_BEFORE_A_SPAN)
def test_a_bracket_before_a_span_keeps_no_reference_live(prose: str) -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        executive_summary=prose,
    )
    html = HtmlRenderer().render(report, embed_figures=False)
    assert "evil" not in "".join(re.findall(r'<a href="[^"]*"', html))
    assert "<img" not in html
    assert "https://evil" not in html


def test_a_block_with_one_unsure_line_is_escaped_whole() -> None:
    from maljan.reporting.renderers.markdown import _escaped_references

    assert _escaped_references("`&#58;`\n`\n\n`&#58;`") == "`\\&#58;`\n`\n\n`&#58;`"


@pytest.mark.parametrize(
    "text",
    [
        "  ```\n```\n[c](https&#58;//evil&#46;example/)",
        "   ~~~\n~~~\n[c](https&#58;//evil&#46;example/)",
        "- a\n  ```\n[c](https&#58;//evil&#46;example/)",
        # The list item's fence ends with the item; the fences after it open
        # where the scanner would have closed one.
        "- \n  ```\n  - x\n```\n|\n```\n[c](https&#58;//evil&#46;example/)",
    ],
)
def test_a_fence_opened_after_spaces_keeps_no_reference_live(text: str) -> None:
    from html import unescape

    from markdown_it import MarkdownIt

    from maljan.reporting.renderers.markdown import _escaped_references

    html = MarkdownIt("commonmark").render(_escaped_references(text))
    # A viewer may link the escaped text beside the page; never to the host.
    hrefs = [unescape(href) for href in re.findall(r'<a href="([^"]*)"', html)]
    assert not [href for href in hrefs if href.lower().startswith(("http:", "https:", "//"))]
