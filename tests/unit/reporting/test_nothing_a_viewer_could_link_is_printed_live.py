"""Nothing a viewer could make a link of is printed live; a word that is no link is as written.

The report is read three ways: as Markdown, as the HTML the platform renders
from it, and on a forge that autolinks a scheme URL, a ``www.`` host and a
mailbox in plain text. The defanger and those viewers must not disagree about
a sample's value: a value the defanger leaves alone must be one no viewer
links. So every scheme URL (any scheme), every ``www.`` host, every mailbox,
every IPv4 or IPv6 address that is no version number, every host under a real
top-level domain and every ``.onion`` name is defanged, by one reader; and the
platform's HTML renderer links no bare text and no link whose scheme is not
http, https or mailto, so a defanged URL never becomes an anchor. Names that
no viewer links (ASP.NET, lib.rs, .NET, System.IO, FileVersion 10.0.0.1,
v1.2.3.4) print as written.
"""

from __future__ import annotations

import re

import pytest

from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(sentence: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
        ),
    )


def _hrefs(html: str) -> list[str]:
    return re.findall(r"<a\s[^>]*href=\"([^\"]*)\"", html)


# Each sentence, and the live text that must not survive it.
CLICKABLE = (
    ("It posts to https://relay.example.net/gate.", "relay.example.net"),
    ("It fetches ftp://files.example.org/a.bin.", "files.example.org"),
    ("It opens sftp://drop.example.org/in.", "drop.example.org"),
    ("It talks over ws://chat.example.org/sock.", "chat.example.org"),
    ("It reads www.relay-example.zz first.", "www.relay-example.zz"),
    ("It reads WWW.RELAY.EXAMPLE.COM first.", "WWW.RELAY.EXAMPLE.COM"),
    ("Mail goes to op@mail.example.org.", "op@mail.example.org"),
    ("It connects to 203.0.113.9 on 443.", "203.0.113.9"),
    ("It connects to 2001:db8::1 on 443.", "2001:db8::1"),
    ("It beacons to relay.example.net.", "relay.example.net"),
    ("It beacons to RELAY.EXAMPLE.NET.", "RELAY.EXAMPLE.NET"),
    ("It resolves dl.delivery.mp.example.com.", "dl.delivery.mp.example.com"),
    ("Its panel is at abcdefghij234567.onion.", "abcdefghij234567.onion"),
    ("It wrote <https://relay.example.net/a> in its config.", "relay.example.net"),
    ("It wrote [the panel](http://relay.example.net/p) in its notes.", "relay.example.net"),
)
AS_WRITTEN = (
    "It is an ASP.NET page handler.",
    "It targets .NET and calls System.IO.File.",
    "The crate ships lib.rs.",
    "FileVersion 10.0.0.1 is in its resources.",
    "The build is v1.2.3.4 of the loader.",
)


@pytest.mark.parametrize(("sentence", "live"), CLICKABLE)
def test_a_clickable_value_is_live_in_neither_the_markdown_nor_the_html(
    sentence: str, live: str
) -> None:
    report = _report(sentence)
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)

    assert live not in markdown
    assert live.lower() not in html.lower()
    assert not [href for href in _hrefs(html) if "example" in href or "onion" in href]


@pytest.mark.parametrize("sentence", AS_WRITTEN)
def test_a_word_no_viewer_links_prints_as_written(sentence: str) -> None:
    report = _report(sentence)
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)

    assert sentence in markdown
    assert sentence in html


def test_the_html_renderer_links_no_bare_text_and_no_defanged_scheme() -> None:
    html = HtmlRenderer()._markdown_to_html(
        "See www.example.com, op@example.com and lib.rs.\n\n"
        "<hxxps://relay[.]example[.]net/a> and [x](hxxp://relay[.]example[.]net/p)\n\n"
        "[ATT&CK](https://attack.mitre.org/techniques/T1055/)"
    )

    assert _hrefs(html) == ["https://attack.mitre.org/techniques/T1055/"]
