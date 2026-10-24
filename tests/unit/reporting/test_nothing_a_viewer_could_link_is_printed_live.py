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


# Targets no reader can be sure of: the HTML report makes no anchor and no image of any.
SCHEMELESS = (
    "![i](//evil.sh/p.png)",
    "![i](//c2.pl/p.png)",
    "[x](//1432778632/)",
    "[x](//intranet/f)",
    "[x](//evil.unknowntld/g)",
    "[x](//0x7f000001/e)",
    "[x](//evil.rs/c)",
    "[x](/absolute/path)",
    "[x](\\\\server\\share)",
    "[x](rel\\path)",
    "![i](https://img.example.org/p.png)",
    "![i](p.png)",
)


@pytest.mark.parametrize("markdown", SCHEMELESS)
def test_a_schemeless_or_image_target_is_no_anchor_and_no_image(markdown: str) -> None:
    html = HtmlRenderer()._markdown_to_html(f"Before {markdown} after.")

    assert _hrefs(html) == []
    assert "<img" not in html


def test_an_in_page_target_stays_a_link_and_a_relative_path_does_not() -> None:
    # A path beside the page names a file no reader of an exported report has.
    html = HtmlRenderer()._markdown_to_html("[a](#section-8) and [b](appendix/figures.html)")

    assert _hrefs(html) == ["#section-8"]


@pytest.mark.parametrize("cell", ["[x](//eViL.com/a)", "![i](//eViL.com/p.png)"])
def test_a_mixed_case_host_in_a_context_cell_is_no_anchor_and_no_image(cell: str) -> None:
    from maljan.reporting.models import StaticAnalysis, StringIOC

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        static=StaticAnalysis(
            interesting_strings=[StringIOC(value="/a C", kind="path", notes=cell)]
        ),
    )
    html = HtmlRenderer().render(report)

    assert not [href for href in _hrefs(html) if "evil" in href.lower()]
    assert "<img" not in html


def test_the_html_report_carries_a_content_security_policy() -> None:
    html = HtmlRenderer().render(_report("It beacons."))

    assert (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
    ) in html


# Hosts whose labels start or end with an underscore. The Markdown escapes an
# underscore that could open emphasis, and that escape comes after the
# defanger has read the value: escaped first, "\_ldap.\_tcp..." was no host to
# the defanger and printed live. The first three are the run's own values, the
# last one a host the run never recorded.
UNDERSCORE_HOSTS = (
    "_ldap._tcp.dc._msdcs.victimcorp.com",
    "my_.duckdns.org",
    "cdn_.update-srv.net",
)
UNRECORDED_UNDERSCORE_HOST = "www._x.ru"


def _underscore_report() -> MalwareReport:
    from maljan.reporting.models import EvidenceSection, NetworkDomain, NetworkIOCs

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=host) for host in UNDERSCORE_HOSTS]),
        sections=[
            EvidenceSection(
                key="tool_dns",
                title="DNS queries",
                kind="table",
                columns=["Query"],
                rows=[
                    [f"query {host}"] for host in (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST)
                ],
                evidence_ids=["ev_0001"],
            )
        ],
    )


def _live(text: str, host: str) -> bool:
    """Whether ``host`` reads live in ``text`` once its Markdown escapes are read."""
    return host in text.replace("\\", "")


@pytest.mark.parametrize("host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST))
def test_an_underscore_host_in_an_appendix_cell_is_defanged(host: str) -> None:
    report = _underscore_report()
    markdown = MarkdownRenderer().render(report)
    appendix = markdown[markdown.index("### DNS queries") :]
    html = HtmlRenderer().render(report)

    assert not _live(appendix, host)
    assert host.replace(".", "[.]") in appendix.replace("\\", "")
    assert host not in html


@pytest.mark.parametrize("host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST))
def test_an_underscore_host_in_a_finding_message_is_read_before_it_is_escaped(host: str) -> None:
    # A finding message is defanged by the reader of every host, not by the
    # run's own values: the escape must leave it exactly what that reader
    # makes of the message, and a host the reader knows ("www.") defanged.
    from maljan.reporting.renderers.markdown import _defanged_text, _finding_text

    message = f"CLAIM 'it queries {host}' cites no entry"
    said = _finding_text({"message": message})

    assert said.replace("\\", "") == _defanged_text(message)
    if host == UNRECORDED_UNDERSCORE_HOST:
        assert not _live(said, host)
        assert host.replace(".", "[.]") in said.replace("\\", "")


@pytest.mark.parametrize("host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST))
def test_an_underscore_host_a_tool_wrote_is_defanged_inline(host: str) -> None:
    from maljan.reporting.renderers.markdown import _Context

    said = _Context(_underscore_report()).inline(f"the tool saw {host} first")

    assert not _live(said, host)
    assert host.replace(".", "[.]") in said.replace("\\", "")
