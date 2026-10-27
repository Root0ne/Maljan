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


# A host the run recorded that the reader of every host leaves as written:
# a two-label name under a top-level domain that is also a file's extension.
# Only the run's own values defang it, so it shows which texts read them.
RECORDED_FILE_EXTENSION_HOST = "loader.sh"
# The codes a finding is printed under: beside the title and §4 (verdict),
# beside §1 (narrative), in the validation list and in the export decisions.
FINDING_CODES = (
    "verdict.unsupported",
    "narrative.unsupported",
    "report.citation_wrong_entry",
    "stix.indicator_dropped",
)


def _finding_report(*hosts: str) -> MalwareReport:
    from maljan.reporting.models import NetworkDomain, NetworkIOCs

    rows = [
        {
            "agent": "composer:x",
            "code": code,
            "message": f"CLAIM 'it queries {host}' cites no entry",
        }
        for host in hosts
        for code in FINDING_CODES
    ]
    recorded = (*UNDERSCORE_HOSTS, RECORDED_FILE_EXTENSION_HOST)
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=host) for host in recorded]),
        run_summary={"validation": {"retries": 1, "unresolved": rows}},
    )


@pytest.mark.parametrize(
    "host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST, RECORDED_FILE_EXTENSION_HOST)
)
def test_a_host_in_a_finding_message_is_defanged_wherever_the_finding_prints(host: str) -> None:
    # A finding message is read with the run's own values, as a tool's text is
    # (``ctx.inline``), and by the reader of every host for one the run never
    # recorded; the escape comes after both.
    report = _finding_report(host)
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)

    printed = [line for line in markdown.splitlines() if "cites no entry" in line]
    assert len(printed) >= len(FINDING_CODES)
    for line in printed:
        assert not _live(line, host), line
        assert host.replace(".", "[.]") in line.replace("\\", ""), line
    assert not _live(markdown, host)
    assert host not in html


@pytest.mark.parametrize("host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST))
def test_the_reader_of_every_host_reads_a_label_with_an_underscore(host: str) -> None:
    # No run's values are given: the host is read by its own shape, labels
    # with an underscore before a name the reader takes for a host.
    from maljan.reporting.renderers.markdown import _defanged_text, _finding_text

    sentence = f"it queries {host}."
    defanged = f"it queries {host.replace('.', '[.]')}"
    assert _defanged_text(sentence) == f"{defanged}."
    assert _finding_text({"message": sentence}).replace("\\", "") == f"{defanged}."


# Identifiers with underscores that name no host: a decompiler's function, a
# dunder, a module or a file, a member access, an import table entry. Each
# prints exactly as written.
UNDERSCORE_IDENTIFIERS = (
    "FUN_00401310",
    "__init__",
    "__init__.py",
    "my_module.py",
    "test_utils.helpers.py",
    "self._data.items",
    "obj.__class__.__name__",
    "sys._getframe",
    "sub_401000",
    "ws2_32.dll",
    "api_ms_win_core.dll",
    "_CorExeMain",
    "this._items.map",
    "foo._bar.com",
    "my_site.com",
)


@pytest.mark.parametrize("identifier", UNDERSCORE_IDENTIFIERS)
def test_an_identifier_with_an_underscore_is_no_host(identifier: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text, _finding_text

    sentence = f"it calls {identifier} first"
    assert _defanged_text(sentence) == sentence
    assert _finding_text({"message": sentence}).replace("\\", "") == sentence
    markdown = MarkdownRenderer().render(_report(f"It calls {identifier} first."))
    assert f"It calls {identifier} first." in markdown.replace("\\", "")


def test_a_recorded_host_in_a_tool_cell_no_context_reads_is_defanged() -> None:
    # A sandbox's request row prints its user agent as the tool wrote it; the
    # closing pass reads the run's own values there too.
    from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkURL

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn=RECORDED_FILE_EXTENSION_HOST)],
            urls=[
                NetworkURL(
                    url="http://203.0.113.9/gate",
                    method="POST",
                    user_agent=f"agent/1.0 ({RECORDED_FILE_EXTENSION_HOST})",
                    source="sandbox",
                )
            ],
        ),
    )
    markdown = MarkdownRenderer().render(report)

    assert "agent/1.0 (loader[.]sh)" in markdown
    assert not _live(markdown, RECORDED_FILE_EXTENSION_HOST)


@pytest.mark.parametrize("host", (*UNDERSCORE_HOSTS, UNRECORDED_UNDERSCORE_HOST))
def test_an_underscore_host_a_tool_wrote_is_defanged_inline(host: str) -> None:
    from maljan.reporting.renderers.markdown import _Context

    said = _Context(_underscore_report()).inline(f"the tool saw {host} first")

    assert not _live(said, host)
    assert host.replace(".", "[.]") in said.replace("\\", "")


# Recorded hosts with an underscore under a TLD that is also a file's
# extension: the reader of every host leaves each as written, and an escaped
# cell writes its underscore as "\_", so only the run's values, read before
# the escape or in their escaped spelling, defang it.
RECORDED_ESCAPED_HOSTS = ("cdn_.evil.zip", "my_.files.sh")


def _user_agent_report(user_agent: str) -> MalwareReport:
    from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkURL

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn=host) for host in RECORDED_ESCAPED_HOSTS],
            urls=[
                NetworkURL(
                    url="http://203.0.113.9/gate",
                    method="POST",
                    user_agent=user_agent,
                    source="sandbox",
                )
            ],
        ),
    )


@pytest.mark.parametrize("host", RECORDED_ESCAPED_HOSTS)
def test_a_recorded_underscore_host_in_an_escaped_cell_is_defanged(host: str) -> None:
    report = _user_agent_report(f"agent/1.0 ({host})")
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)

    assert not _live(markdown, host)
    assert f"agent/1.0 ({host.replace('.', '[.]')})" in markdown.replace("\\", "")
    assert host not in html
    assert host.replace(".", "[.]") in html


@pytest.mark.parametrize("host", RECORDED_ESCAPED_HOSTS)
def test_the_closing_pass_reads_a_recorded_value_in_its_escaped_spelling(host: str) -> None:
    # A cell a helper with no context escaped before any run value was read.
    from maljan.reporting.renderers.markdown import _Context, _escaped_spelling

    escaped = _escaped_spelling(host)
    assert escaped != host
    said = _Context(_user_agent_report("-")).run_values(f"seen {escaped} first")

    assert said == f"seen {escaped.replace('.', '[.]')} first"


# An underscore host after a path's slash or a run of dots, and one written in
# mixed case: each is the host it spells.
UNDERSCORE_HOSTS_IN_PATHS = (
    ("dir/_dmarc.victim.com", "_dmarc.victim.com"),
    ("a/_ldap._tcp.dc._msdcs.victimcorp.com", "_ldap._tcp.dc._msdcs.victimcorp.com"),
    ("./_a.victim.com", "_a.victim.com"),
    ("../_a.victim.com", "_a.victim.com"),
    (".._a.victim.com", "_a.victim.com"),
    ("_ldap._tcp.VictimCorp.Com", "_ldap._tcp.VictimCorp.Com"),
)


@pytest.mark.parametrize(("written", "host"), UNDERSCORE_HOSTS_IN_PATHS)
def test_an_underscore_host_after_a_slash_or_dots_or_in_mixed_case_is_defanged(
    written: str, host: str
) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    said = _defanged_text(f"it reads {written} first")

    assert host not in said
    assert host.replace(".", "[.]") in said


def test_a_decompiled_listing_s_caption_and_code_are_defanged() -> None:
    import json

    from maljan.reporting.figures import build_code_listings
    from maljan.reporting.models import NetworkDomain, NetworkIOCs

    code = (
        "void beacon(void)\n{\n"
        '  connect("https://relay.example.net/gate");\n'
        '  resolve("cdn_.evil.zip");\n'
        '  resolve("loader.sh");\n}\n'
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="loader.sh")]),
        technical_evidence={
            "reverser": [
                {
                    "agent_id": "reverser",
                    "tool_name": "decompile_function",
                    "args": {"name_or_address": "relay.example.net"},
                    "symbol": "relay.example.net",
                    "output": json.dumps({"name": "beacon", "code": code}),
                    "seq": 1,
                    "source": "mcp:programs",
                }
            ]
        },
    )
    (figure,) = build_code_listings(report)

    assert figure.caption == "Decompiled relay[.]example[.]net"
    for live in ("relay.example.net", "https://", "loader.sh"):
        assert live not in figure.content
    assert "hxxps://relay[.]example[.]net/gate" in figure.content
    assert "loader[.]sh" in figure.content
    assert "void beacon(void)" in figure.content


def test_a_listing_reads_a_value_recorded_only_as_an_ioc_row() -> None:
    import json

    from maljan.reporting.figures import build_code_listings
    from maljan.reporting.models import StaticAnalysis, StringIOC

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        static=StaticAnalysis(interesting_strings=[StringIOC(value="loader.sh", kind="domain")]),
        technical_evidence={
            "reverser": [
                {
                    "agent_id": "reverser",
                    "tool_name": "decompile_function",
                    "args": {"name_or_address": "0x401000"},
                    "output": json.dumps(
                        {"name": "f", "code": 'void f(void)\n{\n  r("loader.sh");\n}\n'}
                    ),
                    "seq": 1,
                    "source": "mcp:programs",
                }
            ]
        },
    )
    (figure,) = build_code_listings(report)

    assert "loader.sh" not in figure.content
    assert "loader[.]sh" in figure.content


def test_a_stored_report_s_figures_are_read_again_when_the_html_is_drawn() -> None:
    # Figures drawn before their text was defanged, stored with the report:
    # the HTML reads each again with the run's own values and every other one.
    from maljan.reporting.models import Figure, NetworkDomain, NetworkIOCs

    listing = (
        '<pre class="listing">connect(&quot;https://relay.example.net/gate&quot;);\n'
        "resolve(&quot;loader.sh&quot;); r(&quot;_ldap._tcp.victimcorp.com&quot;);</pre>"
    )
    tree = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
        '<text x="1" y="2" fill="#000">curl.exe http://drop.example.org/a (pid 4)</text>'
        '<text x="1" y="9">loader.sh (pid 5)</text></svg>'
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="loader.sh")]),
        figures=[
            Figure(
                id="fig-listing-0",
                caption="Decompiled https://relay.example.net/x",
                kind="code_listing",
                content=listing,
                legend="Seen at relay.example.net.",
            ),
            Figure(
                id="fig-process-tree", caption="Process tree", kind="process_tree", content=tree
            ),
            # An ELF section's name is the sample's, of any length.
            Figure(
                id="fig-entropy",
                caption="Section entropy",
                kind="entropy_chart",
                content=(
                    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
                    '<text x="1" y="2">www.evil.co</text><text x="1" y="5">http://ev.il.co/</text>'
                    '<text x="1" y="9">7.12</text></svg>'
                ),
            ),
        ],
    )
    html = HtmlRenderer().render(report)

    for live in (
        "www.evil.co",
        "ev.il.co",
        "relay.example.net",
        "drop.example.org",
        "https://",
        "http://drop",
        "loader.sh",
        "_ldap._tcp.victimcorp.com",
    ):
        assert live not in html, live
    for written in (
        "hxxps://relay[.]example[.]net/gate",
        "Decompiled hxxps://relay[.]example[.]net/x",
        "Seen at relay[.]example[.]net.",
        "hxxp://drop[.]example[.]org/a (pid 4)",
        "loader[.]sh (pid 5)",
        ">www[.]evil[.]co<",
        ">hxxp://ev[.]il[.]co/<",
        ">7.12<",
        "_ldap[.]_tcp[.]victimcorp[.]com",
        'xmlns="http://www.w3.org/2000/svg"',
    ):
        assert written in html, written


# Identifiers the reader of every host defangs, the safe way: a camelCase
# label ("toString") under a real TLD reads as a host once read in lower
# case. Telling it from a host would read "victimCorp" as an identifier too,
# and "_ldap._tcp.victimCorp.com" would print live again, so they stay defanged.
KNOWN_DEFANGED_IDENTIFIERS = ("my_var.toString.call", "obj._impl.api.dev")


@pytest.mark.parametrize("identifier", KNOWN_DEFANGED_IDENTIFIERS)
def test_a_camel_case_identifier_is_defanged_rather_than_a_host_printed_live(
    identifier: str,
) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert _defanged_text(identifier) != identifier
    assert _defanged_text("_ldap._tcp.victimCorp.com") == "_ldap[.]_tcp[.]victimCorp[.]com"


def test_a_figure_label_the_sample_named_is_defanged_when_drawn() -> None:
    from maljan.reporting.figures import build_attack_matrix, build_entropy_chart
    from maljan.reporting.models import PESection, StaticAnalysis, TTPMapping

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        static=StaticAnalysis(
            sections=[
                PESection(name="www.evil.co", virtual_address="0x1000", entropy=7.5),
                PESection(name=".text", virtual_address="0x2000", entropy=6.1),
            ]
        ),
        ttp_mappings=[
            TTPMapping(technique_id="evil.example.net", technique_name="x", tactic="TA0011")
        ],
    )
    entropy = build_entropy_chart(report)
    matrix = build_attack_matrix(report)

    assert entropy is not None and matrix is not None
    assert "www.evil.co" not in entropy.content and ">www[.]evil[.]co<" in entropy.content
    assert ">.text<" in entropy.content
    assert "evil.example.net" not in matrix.content
