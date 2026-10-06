"""Every network value the report prints is defanged, in the strings table and in findings.

The report defangs a network value wherever it prints one for reading. Two
places printed them live: the Value column of "Strings of note", which
printed a string extracted from the file's bytes as it was, and the
platform's findings in section 13, whose messages quote the claim they are
about, network values and all. Both print defanged now, as do the export
decisions and the findings on the verdict, which print messages the same
way, a file or host indicator that holds a network value, a tool failure's
error and the line naming the values a draft rule was made from. A draft
rule's body is the rule to deploy and is printed as it compiles. The HTML and
PDF renderings are made from this text.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

URL = "https://relay.example.net/live/"
HOST = "relay.example.net"
ADDRESS = "203.0.113.9"
LIVE = ("https://", "http://", HOST, ADDRESS)


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        **over,
    )


def _live_in(text: str) -> list[str]:
    return [value for value in LIVE if value in text]


def test_the_strings_of_note_print_their_network_values_defanged() -> None:
    report = _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(value=URL, kind="url", notes=f"decoded next to {HOST}"),
                StringIOC(value=HOST, kind="domain"),
                StringIOC(value=ADDRESS, kind="ip"),
                StringIOC(value="Software\\Microsoft\\Windows", kind="registry"),
            ]
        )
    )
    markdown = MarkdownRenderer().render(report)
    table = markdown.split("Strings of note", 1)[1].split("\n\n", 3)[2]

    assert "relay[.]example[.]net" in table
    assert "hxxps://" in table
    assert _live_in(table) == []
    # A value that names no network value is printed as it is.
    assert "Software\\\\Microsoft\\\\Windows" in table or "Software\\Microsoft\\Windows" in table


def _with_findings(*rows: dict[str, str]) -> str:
    report = _report(run_summary={"validation": {"retries": 1, "unresolved": list(rows)}})
    return MarkdownRenderer().render(report)


def test_a_finding_quoting_a_claim_prints_its_network_values_defanged() -> None:
    markdown = _with_findings(
        {
            "agent": "dynamic",
            "code": "attck.absence_claim",
            "message": (
                f"CLAIM 'The sample never reached `{URL}` or {ADDRESS} in this run.' reads as "
                "saying the behaviour is absent, and carries TECHNIQUE T1071.001."
            ),
            "subject": "T1071.001",
        },
        {
            "agent": "judge",
            "code": "stix.unpublishable_endpoint",
            "message": f"the indicator for {HOST} is not exported: it was not published.",
        },
    )
    validation = markdown.split("**Validation:**", 1)[1]

    assert "hxxps://relay[.]example[.]net/live/" in validation
    assert "203[.]0[.]113[.]9" in validation
    assert _live_in(validation) == []


def test_a_finding_on_the_verdict_prints_its_network_values_defanged() -> None:
    markdown = _with_findings(
        {
            "agent": "judge",
            "code": "verdict.unsupported",
            "message": f"the verdict names {URL} as the sample's server.",
        }
    )

    assert "hxxps://relay[.]example[.]net/live/" in markdown
    assert _live_in(markdown) == []


def test_a_host_indicator_holding_a_network_value_prints_it_defanged() -> None:
    report = _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(value=f"//{HOST}/live/ C", kind="path"),
                StringIOC(value="C:\\ProgramData\\example\\update_data.dat", kind="path"),
            ]
        )
    )
    section = MarkdownRenderer().render(report).split("## 9.", 1)[1].split("\n## ", 1)[0]

    assert "//relay[.]example[.]net/live/ C" in section
    assert "update_data.dat" in section
    assert _live_in(section) == []


def test_a_draft_rule_s_source_line_is_defanged_and_its_body_compiles_as_written() -> None:
    from maljan.reporting.models import DetectionRule

    body = f'rule Example {{ strings: $s1 = "{HOST}" condition: $s1 }}'
    report = _report(
        detection_signatures=[
            DetectionRule(
                kind="yara", name="Example", body=body, source_evidence=[f"string:url:{URL}"]
            )
        ]
    )
    markdown = MarkdownRenderer().render(report)
    (source,) = [line for line in markdown.splitlines() if "auto-generated from" in line]

    assert "string:url:hxxps://relay[.]example[.]net/live/" in source
    assert _live_in(source) == []
    # The rule is printed as it compiles: a defanged string would match nothing.
    assert body in markdown


def test_a_tool_failure_prints_a_network_value_in_its_error_defanged() -> None:
    report = _report(
        run_summary={
            "evidence": {
                "entries": 1,
                "failures": [{"tool": "floss", "error": f"see {URL} for the error", "count": 1}],
            }
        }
    )
    markdown = MarkdownRenderer().render(report)

    assert "see hxxps://relay[.]example[.]net/live/ for the error" in markdown
    assert _live_in(markdown) == []


def test_the_indicator_context_cells_print_their_urls_defanged() -> None:
    report = _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(value=f"//{HOST}/a C", kind="path", notes=f"decoded next to {URL}"),
                StringIOC(value=URL, kind="url"),
            ]
        )
    )
    section = MarkdownRenderer().render(report).split("## 9.", 1)[1].split("\n## ", 1)[0]

    assert "decoded next to hxxps://relay[.]example[.]net/live/" in section
    assert _live_in(section) == []


def test_a_host_in_capitals_and_an_onion_name_print_defanged() -> None:
    report = _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(value="RELAY.EXAMPLE.NET", kind="domain"),
                StringIOC(value="x.onion", kind="domain"),
                StringIOC(value="KERNEL32.DLL", kind="other"),
            ]
        )
    )
    table = MarkdownRenderer().render(report).split("Strings of note", 1)[1].split("\n\n", 3)[2]

    assert "RELAY[.]EXAMPLE[.]NET" in table
    assert "x[.]onion" in table
    assert "`KERNEL32.DLL`" in table


def test_a_draft_rule_s_compile_error_prints_defanged() -> None:
    from maljan.reporting.models import DetectionRule

    report = _report(
        detection_signatures=[
            DetectionRule(
                kind="yara",
                name="Example",
                body="rule Example { condition: true }",
                compile_error=f'syntax error near "{URL}"',
            )
        ]
    )
    (line,) = [
        line for line in MarkdownRenderer().render(report).splitlines() if "compile error" in line
    ]

    assert "hxxps://relay[.]example[.]net/live/" in line
    assert _live_in(line) == []


# What free prose prints as written: words that look dotted and name no host.
NOT_NETWORK = (
    "It is an ASP.NET page handler.",
    "It targets .NET and calls System.IO.File.",
    "The crate ships src/main.rs and lib.rs.",
    "FileVersion 10.0.0.1 and ProductVersion 2.1.0.0 are in its resources.",
    "The build is v1.2.3.4 of the loader.",
    "It reports version 10.0.0.1 in its banner.",
    "It drops update_data.dat and setup.exe beside kernel32.dll.",
)
# What free prose prints defanged: hosts under a real top-level domain,
# addresses that are no version, URLs and mailboxes.
NETWORK = (
    ("It beacons to relay.example.net daily.", "relay[.]example[.]net"),
    ("It resolves dl.delivery.mp.microsoft.com first.", "dl[.]delivery[.]mp[.]microsoft[.]com"),
    ("A fallback host is x.icu.", "x[.]icu"),
    ("Another is a.ru.", "a[.]ru"),
    ("It connects to 203.0.113.9 on port 443.", "203[.]0[.]113[.]9"),
    ("It posts to https://relay.example.net/a.", "hxxps://relay[.]example[.]net/a"),
    ("Mail goes to op@mail.example.org.", "op[@]mail[.]example[.]org"),
    ("It names EVIL.COM in capitals.", "EVIL[.]COM"),
)


@pytest.mark.parametrize("sentence", NOT_NETWORK)
def test_prose_that_names_no_network_value_prints_as_written(sentence: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert _defanged_text(sentence) == sentence


@pytest.mark.parametrize(("sentence", "defanged"), NETWORK)
def test_prose_that_names_a_network_value_prints_it_defanged(sentence: str, defanged: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert defanged in _defanged_text(sentence)


def test_the_run_s_own_indicator_is_defanged_even_where_it_reads_as_a_file_name() -> None:
    from maljan.reporting.models import (
        NetworkDomain,
        NetworkIOCs,
        TechnicalAnalysis,
        TechnicalSubsection,
    )

    report = _report(
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="lib.rs", source="sandbox")]),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="Command and control", body="It beacons to lib.rs every hour."
            )
        ),
    )
    markdown = MarkdownRenderer().render(report)

    assert "It beacons to lib[.]rs every hour." in markdown


def test_a_reference_link_stays_a_link_unless_it_holds_the_run_s_indicator() -> None:
    from maljan.reporting.renderers.markdown import _Context

    report = _report(network=None)
    from maljan.reporting.models import NetworkIOCs, NetworkIP

    report.network = NetworkIOCs(ips=[NetworkIP(address="203.0.113.9", source="sandbox")])
    ctx = _Context(report)
    file_link = "https://www.virustotal.com/gui/file/" + "a" * 64
    ip_link = "https://www.virustotal.com/gui/ip-address/203.0.113.9"

    assert ctx.plain(f"report url {file_link}") == f"report url {file_link}"
    kept = ctx.plain(f"report url {ip_link}")
    assert "https://" not in kept and "203.0.113.9" not in kept


def test_a_digit_before_a_top_level_domain_is_no_host() -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert _defanged_text('noise "?3e)}3.cz in a string') == 'noise "?3e)}3.cz in a string'


@pytest.mark.parametrize(
    "url",
    [
        "https://www.virustotal.com/gui/url/http://evil.com/e",
        "https://attack.mitre.org/techniques/T1055/?r=http://evil.com",
        "https://bazaar.abuse.ch/../\\@evil.com",
        "https://www.virustotal.com/gui/search/evil.com",
    ],
)
def test_a_reference_host_url_off_its_lookup_shape_is_defanged(url: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    written = _defanged_text(f"see {url} here")

    assert "evil.com" not in written
    assert "https://" not in written


@pytest.mark.parametrize(
    "url",
    [
        "https://www.virustotal.com/gui/file/" + "a" * 64,
        "https://www.virustotal.com/gui/url/" + "b" * 64,
        "https://www.virustotal.com/gui/ip-address/198.51.100.20",
        "https://www.virustotal.com/gui/domain/relay.example.net",
        "https://bazaar.abuse.ch/sample/" + "c" * 64 + "/",
        "https://attack.mitre.org/techniques/T1055/012/",
        "https://attack.mitre.org/tactics/TA0011/",
        "https://attack.mitre.org/software/S0154/",
        "https://attack.mitre.org/matrices/enterprise/",
    ],
)
def test_a_reference_lookup_stays_a_link(url: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert _defanged_text(f"see {url} here") == f"see {url} here"


def test_a_package_name_is_no_host() -> None:
    from maljan.pipeline.validation import network_values_in

    for name in (
        "com.facebook.react.bridge.app",
        "com.example.myapp.services.io",
        "net.sf.json.util.info",
        "com.android.okhttp.internal.net",
        "com.google.firebase.messaging.cloud",
        "org.apache.commons.io.monster",
        "android.app.admin.device.policy",
        "kotlin.collections.builders.list.app",
    ):
        assert network_values_in(f"It loads {name} at start.") == [], name
    assert network_values_in("It resolves dl.delivery.mp.microsoft.com.") == [
        ("domain", "dl.delivery.mp.microsoft.com")
    ]


# ".sh" and ".ps" are not in the vendored TLD list, so no reader reads them as hosts.
@pytest.mark.parametrize("host", ["evil.pl", "panel.ml"])
def test_a_common_country_code_host_is_defanged_in_prose(host: str) -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    assert host not in _defanged_text(f"see {host} now")


def test_a_kept_link_is_put_back_whatever_the_text_holds() -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    url = "https://www.virustotal.com/gui/file/" + "a" * 64
    text = f"odd \x000\x00 and  0  beside {url}"

    assert _defanged_text(text) == text


def test_a_reference_lookup_before_a_comma_stays_a_link() -> None:
    from maljan.reporting.renderers.markdown import _defanged_text

    text = "report_url=https://www.virustotal.com/gui/ip-address/198.51.100.20, coverage=91"
    assert _defanged_text(text) == text
