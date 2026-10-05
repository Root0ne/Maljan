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
