"""No payload a model or a sample could write becomes a live link, and none recurses.

Payloads go through a report's prose and an indicator's context cell, and the
Markdown is rendered to HTML. Every one must come out with no live host in the
Markdown and no anchor or image in the HTML other than a reference service's
own lookup. A reference URL off its service's lookup shape, raw or encoded
(``%2e%2e``, ``..%2f``, a backslash, an ``@`` or a second ``//`` in the path),
is defanged. Text nested a hundred thousand brackets deep renders quickly, as
text, and raises nothing.
"""

from __future__ import annotations

import re
import time

import pytest

from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer, _defanged_text

HOST = "evil.example.com"
SHA = "a" * 64
PAYLOADS = (
    f"http://{HOST}/a",
    f"HTTPS://{HOST}/a",
    f"hxxp://{HOST}/a",
    f"ftp://{HOST}/a",
    f"<http://{HOST}/a>",
    f"[x](http://{HOST}/a)",
    f"[x](//{HOST}/a)",
    f"![i](//{HOST}/p.png)",
    f"![i](http://{HOST}/p.png)",
    f"[x](javascript:alert('{HOST}'))",
    f"[x](data:text/html,{HOST})",
    f"[x](%2F%2F{HOST}/a)",
    f"[x](\\\\{HOST}\\share)",
    f"[x]( //{HOST}/a )",
    f"[x](<//{HOST}/a>)",
    f"www.{HOST}",
    f"op@{HOST}",
    f"mailto:op@{HOST}",
    f"`{HOST}`",
    HOST.upper(),
    "Evil.Example.Com",
    f"https://www.virustotal.com/gui/url/http://{HOST}/e",
    f"https://www.virustotal.com/gui/file/%2e%2e/%2e%2e/{HOST}",
    f"https://www.virustotal.com/gui/domain/..%2f{HOST}",
    f"https://www.virustotal.com/gui/file/aa\\..\\{HOST}",
    f"https://www.virustotal.com/gui/file/aa@{HOST}",
    f"https://www.virustotal.com/gui/file//{HOST}",
    f"https://www.virustotal.com@{HOST}/gui/file/aa",
    f"https://www.virustotal.com:443/gui/file/aa?x={HOST}",
    f"https://attack.mitre.org/techniques/T1055/?r=http://{HOST}",
    f"https://attack.mitre.org/techniques/T1055/%2e%2e/{HOST}",
    f"https://bazaar.abuse.ch/../\\@{HOST}",
    f"https://bazaar.abuse.ch/sample/{'c' * 64}/%2f%2f{HOST}",
    f"see https://www.virustotal.com/gui/file/{SHA} and http://x.example.net/r?u=http://{HOST}",
)


def _report(text: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=text)
        ),
        static=StaticAnalysis(
            interesting_strings=[StringIOC(value="/a C", kind="path", notes=text)]
        ),
    )


def _foreign_hrefs(html: str) -> list[str]:
    hrefs = re.findall(r"<a\s[^>]*href=\"([^\"#][^\"]*)\"", html)
    return [h for h in hrefs if HOST in h.lower() or "%2f" in h.lower()]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_no_payload_is_live_in_the_markdown_or_linked_in_the_html(payload: str) -> None:
    report = _report(f"Before {payload} after.")
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report)

    assert HOST not in markdown.lower()
    assert _foreign_hrefs(html) == []
    assert "<img" not in html


@pytest.mark.parametrize("payload", PAYLOADS)
def test_no_payload_is_live_after_the_defanger(payload: str) -> None:
    assert HOST not in _defanged_text(payload).lower()


@pytest.mark.parametrize(
    "nested",
    [
        "[" * 100_000 + "x" + "]" * 100_000,
        "(" * 100_000 + "x" + ")" * 100_000,
        "![" * 50_000 + "x" + "](y)" * 50_000,
        "http://" * 20_000 + HOST,
    ],
)
def test_text_nested_deep_renders_quickly_as_text(nested: str) -> None:
    started = time.monotonic()
    markdown = MarkdownRenderer().render(_report(nested))
    html = HtmlRenderer().render(_report(nested))
    elapsed = time.monotonic() - started

    assert elapsed < 30
    assert "x" in markdown and "x" in html
    assert HOST not in markdown.lower()


def test_a_reverse_dns_host_in_the_evidence_is_read_and_defanged() -> None:
    hosts = [
        "com.evil-c2.ru",
        "net.update-cdn.xyz",
        "io.payload.top",
        "com.evil-c2.update.cdn.ru",
    ]
    report = _report(" and ".join(f"it resolves {h}" for h in hosts))
    report.network = NetworkIOCs(domains=[NetworkDomain(fqdn=h, source="sandbox") for h in hosts])
    markdown = MarkdownRenderer().render(report)
    prose = markdown.split("Command and control", 1)[1]

    for host in hosts:
        assert host not in prose, host


def test_a_package_name_with_no_network_evidence_is_no_host() -> None:
    from maljan.pipeline.validation import network_values_in, recommendation_indicator_violations

    assert network_values_in("It loads com.facebook.react.bridge.app.") == []
    payload = {
        "defensive_recommendations": [
            {
                "action": "Block com.evil-c2.update.cdn.ru and watch com.facebook.react.bridge.app",
                "rationale": "",
            }
        ]
    }

    def answers(kind: str, value: str) -> str:
        return "no: unattributed" if value == "com.evil-c2.update.cdn.ru" else ""

    (asked,) = recommendation_indicator_violations(payload, answers)
    assert "com.evil-c2.update.cdn.ru" in asked.message
    assert "com.facebook.react.bridge.app" not in asked.message
