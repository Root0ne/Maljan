"""A draft detection rule matches only on what the run publishes.

A signed benign tool got twenty Suricata alerts classed ``trojan-activity`` —
certificate-authority hosts, the vendor's home page, and a "C2 IP" rule for
``6.0.0.0`` — and a YARA branch of ``8 of them`` over common API names. The
drafts read every row the string sweep produced, published or not, and ran on
a Benign verdict. They are now drawn from the IOC table's published rows only,
and a Benign verdict, which publishes no malicious indicator, gets none; the
report says so. The version number that became an address is no longer read as
one.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.tools.strings import iter_string_iocs

OBSERVED = "gate9.example.org"
SWEPT = "crl.example-authority.org"
JUDGED = "relay4.example.net"


def _report(verdict: str = "Malware", **over: Any) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict=verdict,
        malware_category="loader",
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=OBSERVED, source="sandbox"),
                NetworkDomain(fqdn=SWEPT, source="strings"),
            ],
            ips=[NetworkIP(address="185.99.133.7", source="strings")],
            urls=[NetworkURL(url=f"https://{SWEPT}/root.crl", source="strings")],
        ),
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="mutex", value="ExampleMarkerSwept"),
            ],
        ),
        **over,
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _rule(report: MalwareReport, kind: str) -> Any:
    return next((r for r in build_detection_rules(report) if r.kind == kind), None)


class TestABenignVerdict:
    def test_gets_no_draft(self) -> None:
        assert build_detection_rules(_report(verdict="Benign")) == []

    def test_the_report_says_why(self) -> None:
        text = MarkdownRenderer().render(_report(verdict="Benign"))

        assert "the verdict is Benign, and a Benign run publishes no malicious indicator" in text


class TestAMalwareVerdict:
    def test_suricata_alerts_on_a_published_name_only(self) -> None:
        body = _rule(_report(), "suricata").body

        assert OBSERVED in body
        assert SWEPT not in body
        assert "185.99.133.7" not in body

    def test_a_value_the_export_publishes_from_the_judge_is_drafted(self) -> None:
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "x", "pattern": f"[domain-name:value = '{JUDGED}']"}
            ],
        }

        body = _rule(_report(stix_bundle_extended=bundle), "suricata").body

        assert JUDGED in body

    def test_no_published_network_value_means_no_suricata(self) -> None:
        report = _report()
        report.network = NetworkIOCs(domains=[NetworkDomain(fqdn=SWEPT, source="strings")])
        report.consolidated_iocs = build_consolidated_iocs(report)

        assert _rule(report, "suricata") is None

    def test_yara_strings_are_published_rows_only(self) -> None:
        body = _rule(_report(), "yara").body

        assert "ExampleMarkerSwept" not in body
        assert SWEPT not in body
        assert OBSERVED in body


class TestTheReader:
    @pytest.mark.parametrize(
        "text",
        [
            b'<assemblyIdentity name="Example.Controls" version="6.0.0.0" type="win32"/>',
            b"FileVersion 10.0.19041.1",
            b"build v8.0.0.1 ready",
            b"ver: 7.1.2.3",
        ],
    )
    def test_a_version_number_is_not_an_address(self, text: bytes) -> None:
        found = [row for row in iter_string_iocs(b"\x00" + text + b"\x00") if row["kind"] == "ip"]

        assert found == []

    def test_an_address_is_still_one(self) -> None:
        found = [
            row["value"]
            for row in iter_string_iocs(b"\x00connect to 185.99.133.7 now\x00")
            if row["kind"] == "ip"
        ]

        assert found == ["185.99.133.7"]
