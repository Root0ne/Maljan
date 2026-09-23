"""The IOC table and the feed publish what the STIX export publishes.

A run exported two C2 names the judge read out of the decoded strings, while
the report's IOC section and ``/reports/{id}/iocs`` listed four hashes; another
exported an address the table called "seen only in the file's strings". The
export carries the judge's indicators beside the rows it mints from the report,
and the two other surfaces never read them. Both now read the export's values:
a value only the judge's objects carry is a published row whose source is
``judge``, and a value the table already publishes keeps its own row.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import _with_what_the_export_publishes
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    exported_indicator_values,
    indicator_publish_reason,
)

C2 = "gate9.example.org"
ADDRESS = "185.99.133.7"
SHA256 = "a" * 64
OTHER_SHA256 = "b" * 64


def _indicator(pattern: str) -> dict[str, Any]:
    return {"type": "indicator", "id": "indicator--x", "pattern": pattern}


def _bundle(*patterns: str) -> dict[str, Any]:
    return {"type": "bundle", "objects": [_indicator(p) for p in patterns]}


def _report(bundle: dict[str, Any], **over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        stix_bundle_extended=bundle,
        **over,
    )


class TestTheExportsValues:
    def test_each_single_comparison_is_read(self) -> None:
        values = exported_indicator_values(
            _bundle(
                f"[domain-name:value = '{C2}']",
                f"[file:hashes.'SHA-256' = '{OTHER_SHA256}']",
                "[file:name = '/tmp/example.bin']",
            )
        )

        assert [(v.kind, v.value, v.algorithm) for v in values] == [
            ("domain", C2, ""),
            ("hash", OTHER_SHA256, "SHA-256"),
            ("path", "/tmp/example.bin", ""),
        ]

    def test_a_compound_pattern_is_left_to_the_bundle(self) -> None:
        pattern = f"[file:hashes.'SHA-256' = '{SHA256}'] AND [file:name = 'x.exe']"

        assert exported_indicator_values(_bundle(pattern)) == []

    def test_no_bundle_is_no_values(self) -> None:
        assert exported_indicator_values(None) == []
        assert exported_indicator_values({}) == []


class TestTheTable:
    def test_a_value_only_the_judge_carries_is_a_published_judge_row(self) -> None:
        rows = build_consolidated_iocs(_report(_bundle(f"[domain-name:value = '{C2}']")))

        (row,) = [r for r in rows if r.value == C2]
        assert (row.type, row.source, row.published, row.is_network) == (
            "Domain",
            "judge",
            "yes",
            True,
        )

    def test_a_refused_string_row_of_the_same_value_is_stood_in_for(self) -> None:
        report = _report(
            _bundle(f"[ipv4-addr:value = '{ADDRESS}']"),
            network=NetworkIOCs(ips=[NetworkIP(address=ADDRESS, source="strings")]),
        )
        before = build_consolidated_iocs(report.model_copy(update={"stix_bundle_extended": {}}))
        assert [r.published for r in before if r.value == ADDRESS] == [
            "no: seen only in the file's strings"
        ]

        rows = build_consolidated_iocs(report)

        assert [(r.source, r.published) for r in rows if r.value == ADDRESS] == [("judge", "yes")]

    def test_a_row_the_table_publishes_keeps_its_own_source(self) -> None:
        report = _report(
            _bundle(f"[ipv4-addr:value = '{ADDRESS}']"),
            network=NetworkIOCs(ips=[NetworkIP(address=ADDRESS, source="sandbox")]),
        )

        rows = build_consolidated_iocs(report)

        assert [(r.source, r.published) for r in rows if r.value == ADDRESS] == [("sandbox", "yes")]

    def test_the_sample_s_own_hash_is_not_repeated(self) -> None:
        rows = build_consolidated_iocs(_report(_bundle(f"[file:hashes.'SHA-256' = '{SHA256}']")))

        assert [r.source for r in rows if r.value == SHA256] == ["identity"]

    def test_a_host_value_is_placed_with_the_host_rows(self) -> None:
        report = _report(
            _bundle(f"[domain-name:value = '{C2}']", "[mutex:name = 'ExampleMarker']"),
        )

        rows = build_consolidated_iocs(report)

        kinds = [r.kind for r in rows]
        assert kinds.index("mutex") < kinds.index("domain")


class TestTheFeed:
    def _feed(self, bundle: dict[str, Any], rows: list[dict[str, Any]], kind: str | None = None):
        out = list(rows)
        _with_what_the_export_publishes(out, bundle, kind)
        return out

    def test_a_value_only_the_judge_carries_is_served(self) -> None:
        out = self._feed(_bundle(f"[domain-name:value = '{C2}']"), [])

        assert out == [{"kind": "domain", "value": C2, "source": "judge", "published": True}]

    def test_a_withheld_row_of_the_same_value_is_stood_in_for(self) -> None:
        withheld = {"kind": "ip", "value": ADDRESS, "source": "strings", "published": False}

        out = self._feed(_bundle(f"[ipv4-addr:value = '{ADDRESS}']"), [withheld])

        assert out == [{"kind": "ip", "value": ADDRESS, "source": "judge", "published": True}]

    def test_the_sample_s_own_hash_keeps_its_identity_row(self) -> None:
        identity = {"kind": "hash", "value": f"sha256:{SHA256}", "source": "identity"}

        out = self._feed(_bundle(f"[file:hashes.'SHA-256' = '{SHA256}']"), [identity])

        assert out == [identity]

    def test_the_kind_filter_holds(self) -> None:
        out = self._feed(_bundle(f"[domain-name:value = '{C2}']"), [], kind="ip")

        assert out == []


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("domain", C2),
        ("ip", ADDRESS),
        ("url", f"https://{C2}/path/"),
        ("path", "C:\\Users\\Public\\example.dat"),
        ("mutex", "ExampleMarker"),
        ("registry", "HKCU\\Software\\ExampleVendor"),
    ],
)
def test_the_one_rule_publishes_what_the_judge_asserted(kind: str, value: str) -> None:
    """The rule the table's other rows are asked, asked with the judge as the source,
    answers as the export did: the judge asserting a value is a source that is not
    the string sweep."""
    assert indicator_publish_reason(kind, value, "judge") is not None
