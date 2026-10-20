"""A stored report's tool sections are joined once per reading, however many values (RR-8)."""

from __future__ import annotations

from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers import stix_renderer


def _report(text: str, rows: list[list[str]] | None = None) -> MalwareReport:
    section = EvidenceSection(
        key="floss",
        title="floss",
        source="tool:floss",
        evidence_ids=["ev_0001"],
        text=text,
        rows=rows or [],
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), sections=[section]
    )


def test_the_text_is_joined_once_for_many_values_in_one_reading() -> None:
    report = _report("c2 at host-0.example.net and host-1.example.net")
    with stix_renderer.one_reading(report):
        first = stix_renderer._tool_section_texts(report)
        for i in range(50):
            held = stix_renderer._section_sightings(report, f"host-{i % 2}.example.net")
            assert held == [("ev_0001", "floss")]
            assert stix_renderer._tool_section_texts(report) is first


def test_an_in_place_row_edit_between_calls_is_seen() -> None:
    report = _report("nothing", rows=[["first.example.net"]])
    assert stix_renderer._section_sightings(report, "second.example.net") == []
    report.sections[0].rows[0][0] = "second.example.net"
    assert stix_renderer._section_sightings(report, "second.example.net") == [("ev_0001", "floss")]


def test_a_text_edit_between_calls_is_seen() -> None:
    report = _report("first.example.net")
    assert stix_renderer._section_sightings(report, "second.example.net") == []
    report.sections[0].text = "second.example.net"
    assert stix_renderer._section_sightings(report, "second.example.net") == [("ev_0001", "floss")]
