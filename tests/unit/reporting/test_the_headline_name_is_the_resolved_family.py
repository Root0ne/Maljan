"""The headline malware name is the grounded family of a non-benign run (RC-20)."""

from __future__ import annotations

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import FamilyAttribution, FileHashes, MalwareReport, SampleIdentity


def _builder() -> MalwareReportBuilder:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="x.exe",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output=None,
        run_summary=None,
        discussion_history=None,
        final_decision="Malware",
    )


def _name(
    family: str | None, category: str | None, *, verdict: str = "Malware", grounded: bool = True
) -> str | None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict=verdict,  # type: ignore[arg-type]
        malware_category=category,
        attribution=FamilyAttribution(family=family, family_grounded=grounded),
    )
    return _builder()._build_front_matter(report).malware_name


@pytest.mark.parametrize(
    ("family", "category", "verdict", "grounded", "expected"),
    [
        ("njRAT", "trojan", "Malware", True, "njRAT"),
        ("  AsyncRAT ", "trojan", "Malware", True, "AsyncRAT"),
        ("Generic", "benign", "Benign", True, "Benign"),
        ("Emotet", "trojan", "Malware", False, "Trojan"),
        ("generic", "trojan", "Malware", True, "Trojan"),
        ("Unknown", "ransomware", "Malware", True, "Ransomware"),
        ("Unknown family", "ransomware", "Malware", True, "Ransomware"),
        ("-", "ransomware", "Malware", True, "Ransomware"),
        ("Emotet", "benign", "Benign", True, "Benign"),
        (None, "ransomware", "Malware", True, "Ransomware"),
    ],
)
def test_the_headline_name(
    family: str | None, category: str, verdict: str, grounded: bool, expected: str
) -> None:
    assert _name(family, category, verdict=verdict, grounded=grounded) == expected
