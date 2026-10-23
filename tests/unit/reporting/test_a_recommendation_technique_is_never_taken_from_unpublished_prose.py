"""A technique the prose names is moved into the column only if the report publishes it (RC-15)."""

from __future__ import annotations

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity, TTPMapping


def _rec(action: str) -> dict[str, str]:
    return {
        "category": "edr_hunting",
        "action": action,
        "rationale": "because",
        "priority": "P1",
    }


def test_only_a_published_id_is_moved() -> None:
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
    report.ttp_mappings = [TTPMapping(technique_id="T1105", technique_name="Ingress Tool Transfer")]
    MalwareReportBuilder.apply_narrative(
        report,
        {
            "defensive_recommendations": [
                _rec("Hunt T1059.003 then T1105"),
                _rec("Block T1547 autorun"),
            ]
        },
    )
    assert [r.technique_id for r in report.defensive_recommendations] == ["T1105", None]
