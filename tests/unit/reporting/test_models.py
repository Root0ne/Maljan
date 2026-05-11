"""Schema regression tests for MalwareReport and its sub-models."""

from __future__ import annotations

import pytest

from maljan.reporting.models import (
    DefensiveRecommendation,
    FileHashes,
    MalwareReport,
    ProcessNode,
    SampleIdentity,
    SeverityAssessment,
)


def _minimal_report(**overrides: object) -> MalwareReport:
    """Smallest valid MalwareReport — used by every test below."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        **overrides,  # type: ignore[arg-type]
    )


class TestMinimalConstruction:
    def test_defaults(self) -> None:
        r = _minimal_report()
        assert r.schema_version == "1.0"
        assert r.verdict == "Suspicious"
        assert r.overall_confidence == 0.0
        assert r.severity.rating == "Informational"
        assert r.identity.hashes.sha256 == "a" * 64
        assert r.static is None and r.dynamic is None and r.network is None
        assert r.persistence == []

    def test_round_trip(self) -> None:
        r = _minimal_report(verdict="Malware", overall_confidence=0.92)
        dumped = r.model_dump(mode="json")
        r2 = MalwareReport.model_validate(dumped)
        assert r2.verdict == "Malware"
        assert r2.overall_confidence == 0.92


class TestRecursiveProcessNode:
    def test_children_round_trip(self) -> None:
        tree = ProcessNode(
            pid=100,
            name="parent.exe",
            children=[
                ProcessNode(
                    pid=200,
                    ppid=100,
                    name="child.exe",
                    children=[ProcessNode(pid=300, ppid=200, name="grandchild.exe")],
                )
            ],
        )
        dumped = tree.model_dump()
        rebuilt = ProcessNode.model_validate(dumped)
        assert rebuilt.children[0].children[0].name == "grandchild.exe"


class TestSeverity:
    def test_clamping(self) -> None:
        with pytest.raises(ValueError):
            SeverityAssessment(overall_score=15.0)  # type: ignore[call-arg]
        with pytest.raises(ValueError):
            SeverityAssessment(overall_score=-1.0)  # type: ignore[call-arg]


class TestDefensiveRecommendation:
    def test_priority_literal(self) -> None:
        rec = DefensiveRecommendation(
            category="firewall",
            action="Block 1.2.3.4/32 outbound on perimeter",
            rationale="C2 IP",
            priority="P0",
        )
        assert rec.priority == "P0"

    def test_invalid_priority(self) -> None:
        with pytest.raises(ValueError):
            DefensiveRecommendation(
                category="firewall",
                action="block",
                rationale="why",
                priority="urgent",  # type: ignore[arg-type]
            )


class TestForbidExtra:
    def test_subblock_forbids_extra(self) -> None:
        with pytest.raises(ValueError):
            FileHashes(sha256="a" * 64, totally_unknown_field="x")  # type: ignore[call-arg]

    def test_top_level_permissive(self) -> None:
        """Top-level MalwareReport accepts extra fields (forward compat)."""
        report = MalwareReport.model_validate(
            {
                "identity": {"hashes": {"sha256": "a" * 64}},
                "extra_future_field": "ok",
            }
        )
        assert report.identity.hashes.sha256 == "a" * 64
