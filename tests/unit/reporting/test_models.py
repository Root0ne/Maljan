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


class TestReshapingSchemaPhase2:
    """Additive professional-report front-matter + technical spine (Phase 2).

    All new fields must default empty/None so legacy reports still validate,
    and a fully-populated report must round-trip.
    """

    def test_new_fields_default_empty(self) -> None:
        r = _minimal_report()
        assert r.front_matter is None
        assert r.version_history == []
        assert r.tlp == "CLEAR"
        assert r.technical_analysis is None
        assert r.c2_channels == []
        assert r.conclusion is None
        assert r.consolidated_iocs == []
        assert r.figures == []
        assert r.technical_evidence == {}

    def test_legacy_row_still_validates(self) -> None:
        # A pre-Phase-2 JSONB row (no new keys) must load unchanged.
        legacy = {
            "schema_version": "1.0",
            "verdict": "Malware",
            "identity": {"hashes": {"sha256": "b" * 64}},
        }
        r = MalwareReport.model_validate(legacy)
        assert r.verdict == "Malware"
        assert r.front_matter is None and r.technical_analysis is None

    def test_full_spine_round_trip(self) -> None:
        from maljan.reporting.models import (
            CliFlag,
            ConsolidatedIOC,
            EncryptionScheme,
            Figure,
            ReportFrontMatter,
            TechnicalAnalysis,
            VersionHistoryEntry,
        )

        r = _minimal_report(
            front_matter=ReportFrontMatter(
                malware_name="CACTUS", tlp="AMBER", report_number="MJN20260713001"
            ),
            version_history=[
                VersionHistoryEntry(
                    version="1.0", date="2026-07-13", authors="Maljan", description="Completed"
                )
            ],
            tlp="AMBER",
            technical_analysis=TechnicalAnalysis(
                cli_flags=[CliFlag(flag="-kd", description="kill + delete shadows")],
                shadow_copy_destruction=["vssadmin delete shadows /all /quiet"],
                encryption_scheme=EncryptionScheme(
                    cipher="AES-256", mode="CBC", extension=".cts6", per_file_key=True
                ),
            ),
            consolidated_iocs=[
                ConsolidatedIOC(type="Domain", value="888kafa[.]com", is_network=True)
            ],
            figures=[Figure(id="f1", caption="ATT&CK", kind="attack_matrix", content="<svg/>")],
        )
        r2 = MalwareReport.model_validate(r.model_dump(mode="json"))
        assert r2.front_matter is not None and r2.front_matter.malware_name == "CACTUS"
        assert r2.tlp == "AMBER"
        assert r2.technical_analysis is not None
        assert r2.technical_analysis.encryption_scheme.extension == ".cts6"
        assert r2.technical_analysis.cli_flags[0].flag == "-kd"
        assert r2.consolidated_iocs[0].value == "888kafa[.]com"
        assert r2.figures[0].kind == "attack_matrix"

    def test_subblocks_forbid_extra(self) -> None:
        from maljan.reporting.models import EncryptionScheme

        with pytest.raises(ValueError):
            EncryptionScheme(cipher="AES", bogus_field="x")  # type: ignore[call-arg]

    def test_figure_kind_literal_enforced(self) -> None:
        from maljan.reporting.models import Figure

        with pytest.raises(ValueError):
            Figure(id="f", caption="c", kind="screenshot", content="x")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Wave 9 — PersistenceKind Linux Literal extension
# ---------------------------------------------------------------------------


class TestPersistenceLinuxKinds:
    """The Pydantic Literal must accept the 5 Linux-flavoured kinds added
    in Wave 9 (2026-05-29). The TypeScript mirror lives at
    apps/web/src/types/malware-report.ts."""

    @pytest.mark.parametrize(
        "kind",
        [
            "systemd_service",
            "cron_job",
            "init_d",
            "rc_local",
            "ld_preload",
        ],
    )
    def test_linux_kind_accepted(self, kind: str) -> None:
        from maljan.reporting.models import PersistenceMechanism

        pm = PersistenceMechanism.model_validate(
            {"kind": kind, "target": "/etc/foo", "evidence_ref": "x"}
        )
        assert pm.kind == kind

    def test_windows_kinds_still_accepted(self) -> None:
        from maljan.reporting.models import PersistenceMechanism

        for kind in ("registry_run", "scheduled_task", "service", "other"):
            pm = PersistenceMechanism.model_validate(
                {"kind": kind, "target": "x", "evidence_ref": "y"}
            )
            assert pm.kind == kind

    def test_unknown_kind_rejected(self) -> None:
        from maljan.reporting.models import PersistenceMechanism

        with pytest.raises(ValueError):
            PersistenceMechanism.model_validate(
                {"kind": "totally_made_up", "target": "x", "evidence_ref": "y"}
            )
