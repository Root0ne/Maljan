"""Integration tests for the MalwareReportBuilder.

Each test feeds the builder with a different shape of sandbox/static data
and asserts on the deterministic projection: severity rating, capability
matrix size, IOC counts, attribution.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.schemas.judgement import FamilyVerdict, JudgeAssessment, SeverityVerdict
from tests.unit._ledger_helpers import ledger_from_sandbox


def _build(
    *,
    sample_path: str | None = None,
    sandbox: dict[str, Any] | None = None,
    decision: str = "Malware",
    confidence: float = 0.85,
    category: str | None = None,
    isr_reports: dict[str, Any] | None = None,
    ledger: list[Any] | None = None,
    assessment: Any | None = None,
) -> MalwareReport:
    # The report is built from the calls the run made, so a sandbox fixture
    # reaches it the way it does in production: through the sandbox tools a
    # dynamic analyst would have called on it.
    if ledger is None:
        ledger = ledger_from_sandbox(sandbox) if sandbox else []
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=sample_path,
        sandbox_report=sandbox or {},
        reports={},
        isr_reports=isr_reports or {},
        stix_output={"objects": []},
        run_summary={
            "negotiation": {
                "rounds_completed": 1,
                "termination_reason": "consensus",
                "final_confidence": confidence,
            }
        },
        discussion_history=[],
        final_decision=decision,
        overall_confidence=confidence,
        judge_assessment=assessment,
        malware_category=category,
        evidence_ledger=ledger,
    ).build_deterministic()


class TestMinimalBuild:
    def test_empty_inputs_still_validate(self) -> None:
        report = _build()
        assert isinstance(report, MalwareReport)
        assert report.identity.hashes.sha256 == "a" * 64
        # No judge assessment means no severity. It is not defaulted to a
        # rating the run never established.
        assert report.severity is None
        # References include VT + MalwareBazaar even with no TTPs
        assert any(r.source == "VirusTotal" for r in report.references)


class TestRansomwareFixture:
    @pytest.fixture
    def sandbox(self) -> dict[str, Any]:
        return {
            "target": {"file": {"sha256": "a" * 64, "name": "lockbit.exe"}},
            "behavior": {
                "processes": [
                    {
                        "name": "lockbit.exe",
                        "pid": 1234,
                        "ppid": 1,
                        "cmd": "lockbit.exe -encrypt",
                        "calls": [],
                    }
                ],
                "calls": [
                    {
                        "api": "RegSetValueExA",
                        "arguments": [
                            {
                                "FullName": (
                                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                                ),
                                "ValueName": "lockbit",
                                "Buffer": "C:\\Users\\Public\\lockbit.exe",
                            }
                        ],
                    }
                ],
                "apistats": {"lockbit.exe": {"CryptEncrypt": 42, "CreateRemoteThread": 1}},
            },
            "network": {
                "dns": [{"request": "evil-c2.duckdns.org", "answers": []}],
                "http": [],
                "tcp": [{"dst": "1.2.3.4", "dport": 443}],
                "udp": [],
            },
            "signatures": [
                {
                    "name": "InstallsAutoRun",
                    "description": "Installs registry auto-run",
                    "severity": 8,
                    "marks": ["HKLM\\...\\Run\\lockbit"],
                }
            ],
            "ttp_tags": ["T1486"],
        }

    def test_persistence_comes_from_the_analyst_that_saw_it(self, sandbox: dict[str, Any]) -> None:
        # An analyst that read the call and wrote it down as an artifact is
        # one of the two routes; the other is the registry tool below.
        from tests.unit._ledger_helpers import persistence_isr

        report = _build(
            sandbox=sandbox,
            category="ransomware",
            isr_reports={
                "dynamic": persistence_isr(
                    [
                        [
                            "registry_run",
                            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "C:\\Users\\Public\\lockbit.exe",
                        ]
                    ]
                )
            },
        )
        assert len(report.persistence) >= 1
        kinds = {p.kind for p in report.persistence}
        assert "registry_run" in kinds

    def test_the_registry_call_alone_is_enough_to_find_the_autorun(
        self, sandbox: dict[str, Any]
    ) -> None:
        # No analyst artifact this time: the Run key comes from the registry
        # call the sandbox recorded, read through ``sandbox_registry_ops``.
        report = _build(sandbox=sandbox, category="ransomware")
        assert [p.kind for p in report.persistence] == ["registry_run"]
        assert report.persistence[0].payload == "C:\\Users\\Public\\lockbit.exe"

    def test_persistence_is_empty_when_the_run_recorded_none(self) -> None:
        assert _build(sandbox={"behavior": {"processes": []}}).persistence == []

    def test_network_ioc_extracted(self, sandbox: dict[str, Any]) -> None:
        report = _build(sandbox=sandbox, category="ransomware")
        assert report.network is not None
        assert any("duckdns" in d.fqdn for d in report.network.domains)
        assert any(d.is_suspicious for d in report.network.domains)
        assert any(ip.address == "1.2.3.4" for ip in report.network.ips)

    def test_dynamic_signature_carried(self, sandbox: dict[str, Any]) -> None:
        report = _build(sandbox=sandbox, category="ransomware")
        assert report.dynamic is not None
        names = {s.name for s in report.dynamic.sandbox_signatures}
        assert "InstallsAutoRun" in names

    def test_severity_is_the_judges_rating_and_its_rationale(self, sandbox: dict[str, Any]) -> None:
        report = _build(
            sandbox=sandbox,
            category="ransomware",
            confidence=0.9,
            assessment=JudgeAssessment(
                severity=SeverityVerdict(rating="Critical", rationale="it encrypts every file")
            ),
        )
        assert report.severity is not None
        assert report.severity.rating == "Critical"
        assert report.severity.business_impact == "it encrypts every file"

    def test_severity_is_not_invented_when_the_judge_gave_none(
        self, sandbox: dict[str, Any]
    ) -> None:
        """The arithmetic this replaces read "0.9 confidence + persistence +
        suspicious domains" and printed 9.4/10 Critical over the judge's head."""
        assert _build(sandbox=sandbox, category="ransomware", confidence=0.9).severity is None


class TestAttributionGrounding:
    """Family attribution: the judge's answer, flagged rather than vetoed.

    The guardrail this replaces zeroed the confidence of any family no
    deterministic layer had already named. That meant the judge's own reading
    of a sample could never produce an attribution at all, and a family with a
    caveat became a family with 0.00 next to it, which reads as a bug.
    """

    def test_no_family_anywhere_leaves_it_unset(self) -> None:
        report = _build(category=None)
        assert report.attribution.family is None
        assert report.attribution.family_grounded is True

    def test_the_category_is_never_echoed_as_a_family(self) -> None:
        report = _build(category="rat", confidence=0.6)
        assert report.attribution.family is None
        assert report.malware_category == "rat"

    def test_the_judges_family_wins_and_carries_its_own_confidence(self) -> None:
        report = _build(
            sandbox={"cti": {"family": ["Trojan/RAT"]}},
            assessment=JudgeAssessment(
                family=FamilyVerdict(name="AsyncRAT", confidence=0.72, evidence_ids=["ev_0009"])
            ),
        )
        assert report.attribution.family == "AsyncRAT"
        assert report.attribution.family_confidence == 0.72
        assert report.attribution.family_grounded is True

    def test_a_family_with_no_evidence_ids_is_kept_and_flagged(self) -> None:
        report = _build(assessment=JudgeAssessment(family=FamilyVerdict(name="LockBit")))
        assert report.attribution.family == "LockBit"
        assert report.attribution.family_grounded is False

    def test_the_sandbox_names_the_family_when_the_judge_abstained(self) -> None:
        report = _build(sandbox={"cti": {"family": ["Trojan/RAT"]}}, confidence=0.6)
        assert report.attribution.family == "Trojan/RAT"
        assert report.attribution.family_grounded is True


class TestFallbackNarrative:
    def test_fallback_produces_summary(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)
        assert len(report.executive_summary) > 100
        assert report.capabilities_narrative  # non-empty
        assert report.defensive_recommendations  # non-empty
