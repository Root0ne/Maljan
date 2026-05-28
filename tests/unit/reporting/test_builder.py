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


def _build(
    *,
    sample_path: str | None = None,
    sandbox: dict[str, Any] | None = None,
    decision: str = "Malware",
    confidence: float = 0.85,
    category: str | None = None,
    isr_reports: dict[str, Any] | None = None,
) -> MalwareReport:
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
        cascade_summary=None,
        malware_category=category,
    ).build_deterministic()


class TestMinimalBuild:
    def test_empty_inputs_still_validate(self) -> None:
        report = _build()
        assert isinstance(report, MalwareReport)
        assert report.identity.hashes.sha256 == "a" * 64
        # Severity drops to "Low"/"Medium" range with no signal beyond confidence
        assert report.severity.rating in {"Low", "Medium", "High"}
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

    def test_persistence_detected(self, sandbox: dict[str, Any]) -> None:
        report = _build(sandbox=sandbox, category="ransomware")
        assert len(report.persistence) >= 1
        # at least one mechanism is the autorun registry entry
        kinds = {p.kind for p in report.persistence}
        assert "registry_run" in kinds

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

    def test_severity_high_or_critical(self, sandbox: dict[str, Any]) -> None:
        report = _build(sandbox=sandbox, category="ransomware", confidence=0.9)
        assert report.severity.rating in {"High", "Critical"}


class TestFallbackNarrative:
    def test_fallback_produces_summary(self) -> None:
        report = _build()
        report = MalwareReportBuilder.apply_fallback_narrative(report)
        assert len(report.executive_summary) > 100
        assert report.capabilities_narrative  # non-empty
        assert report.defensive_recommendations  # non-empty


class TestAttributionGrounding:
    """D11 — family attribution guardrail.

    The judge fallback path can hallucinate a family string when local
    LLMs time out (the 2026-05-23 zararli.apk run produced
    ``attribution.family = 'rat'`` with no Triage / signature / claim
    corroboration). The builder must mark that case as ungrounded so the
    UI can render it with a low-confidence badge.
    """

    def test_no_family_treated_as_grounded(self) -> None:
        report = _build(category=None)
        assert report.attribution.family is None
        # Legacy behaviour: missing family => no grounding claim to make.
        assert report.attribution.family_grounded is True

    def test_ungrounded_family_zeroes_confidence(self) -> None:
        report = _build(category="rat", confidence=0.6)
        assert report.attribution.family == "rat"
        assert report.attribution.family_grounded is False
        # Confidence must drop to 0.0 — the value was unsupported by any
        # deterministic layer.
        assert report.attribution.family_confidence == 0.0

    def test_family_grounded_via_triage_cti(self) -> None:
        sandbox = {"cti": {"family": ["Trojan/RAT"]}}
        report = _build(sandbox=sandbox, category="rat", confidence=0.6)
        assert report.attribution.family_grounded is True
        assert report.attribution.family_confidence == 0.6

    def test_family_grounded_via_signature_name(self) -> None:
        sandbox = {
            "signatures": [
                {"name": "LockBit ransomware payload", "severity": 9},
            ]
        }
        report = _build(sandbox=sandbox, category="lockbit", confidence=0.8)
        assert report.attribution.family_grounded is True
        assert report.attribution.family_confidence == 0.8

    def test_family_grounded_via_isr_claim(self) -> None:
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Sample matches Cobalt Strike beacon pattern",
                    evidence_ref="strings: cobaltstrike-beacon-config",
                    confidence=0.7,
                    technique_id="T1059",
                )
            ],
            dissent_items=[],
            revision_round=0,
        )
        report = _build(
            isr_reports={"static": isr},
            category="cobaltstrike",
            confidence=0.7,
        )
        assert report.attribution.family_grounded is True
