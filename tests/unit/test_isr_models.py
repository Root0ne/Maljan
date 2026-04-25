"""Unit tests for ISR (Intermediate Structural Representation) models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.schemas.isr_models import AgentISR, ClaimEvidence


class TestClaimEvidence:
    def test_valid_claim(self) -> None:
        claim = ClaimEvidence(
            claim="Injects code into svchost.exe",
            evidence_ref="API call: VirtualAllocEx @ 0x401234",
            confidence=0.9,
            technique_id="T1055.001",
        )
        assert claim.confidence == 0.9
        assert claim.technique_id == "T1055.001"

    def test_claim_without_technique(self) -> None:
        claim = ClaimEvidence(
            claim="Reads registry key",
            evidence_ref="RegOpenKeyEx HKLM\\Software\\...",
            confidence=0.75,
        )
        assert claim.technique_id is None

    def test_confidence_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ClaimEvidence(
                claim="x", evidence_ref="y", confidence=1.5
            )

    def test_invalid_technique_id_pattern(self) -> None:
        with pytest.raises(ValidationError):
            ClaimEvidence(
                claim="x",
                evidence_ref="y",
                confidence=0.5,
                technique_id="INVALID",
            )

    def test_valid_sub_technique(self) -> None:
        claim = ClaimEvidence(
            claim="DLL injection",
            evidence_ref="LoadLibrary @ 0x402000",
            confidence=0.8,
            technique_id="T1055.001",
        )
        assert claim.technique_id == "T1055.001"


class TestAgentISR:
    def _make_isr(self, agent_id: str = "static", round_num: int = 0) -> AgentISR:
        return AgentISR(
            agent_id=agent_id,
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Encrypts files with AES-256",
                    evidence_ref="string: 'AES' at .data+0x28",
                    confidence=0.85,
                    technique_id="T1486",
                )
            ],
            dissent_items=[],
            revision_round=round_num,
        )

    def test_mean_confidence_single_claim(self) -> None:
        isr = self._make_isr()
        assert isr.mean_confidence == pytest.approx(0.85)

    def test_mean_confidence_no_claims(self) -> None:
        isr = AgentISR(agent_id="dynamic", domain="dynamic", revision_round=0)
        assert isr.mean_confidence == 0.0

    def test_mean_confidence_multiple(self) -> None:
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(claim="C2", evidence_ref="PCAP frame 10", confidence=0.9),
                ClaimEvidence(claim="Exfil", evidence_ref="PCAP frame 20", confidence=0.7),
            ],
            revision_round=0,
        )
        assert isr.mean_confidence == pytest.approx(0.8)

    def test_to_text_summary_contains_agent_id(self) -> None:
        isr = self._make_isr("static")
        summary = isr.to_text_summary()
        assert "STATIC" in summary

    def test_to_text_summary_contains_claim(self) -> None:
        isr = self._make_isr()
        summary = isr.to_text_summary()
        assert "Encrypts files" in summary
        assert "T1486" in summary

    def test_to_text_summary_convergence_signal(self) -> None:
        isr = AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            claims=[],
            dissent_items=[],
            revision_round=1,  # round > 0 and empty dissent_items
        )
        summary = isr.to_text_summary()
        assert "CONVERGENCE SIGNAL" in summary

    def test_to_text_summary_dissent_listed(self) -> None:
        isr = AgentISR(
            agent_id="network",
            domain="network",
            claims=[],
            dissent_items=["Static analyst claims no network activity, but PCAP shows DNS exfil."],
            revision_round=1,
        )
        summary = isr.to_text_summary()
        assert "Disputes" in summary
        assert "DNS exfil" in summary

    def test_revision_round_default(self) -> None:
        isr = AgentISR(agent_id="static", domain="static")
        assert isr.revision_round == 0
