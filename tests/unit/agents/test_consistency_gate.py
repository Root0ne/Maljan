"""Unit tests for the inline foundational-tier consistency gate (§4 Item 4, LAMD).

No live LLM. The pure grounding helper is tested directly; the gate method is
tested with the config flag stubbed on and off via monkeypatch.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst, _claim_grounded_in_evidence
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_EVIDENCE = (
    "The binary imports VirtualAllocEx and WriteProcessMemory and creates a "
    "remote thread in explorer.exe. It sets HKCU\\Software\\Microsoft\\Windows\\"
    "CurrentVersion\\Run\\Updater for persistence. Technique T1055 applies."
)


# ---------------------------------------------------------------------------
# Pure grounding helper
# ---------------------------------------------------------------------------


class TestClaimGroundedInEvidence:
    def test_technique_id_present_in_evidence_grounds(self) -> None:
        assert _claim_grounded_in_evidence(
            "Some opaque sentence with no shared vocabulary whatsoever",
            "synthetic",
            "T1055",
            _EVIDENCE,
        )

    def test_real_artifact_ref_token_present_grounds(self) -> None:
        # A structured claim carrying a real artifact reference is grounded when
        # that artifact appears in the evidence, even if the claim text doesn't.
        assert _claim_grounded_in_evidence(
            "Injects into a host process.",
            "API import: VirtualAllocEx",
            None,
            _EVIDENCE,
        )

    def test_claim_text_overlap_grounds(self) -> None:
        assert _claim_grounded_in_evidence(
            "Process injection via WriteProcessMemory into explorer.",
            "text-extracted from static report",
            None,
            _EVIDENCE,
        )

    def test_synthetic_ref_does_not_auto_ground(self) -> None:
        # Synthetic placeholder ref + no evidence overlap + no technique => drop.
        assert not _claim_grounded_in_evidence(
            "Exfiltrates cryptocurrency seed phrases to a pastebin dropsite.",
            "text-extracted from static report",
            None,
            _EVIDENCE,
        )

    def test_ungrounded_claim_returns_false(self) -> None:
        assert not _claim_grounded_in_evidence(
            "Steals browser cookies and uploads them to a Telegram channel.",
            "speculation",
            None,
            _EVIDENCE,
        )

    def test_only_filler_tokens_returns_false(self) -> None:
        assert not _claim_grounded_in_evidence(
            "This that these those with from",
            "",
            None,
            _EVIDENCE,
        )


# ---------------------------------------------------------------------------
# Gate method (config-flag driven)
# ---------------------------------------------------------------------------


class _StubAnalyst(BaseAnalyst):
    def analyze(self, data: str) -> str:
        return "unused"

    def revise(self, original_data, own_report, peer_reports, mediator_feedback) -> str:
        return "unused"


def _agent() -> _StubAnalyst:
    return _StubAnalyst(llm=MagicMock(), name="static_analyst")


def _set_gate(monkeypatch: pytest.MonkeyPatch, on: bool) -> None:
    settings = SimpleNamespace(preprocessing=SimpleNamespace(use_claim_consistency_gate=on))
    monkeypatch.setattr("maljan.agents.base_agent.get_settings", lambda: settings)


def _isr_with_two_claims() -> AgentISR:
    return AgentISR(
        agent_id="static_analyst",
        domain="static",
        claims=[
            ClaimEvidence(
                claim="Process injection via VirtualAllocEx and WriteProcessMemory.",
                evidence_ref="API import: VirtualAllocEx",
                confidence=0.8,
                technique_id="T1055",
            ),
            ClaimEvidence(
                claim="Exfiltrates cryptocurrency seed phrases to a pastebin dropsite.",
                evidence_ref="speculation",
                confidence=0.6,
                technique_id=None,
            ),
        ],
    )


class TestApplyConsistencyGate:
    def test_gate_off_keeps_all_claims(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, False)
        isr = _isr_with_two_claims()
        out = _agent()._apply_consistency_gate(isr, _EVIDENCE)
        assert len(out.claims) == 2

    def test_gate_on_drops_ungrounded_claim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, True)
        isr = _isr_with_two_claims()
        out = _agent()._apply_consistency_gate(isr, _EVIDENCE)
        assert len(out.claims) == 1
        assert out.claims[0].technique_id == "T1055"

    def test_gate_on_keeps_all_grounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, True)
        isr = AgentISR(
            agent_id="static_analyst",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Persistence via the CurrentVersion Run key Updater.",
                    evidence_ref="registry key: CurrentVersion Run Updater",
                    confidence=0.7,
                    technique_id=None,
                ),
            ],
        )
        out = _agent()._apply_consistency_gate(isr, _EVIDENCE)
        assert len(out.claims) == 1

    def test_gate_on_empty_claims_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, True)
        isr = AgentISR(agent_id="static_analyst", domain="static", claims=[])
        out = _agent()._apply_consistency_gate(isr, _EVIDENCE)
        assert out.claims == []

    def test_gate_on_empty_evidence_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, True)
        isr = _isr_with_two_claims()
        out = _agent()._apply_consistency_gate(isr, "")
        assert len(out.claims) == 2

    def test_gate_preserves_other_isr_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_gate(monkeypatch, True)
        isr = AgentISR(
            agent_id="static_analyst",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Injects via VirtualAllocEx.",
                    evidence_ref="API import: VirtualAllocEx",
                    confidence=0.8,
                    technique_id="T1055",
                ),
            ],
            dissent_items=["peer disputed nothing"],
            revision_round=2,
        )
        out = _agent()._apply_consistency_gate(isr, _EVIDENCE)
        assert out.revision_round == 2
        assert out.dissent_items == ["peer disputed nothing"]
        assert out.agent_id == "static_analyst"
