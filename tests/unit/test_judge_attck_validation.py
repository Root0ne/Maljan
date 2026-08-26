"""Unit tests for Phase 4.2: ATT&CK TTP validation integrated into JudgeAgent.

All tests use fixture-based ATTCKIndex/Validator to avoid network calls.
JudgeAgent LLM calls are NOT tested here (those are integration tests).
We test:
  - TTPClaimValidation / TTPValidationSummary model behavior
  - ATTCKValidator.validate_isr_reports() batch validation
  - JudgeAgent._build_validation_block() prompt grounding
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.agents.judge_agent import JudgeAgent
from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.attck_loader import ATTCKTechnique
from maljan.memory.attck_validator import ATTCKValidator
from maljan.memory.ttp_validation import TTPClaimValidation, TTPValidationSummary
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_technique(tid: str, name: str, desc: str, tactics: list[str]) -> ATTCKTechnique:
    return ATTCKTechnique(
        technique_id=tid,
        name=name,
        description=desc,
        tactic_phases=tactics,
        is_subtechnique="." in tid,
    )


FIXTURE_TECHNIQUES = [
    _make_technique(
        "T1055",
        "Process Injection",
        "Adversaries inject code into processes using WriteProcessMemory VirtualAllocEx "
        "CreateRemoteThread to evade defenses and elevate privileges.",
        ["defense-evasion", "privilege-escalation"],
    ),
    _make_technique(
        "T1071",
        "Application Layer Protocol",
        "Adversaries communicate via HTTP HTTPS DNS C2 beaconing to avoid detection.",
        ["command-and-control"],
    ),
    _make_technique(
        "T1547",
        "Boot or Logon Autostart Execution",
        "Adversaries configure registry run keys startup folder for persistence.",
        ["persistence"],
    ),
]


@pytest.fixture
def index() -> ATTCKIndex:
    return ATTCKIndex.from_techniques(FIXTURE_TECHNIQUES)


@pytest.fixture
def validator(index: ATTCKIndex) -> ATTCKValidator:
    return ATTCKValidator.from_index(index)


def _make_isr(
    agent_id: str,
    claims: list[ClaimEvidence],
) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain="static",
        claims=claims,
        dissent_items=[],
        revision_round=0,
    )


# ---------------------------------------------------------------------------
# TTPClaimValidation model
# ---------------------------------------------------------------------------


class TestTTPClaimValidation:
    def test_is_hallucinated_true_when_id_unknown(self) -> None:
        result = TTPClaimValidation(
            agent_id="static",
            technique_id="T9999",
            claim_text="some claim",
            evidence_ref="some evidence",
            is_valid_id=False,
            alignment_score=0.0,
            is_plausible=False,
        )
        assert result.is_hallucinated is True
        assert result.is_suspicious is False

    def test_is_suspicious_true_when_id_valid_but_low_alignment(self) -> None:
        result = TTPClaimValidation(
            agent_id="static",
            technique_id="T1055",
            claim_text="some claim",
            evidence_ref="unrelated evidence",
            is_valid_id=True,
            alignment_score=0.01,
            is_plausible=False,
        )
        assert result.is_hallucinated is False
        assert result.is_suspicious is True

    def test_neither_hallucinated_nor_suspicious_when_valid_plausible(self) -> None:
        result = TTPClaimValidation(
            agent_id="static",
            technique_id="T1055",
            claim_text="injection claim",
            evidence_ref="WriteProcessMemory",
            is_valid_id=True,
            alignment_score=0.4,
            is_plausible=True,
        )
        assert result.is_hallucinated is False
        assert result.is_suspicious is False


# ---------------------------------------------------------------------------
# TTPValidationSummary
# ---------------------------------------------------------------------------


class TestTTPValidationSummary:
    def _make_summary(
        self,
        valid: int,
        invalid: int,
        low_align: int,
    ) -> TTPValidationSummary:
        return TTPValidationSummary(
            total_claims=valid + invalid + low_align,
            valid_ids=valid,
            invalid_ids=invalid,
            low_alignment=low_align,
        )

    def test_hallucination_rate_zero_claims(self) -> None:
        s = TTPValidationSummary(total_claims=0, valid_ids=0, invalid_ids=0, low_alignment=0)
        assert s.hallucination_rate == 0.0

    def test_hallucination_rate_all_valid(self) -> None:
        s = self._make_summary(valid=3, invalid=0, low_align=0)
        assert s.hallucination_rate == pytest.approx(0.0)

    def test_hallucination_rate_partial(self) -> None:
        s = self._make_summary(valid=3, invalid=1, low_align=0)
        assert s.hallucination_rate == pytest.approx(0.25)

    def test_to_prompt_block_no_claims(self) -> None:
        s = TTPValidationSummary(total_claims=0, valid_ids=0, invalid_ids=0, low_alignment=0)
        block = s.to_prompt_block()
        assert "No structured TTP claims" in block

    def test_to_prompt_block_all_pass(self) -> None:
        s = TTPValidationSummary(
            total_claims=2,
            valid_ids=2,
            invalid_ids=0,
            low_alignment=0,
            results=[
                TTPClaimValidation(
                    agent_id="static",
                    technique_id="T1055",
                    claim_text="x",
                    evidence_ref="y",
                    is_valid_id=True,
                    alignment_score=0.5,
                    is_plausible=True,
                )
            ],
        )
        block = s.to_prompt_block()
        assert "All TTP claims passed validation" in block

    def test_to_prompt_block_shows_hallucinated(self) -> None:
        s = TTPValidationSummary(
            total_claims=1,
            valid_ids=0,
            invalid_ids=1,
            low_alignment=0,
            results=[
                TTPClaimValidation(
                    agent_id="static",
                    technique_id="T9999",
                    claim_text="x",
                    evidence_ref="y",
                    is_valid_id=False,
                    alignment_score=0.0,
                    is_plausible=False,
                    suggested_ids=["T1055"],
                )
            ],
        )
        block = s.to_prompt_block()
        assert "HALLUCINATED" in block
        assert "T9999" in block
        assert "T1055" in block

    def test_to_prompt_block_shows_suspicious(self) -> None:
        s = TTPValidationSummary(
            total_claims=1,
            valid_ids=1,
            invalid_ids=0,
            low_alignment=1,
            results=[
                TTPClaimValidation(
                    agent_id="network",
                    technique_id="T1071",
                    claim_text="x",
                    evidence_ref="registry key modification",
                    is_valid_id=True,
                    alignment_score=0.01,
                    is_plausible=False,
                )
            ],
        )
        block = s.to_prompt_block()
        assert "SUSPICIOUS" in block
        assert "T1071" in block


# ---------------------------------------------------------------------------
# ATTCKValidator.validate_isr_reports()
# ---------------------------------------------------------------------------


class TestValidateISRReports:
    def test_empty_isr_reports(self, validator: ATTCKValidator) -> None:
        summary = validator.validate_isr_reports({})
        assert summary.total_claims == 0
        assert summary.hallucination_rate == 0.0

    def test_no_technique_ids_in_claims(self, validator: ATTCKValidator) -> None:
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="something", evidence_ref="ref", confidence=0.8, technique_id=None
                )
            ],
        )
        summary = validator.validate_isr_reports({"static": isr})
        assert summary.total_claims == 0

    def test_valid_technique_id_counted(self, validator: ATTCKValidator) -> None:
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="process injection via WriteProcessMemory",
                    evidence_ref="API: WriteProcessMemory PID=1234",
                    confidence=0.9,
                    technique_id="T1055",
                )
            ],
        )
        summary = validator.validate_isr_reports({"static": isr})
        assert summary.total_claims == 1
        assert summary.valid_ids == 1
        assert summary.invalid_ids == 0

    def test_hallucinated_technique_id_flagged(self, validator: ATTCKValidator) -> None:
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="some claim",
                    evidence_ref="some ref",
                    confidence=0.5,
                    technique_id="T9999",
                )
            ],
        )
        summary = validator.validate_isr_reports({"static": isr})
        assert summary.invalid_ids == 1
        assert summary.results[0].is_hallucinated is True

    def test_suggestions_provided_for_invalid_id(self, validator: ATTCKValidator) -> None:
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="process injection code",
                    evidence_ref="WriteProcessMemory VirtualAllocEx",
                    confidence=0.5,
                    technique_id="T9999",
                )
            ],
        )
        summary = validator.validate_isr_reports({"static": isr})
        assert len(summary.results[0].suggested_ids) > 0

    def test_multiple_agents_multiple_claims(self, validator: ATTCKValidator) -> None:
        isr_static = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="injection",
                    evidence_ref="WriteProcessMemory",
                    confidence=0.9,
                    technique_id="T1055",
                ),
                ClaimEvidence(
                    claim="fake",
                    evidence_ref="nothing",
                    confidence=0.3,
                    technique_id="T9999",
                ),
            ],
        )
        isr_network = _make_isr(
            "network",
            [
                ClaimEvidence(
                    claim="C2 beaconing",
                    evidence_ref="HTTPS DNS C2 beacon",
                    confidence=0.8,
                    technique_id="T1071",
                ),
            ],
        )
        summary = validator.validate_isr_reports({"static": isr_static, "network": isr_network})
        assert summary.total_claims == 3
        assert summary.valid_ids == 2
        assert summary.invalid_ids == 1


# ---------------------------------------------------------------------------
# JudgeAgent._build_validation_block()
# ---------------------------------------------------------------------------


class TestJudgeBuildValidationBlock:
    @pytest.fixture
    def judge(self) -> JudgeAgent:
        return JudgeAgent(llm=MagicMock())

    def test_returns_empty_string_without_validator(self, judge: JudgeAgent) -> None:
        result = judge._build_validation_block(isr_reports={}, attck_validator=None)
        assert result == ""

    def test_returns_empty_string_without_isr(self, judge: JudgeAgent) -> None:
        mock_validator = MagicMock()
        result = judge._build_validation_block(isr_reports=None, attck_validator=mock_validator)
        assert result == ""

    def test_returns_empty_string_when_no_claims(
        self, judge: JudgeAgent, validator: ATTCKValidator
    ) -> None:
        isr = _make_isr("static", [])
        result = judge._build_validation_block(
            isr_reports={"static": isr}, attck_validator=validator
        )
        assert result == ""

    def test_returns_block_when_claims_present(
        self, judge: JudgeAgent, validator: ATTCKValidator
    ) -> None:
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="injection",
                    evidence_ref="WriteProcessMemory",
                    confidence=0.9,
                    technique_id="T1055",
                )
            ],
        )
        result = judge._build_validation_block(
            isr_reports={"static": isr}, attck_validator=validator
        )
        assert "ATT&CK TTP VALIDATION" in result

    def test_graceful_degradation_on_validator_error(self, judge: JudgeAgent) -> None:
        broken_validator = MagicMock()
        broken_validator.validate_isr_reports.side_effect = RuntimeError("db offline")
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="x",
                    evidence_ref="y",
                    confidence=0.5,
                    technique_id="T1055",
                )
            ],
        )
        # Must NOT raise — returns empty string silently
        result = judge._build_validation_block(
            isr_reports={"static": isr}, attck_validator=broken_validator
        )
        assert result == ""

    def test_skips_validator_without_method(self, judge: JudgeAgent) -> None:
        bad_validator = object()  # no validate_isr_reports
        isr = _make_isr(
            "static",
            [
                ClaimEvidence(
                    claim="x",
                    evidence_ref="y",
                    confidence=0.5,
                    technique_id="T1055",
                )
            ],
        )
        result = judge._build_validation_block(
            isr_reports={"static": isr}, attck_validator=bad_validator
        )
        assert result == ""
