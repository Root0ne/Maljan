"""Tests for the JudgeAgent standalone class.

JudgeAgent is NOT a BaseAnalyst subclass — it has two distinct responsibilities:
  1. mediate()     — finds contradictions, returns (AgentArgument, is_consensus)
  2. give_verdict() — produces a STIX 2.1 Bundle

All tests use a mocked LLM to avoid real API calls.
"""

from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.judge_agent import CONSENSUS_THRESHOLD, JudgeAgent
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.state import AgentArgument


@pytest.fixture
def mock_llm() -> MagicMock:
    """Mocked LLM that supports with_structured_output and LangChain pipe chains."""
    return MagicMock()


@pytest.fixture
def sample_reports() -> dict[str, str]:
    return {
        "static": "Found CryptAcquireContext and CreateRemoteThread.",
        "dynamic": "Process injection into explorer.exe detected.",
        "network": "Periodic HTTPS beacon to 185.220.101.45:443.",
    }


@pytest.fixture
def sample_history() -> list[AgentArgument]:
    return []


class TestJudgeAgentInit:
    """JudgeAgent is a standalone class — no BaseAnalyst inheritance."""

    def test_is_not_base_analyst(self) -> None:
        from maljan.agents.base_agent import BaseAnalyst

        llm = MagicMock()
        judge = JudgeAgent(llm=llm)
        assert not isinstance(judge, BaseAnalyst)

    def test_stores_llm(self) -> None:
        llm = MagicMock()
        judge = JudgeAgent(llm=llm)
        assert judge.llm is llm

    def test_has_logger(self) -> None:
        judge = JudgeAgent(llm=MagicMock())
        assert judge.logger is not None


class TestJudgeAgentMediate:
    """Tests for the mediate() method."""

    def test_mediate_returns_tuple(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        verdict = MediatorVerdict(
            contradictions=["Agent A says X, Agent B says Y"],
            resolution_summary="Partial agreement found.",
            confidence=0.5,
        )
        mock_llm.with_structured_output.return_value.invoke.return_value = verdict

        judge = JudgeAgent(llm=mock_llm)
        result = judge.mediate(sample_reports, sample_history)

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_mediate_returns_agent_argument_and_bool(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        verdict = MediatorVerdict(
            contradictions=[],
            resolution_summary="All experts agree.",
            confidence=0.95,
        )
        mock_llm.with_structured_output.return_value.invoke.return_value = verdict

        judge = JudgeAgent(llm=mock_llm)
        argument, is_consensus = judge.mediate(sample_reports, sample_history)

        assert isinstance(argument, AgentArgument)
        assert argument.agent_name == "Mediator"
        assert isinstance(is_consensus, bool)

    def test_consensus_above_threshold(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        """confidence >= CONSENSUS_THRESHOLD => is_consensus is True."""
        verdict = MediatorVerdict(
            contradictions=[],
            resolution_summary="Full agreement.",
            confidence=CONSENSUS_THRESHOLD,
        )
        judge = JudgeAgent(llm=mock_llm)

        # Patch the private _fallback_mediate to directly return our verdict,
        # bypassing LangChain chain construction which is hard to mock end-to-end.
        with patch.object(judge, "_fallback_mediate", return_value=verdict):
            # Also make structured path raise so fallback is always triggered
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            _, is_consensus = judge.mediate(sample_reports, sample_history)

        assert is_consensus is True

    def test_no_consensus_below_threshold(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        """confidence < CONSENSUS_THRESHOLD => is_consensus is False."""
        verdict = MediatorVerdict(
            contradictions=["Major contradiction"],
            resolution_summary="Unresolved.",
            confidence=CONSENSUS_THRESHOLD - 0.01,
        )
        mock_llm.with_structured_output.return_value.invoke.return_value = verdict

        judge = JudgeAgent(llm=mock_llm)
        _, is_consensus = judge.mediate(sample_reports, sample_history)
        assert is_consensus is False

    def test_mediate_generic_any_agent_count(self, mock_llm: MagicMock) -> None:
        """mediate() accepts any number of reports without modification."""
        verdict = MediatorVerdict(contradictions=[], resolution_summary="Ok.", confidence=0.9)
        # 5 agents instead of 3 — method should not care
        reports = {f"agent_{i}": f"Report from agent {i}" for i in range(5)}
        judge = JudgeAgent(llm=mock_llm)

        with patch.object(judge, "_fallback_mediate", return_value=verdict):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            argument, is_consensus = judge.mediate(reports, [])

        assert argument.agent_name == "Mediator"
        assert is_consensus is True

    def test_confidence_score_stored_in_argument(
        self, mock_llm: MagicMock, sample_reports: dict, sample_history: list
    ) -> None:
        expected_confidence = 0.72
        verdict = MediatorVerdict(
            contradictions=[], resolution_summary="Partial.", confidence=expected_confidence
        )
        judge = JudgeAgent(llm=mock_llm)

        with patch.object(judge, "_fallback_mediate", return_value=verdict):
            mock_llm.with_structured_output.side_effect = Exception("force fallback")
            argument, _ = judge.mediate(sample_reports, sample_history)

        assert argument.confidence_score == pytest.approx(expected_confidence)

    def test_fallback_when_structured_output_fails(
        self, sample_reports: dict, sample_history: list
    ) -> None:
        """When structured output raises, fallback should produce a MediatorVerdict."""
        llm = MagicMock()
        # Structured path raises
        llm.with_structured_output.side_effect = Exception("Provider not supported")
        # Plain text path
        llm.invoke.return_value = MagicMock(content="Confidence: 0.6")

        judge = JudgeAgent(llm=llm)
        # Should not raise — fallback activates
        argument, _ = judge.mediate(sample_reports, sample_history)
        assert argument.agent_name == "Mediator"


class TestJudgeAgentExtractConfidence:
    """Tests for the private text-based confidence extractor (fallback path)."""

    def test_extracts_valid_float(self) -> None:
        text = "The confidence score is: 0.78\nAll experts agree."
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == pytest.approx(0.78)

    def test_clamps_above_one(self) -> None:
        text = "confidence: 1.5"
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == 1.0

    def test_clamps_below_zero(self) -> None:
        text = "confidence: -0.3"
        result = JudgeAgent._extract_confidence_from_text(text)
        assert result == 0.0

    def test_defaults_to_0_5_when_not_found(self) -> None:
        result = JudgeAgent._extract_confidence_from_text("No score mentioned here.")
        assert result == 0.5
