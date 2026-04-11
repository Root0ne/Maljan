from unittest.mock import MagicMock

import pytest

from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.network_analyst import NetworkAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.core.exceptions import AnalystError

# ---------------------------------------------------------------------------
# Agent Analyze Tests
# ---------------------------------------------------------------------------


class TestStaticAnalystAnalyze:
    """Tests for StaticAnalyst.analyze() with mocked LLM."""

    def test_analyze_returns_llm_content(self, mock_llm: MagicMock) -> None:
        """analyze() returns the LLM response content as a string."""
        mock_llm.invoke.return_value = MagicMock(content="Found T1027 obfuscation")
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")

        # Create a mock chain that returns expected content
        chain_mock = MagicMock()
        chain_mock.invoke.return_value = MagicMock(content="Found T1027 obfuscation")
        mock_llm.__or__ = MagicMock(return_value=chain_mock)

        result = agent.analyze("test data")
        assert isinstance(result, str)

    def test_safe_analyze_catches_errors(self, mock_llm: MagicMock) -> None:
        """safe_analyze() wraps errors in AnalystError."""
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        # Patch the agent's own analyze to simulate a failure
        agent.analyze = MagicMock(side_effect=RuntimeError("API down"))  # type: ignore[method-assign]
        with pytest.raises(AnalystError):
            agent.safe_analyze("test data")


class TestDynamicAnalystAnalyze:
    """Tests for DynamicAnalyst.analyze() with mocked LLM."""

    def test_analyze_returns_llm_content(self, mock_llm: MagicMock) -> None:
        """analyze() returns the LLM response content."""
        chain_mock = MagicMock()
        chain_mock.invoke.return_value = MagicMock(content="Found T1055 injection")
        mock_llm.__or__ = MagicMock(return_value=chain_mock)

        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        result = agent.analyze("test data")
        assert isinstance(result, str)


class TestNetworkAnalystAnalyze:
    """Tests for NetworkAnalyst.analyze() with mocked LLM."""

    def test_analyze_returns_llm_content(self, mock_llm: MagicMock) -> None:
        """analyze() returns the LLM response content."""
        chain_mock = MagicMock()
        chain_mock.invoke.return_value = MagicMock(content="Found T1071 C2 beacon")
        mock_llm.__or__ = MagicMock(return_value=chain_mock)

        agent = NetworkAnalyst(llm=mock_llm, name="NetworkAnalyst")
        result = agent.analyze("test data")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Agent Revise Tests
# ---------------------------------------------------------------------------


class TestAgentRevise:
    """Tests for agent revise() methods."""

    def test_static_revise_returns_string(self, mock_llm: MagicMock) -> None:
        """StaticAnalyst.revise() returns updated analysis string."""
        chain_mock = MagicMock()
        chain_mock.invoke.return_value = MagicMock(content="Revised: C2 URL confirmed")
        mock_llm.__or__ = MagicMock(return_value=chain_mock)

        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        result = agent.revise(
            original_data="raw data",
            own_report="original report",
            peer_reports={"dynamic": "found persistence", "network": "found beacon"},
            mediator_feedback="Static missed C2 correlation",
        )
        assert isinstance(result, str)

    def test_dynamic_revise_returns_string(self, mock_llm: MagicMock) -> None:
        """DynamicAnalyst.revise() returns updated analysis string."""
        chain_mock = MagicMock()
        chain_mock.invoke.return_value = MagicMock(content="Revised: persistence confirmed")
        mock_llm.__or__ = MagicMock(return_value=chain_mock)

        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        result = agent.revise(
            original_data="raw data",
            own_report="original report",
            peer_reports={"static": "found APIs", "network": "found beacon"},
            mediator_feedback="Correlate with network findings",
        )
        assert isinstance(result, str)

    def test_safe_revise_catches_errors(self, mock_llm: MagicMock) -> None:
        """safe_revise() wraps errors in AnalystError."""
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        # Patch the agent's own revise to simulate a failure
        agent.revise = MagicMock(side_effect=RuntimeError("API timeout"))  # type: ignore[method-assign]
        with pytest.raises(AnalystError):
            agent.safe_revise(
                original_data="data",
                own_report="report",
                peer_reports={},
                mediator_feedback="feedback",
            )
