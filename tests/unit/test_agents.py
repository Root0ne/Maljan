from unittest.mock import MagicMock, patch

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
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client"),
            patch.object(agent, "execute_tool_loop", return_value="Found T1027 obfuscation"),
        ):
            result = agent.analyze("test data")
        assert isinstance(result, str)
        assert "T1027" in result

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
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client"),
            patch.object(agent, "execute_tool_loop", return_value="Found T1055 injection"),
        ):
            result = agent.analyze("test data")
        assert isinstance(result, str)
        assert "T1055" in result


class TestNetworkAnalystAnalyze:
    """Tests for NetworkAnalyst.analyze() with mocked LLM."""

    def test_analyze_returns_llm_content(self, mock_llm: MagicMock) -> None:
        """analyze() returns the LLM response content."""
        agent = NetworkAnalyst(llm=mock_llm, name="NetworkAnalyst")
        with (
            patch.object(agent, "_try_initialize_mcp", return_value=True),
            patch.object(agent, "execute_tool_loop", return_value="Found T1071 C2 beacon"),
        ):
            result = agent.analyze("test data")
        assert isinstance(result, str)
        assert "T1071" in result


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
