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


# ---------------------------------------------------------------------------
# Wave 5 HANG-01 (2026-05-28) — no-tools fallback timeout regression tests
# ---------------------------------------------------------------------------


class TestNoToolsFallbackTimeout:
    """``execute_tool_loop`` must enforce a hard wall-clock cap on the
    no-tools fallback path so a stalled / queued LLM cannot freeze the
    worker indefinitely.

    Before the fix, ``self.llm.invoke(prebuilt)`` ran synchronously with
    no timeout. The openai SDK's default 600s request_timeout combined
    with the default ``max_retries=2`` produced ~30 min of silent
    waiting before raising, with the worker heartbeating the whole
    time.
    """

    def _make_bare_agent(self, llm: object):  # type: ignore[no-untyped-def]
        """Concrete BaseAnalyst with empty tools list."""
        from maljan.agents.base_agent import BaseAnalyst

        class _BareAgent(BaseAnalyst):
            def analyze(self, data: str) -> str:
                return ""

            def revise(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                return ""

        return _BareAgent(llm=llm, name="bare", tools=[])  # type: ignore[arg-type]

    def test_no_tools_fallback_returns_content_on_success(self) -> None:
        """Fast path: when the LLM responds quickly, the content is returned."""

        class _FastLLM:
            def invoke(self, messages):  # type: ignore[no-untyped-def]
                return MagicMock(content="fast answer")

        agent = self._make_bare_agent(_FastLLM())
        with patch("maljan.agents.base_agent.get_settings") as mock_settings:
            mock_settings.return_value.react_agent_timeout = 5
            mock_settings.return_value.react_agent_timeout_overrides = {}
            result = agent.execute_tool_loop([("system", "s"), ("human", "h")])
        assert result == "fast answer"

    def test_no_tools_fallback_raises_timeout_on_hang(self) -> None:
        """Slow path: a hanging LLM must trigger TimeoutError within budget."""
        import time

        class _HangingLLM:
            def invoke(self, messages):  # type: ignore[no-untyped-def]
                time.sleep(60)
                return MagicMock(content="never")

        agent = self._make_bare_agent(_HangingLLM())
        with patch("maljan.agents.base_agent.get_settings") as mock_settings:
            # 1s budget; outer daemon thread guard is timeout + 30 = 31s.
            mock_settings.return_value.react_agent_timeout = 1
            mock_settings.return_value.react_agent_timeout_overrides = {}

            t0 = time.monotonic()
            with pytest.raises(TimeoutError):
                agent.execute_tool_loop([("system", "s"), ("human", "h")])
            elapsed = time.monotonic() - t0

        # Inner asyncio.wait_for fires at ~1s and propagates to the outer
        # thread, so we should see the failure well before the 31s daemon
        # killer kicks in. 10s gives plenty of slack for slow CI.
        assert elapsed < 10, f"timeout raised too late: {elapsed:.1f}s"

    def test_no_tools_fallback_honours_per_agent_override(self) -> None:
        """The per-agent override wins over the global ``react_agent_timeout``."""
        import time

        observed_timeout: list[int] = []

        class _RecordingLLM:
            def invoke(self, messages):  # type: ignore[no-untyped-def]
                # Sleep just long enough to confirm the wait_for budget.
                time.sleep(10)
                return MagicMock(content="never")

        agent = self._make_bare_agent(_RecordingLLM())
        # Patch the logger so we can capture the timeout value the
        # fallback logs and confirm the override path is taken.
        original_info = agent.logger.info

        def _capturing_info(fmt, *args, **kwargs):  # type: ignore[no-untyped-def]
            if "no-tools fallback, timeout=" in str(fmt) and args:
                observed_timeout.append(int(args[0]))
            return original_info(fmt, *args, **kwargs)

        with patch.object(agent.logger, "info", side_effect=_capturing_info):
            with patch("maljan.agents.base_agent.get_settings") as mock_settings:
                mock_settings.return_value.react_agent_timeout = 999
                mock_settings.return_value.react_agent_timeout_overrides = {"bare": 1}

                t0 = time.monotonic()
                with pytest.raises(TimeoutError):
                    agent.execute_tool_loop([("system", "s"), ("human", "h")])
                elapsed = time.monotonic() - t0

        assert 1 in observed_timeout, (
            f"per-agent override was ignored; observed timeouts: {observed_timeout}"
        )
        assert elapsed < 10, f"override timeout did not fire fast enough: {elapsed:.1f}s"
