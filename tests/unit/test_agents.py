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


class TestPerAgentMaxStepsOverride:
    """2026-06-23 live-UI audit: the static analyst's Ghidra ReAct loop needs
    more than the default 10 recursion steps. ``react_agent_max_steps_overrides``
    must raise the LangGraph ``recursion_limit`` for ``static`` while leaving
    other analysts on the default. Without it the loop was cut off after ~4 tool
    calls and LangGraph returned "Sorry, need more steps to process this request."
    instead of real claims (live job 3be3ba0e: ReAct "completed" in 17.3s after
    4 tool calls, with its 1200s *time* budget barely touched).
    """

    def _make_tool_agent(self, name: str):  # type: ignore[no-untyped-def]
        from maljan.agents.base_agent import BaseAnalyst

        class _ToolAgent(BaseAnalyst):
            def analyze(self, data: str) -> str:
                return ""

            def revise(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                return ""

        # Non-empty tools so execute_tool_loop takes the ReAct (tools) path.
        return _ToolAgent(llm=MagicMock(), name=name, tools=[MagicMock()])  # type: ignore[arg-type]

    def _capture_recursion_limit(self, name: str) -> int:
        captured: dict[str, int] = {}

        class _FakeExecutor:
            async def ainvoke(self, inputs, config):  # type: ignore[no-untyped-def]
                captured["recursion_limit"] = int(config.get("recursion_limit"))
                return {"messages": [MagicMock(content="done", tool_calls=[])]}

        agent = self._make_tool_agent(name)
        with patch("maljan.agents.base_agent.get_settings") as mock_settings:
            cfg = mock_settings.return_value
            cfg.react_agent_timeout = 180
            cfg.react_agent_timeout_overrides = {"static": 1200}
            cfg.react_agent_max_steps = 10
            cfg.react_agent_max_steps_overrides = {"static": 40}
            cfg.react_agent_tool_call_budget = 20
            with patch("langgraph.prebuilt.create_react_agent", return_value=_FakeExecutor()):
                agent.execute_tool_loop([("system", "s"), ("human", "h")])
        return captured["recursion_limit"]

    def test_static_uses_max_steps_override(self) -> None:
        assert self._capture_recursion_limit("static") == 40

    def test_non_overridden_agent_uses_global_default(self) -> None:
        assert self._capture_recursion_limit("network") == 10

    def test_config_default_pins_static_override(self) -> None:
        from maljan.core.config import Settings

        s = Settings()
        assert s.react_agent_max_steps == 10
        assert s.react_agent_max_steps_overrides.get("static") == 40


class TestForcedFinalSynthesis:
    """2026-06-23 live-UI audit: a tool-using ReAct loop that exhausts its step
    budget returns LangGraph's "Sorry, need more steps to process this request."
    stop message, silently discarding every tool result it gathered.
    ``execute_tool_loop`` must salvage that by re-invoking the model once on the
    accumulated conversation so the evidence becomes a real answer.
    """

    def _make_tool_agent(self, llm: object):  # type: ignore[no-untyped-def]
        from maljan.agents.base_agent import BaseAnalyst

        class _ToolAgent(BaseAnalyst):
            def analyze(self, data: str) -> str:
                return ""

            def revise(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                return ""

        return _ToolAgent(llm=llm, name="static", tools=[MagicMock()])  # type: ignore[arg-type]

    @staticmethod
    def _settings(mock_settings):  # type: ignore[no-untyped-def]
        cfg = mock_settings.return_value
        cfg.react_agent_timeout = 180
        cfg.react_agent_timeout_overrides = {"static": 1200}
        cfg.react_agent_max_steps = 10
        cfg.react_agent_max_steps_overrides = {"static": 40}
        cfg.react_agent_tool_call_budget = 20
        return cfg

    def test_recursion_stop_triggers_synthesis(self) -> None:
        # A tool call + result, then the LangGraph "need more steps" stop turn.
        react_messages = [
            MagicMock(content="", tool_calls=[{"name": "decompile", "args": {}, "id": "t1"}]),
            MagicMock(content="entry calls WriteProcessMemory", tool_calls=[]),
            MagicMock(content="Sorry, need more steps to process this request.", tool_calls=[]),
        ]

        class _FakeExecutor:
            async def ainvoke(self, inputs, config):  # type: ignore[no-untyped-def]
                return {"messages": react_messages}

        synth_llm = MagicMock()
        synth_llm.invoke.return_value = MagicMock(
            content=(
                "CLAIM: Process injection via WriteProcessMemory\n"
                "EVIDENCE: decompiled entry\nCONFIDENCE: 0.8\nTECHNIQUE: T1055"
            )
        )
        agent = self._make_tool_agent(synth_llm)
        with patch("maljan.agents.base_agent.get_settings") as ms:
            self._settings(ms)
            with patch("langgraph.prebuilt.create_react_agent", return_value=_FakeExecutor()):
                result = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert "T1055" in result
        assert "need more steps" not in result.lower()
        synth_llm.invoke.assert_called()  # the salvage call fired

    def test_convergent_loop_does_not_trigger_synthesis(self) -> None:
        react_messages = [
            MagicMock(content="", tool_calls=[{"name": "decompile", "args": {}, "id": "t1"}]),
            MagicMock(content="benign code", tool_calls=[]),
            MagicMock(
                content="CLAIM: packer detected\nEVIDENCE: x\nCONFIDENCE: 0.7\nTECHNIQUE: T1027",
                tool_calls=[],
            ),
        ]

        class _FakeExecutor:
            async def ainvoke(self, inputs, config):  # type: ignore[no-untyped-def]
                return {"messages": react_messages}

        llm = MagicMock()
        agent = self._make_tool_agent(llm)
        with patch("maljan.agents.base_agent.get_settings") as ms:
            self._settings(ms)
            with patch("langgraph.prebuilt.create_react_agent", return_value=_FakeExecutor()):
                result = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert "T1027" in result
        llm.invoke.assert_not_called()  # a real answer needs no salvage
