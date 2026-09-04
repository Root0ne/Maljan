"""The dynamic analyst must survive an unreachable CAPE, and static must not.

The CAPE MCP endpoint is a port-forward to a separate VM. When that VM is down
the forward still accepts TCP and then closes, so ``initialize()`` does not fail
fast and politely — ``mcp``'s anyio task group cancels and the cancellation
arrives as an exception at the loop boundary. Before the fix, both analysts
called ``_initialize_mcp_client()`` bare, so that one unreachable host cost the
whole dynamic analyst on every single run: no claims, no ISR, an entry in
``_failed_analysts``, and a confidence cap the report then had to explain.

Dynamic holds a second source of evidence — the sandbox JSON is already in
``data``. Losing the toolkit should cost depth, not the analyst.

The asymmetry is the part worth guarding. Static keeps failing loudly on
purpose: for static, Ghidra *is* the evidence, and an analyst that degrades
quietly there would emit a confident-looking report grounded in the PE header
alone. ``_empty_analysts`` would not catch it, because the LLM still produces
claims. So the two tests below assert opposite behaviours from the same fault,
and a future "let's make this consistent" refactor has to argue with them.

Verified live on 2026-07-27 against a socket that accepts and immediately
closes: the analyst survived in 0.4 s with 0 tools and 1 claim, and the log
named the service and the real cause instead of the bare word ``CancelledError``.
This file is the regression guard for that run.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.core.exceptions import AgentLoopCancelled

_CLAIM_BLOCK = (
    "CLAIM: The sample writes itself to the Run key\n"
    "EVIDENCE: RegSetValue: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1547\n"
    "---\n"
)

_SANDBOX_JSON = '{"behavior": {"processes": [{"process_name": "sample.exe", "pid": 832}]}}'


def _transport_died() -> AgentLoopCancelled:
    """The exception the real failure produces, not a stand-in.

    ``AgentLoopCancelled`` is what ``run_on_agent_loop`` raises when the
    coroutine cancels itself rather than being cancelled by our own hard cap —
    the exact shape an accepting-then-closing forward generates.
    """
    return AgentLoopCancelled(
        "cape-mcp-init was cancelled from inside — the MCP transport's task "
        "group cancelled it (no timeout was reached)"
    )


class TestDynamicSurvivesAnUnreachableSandbox:
    """One dead port-forward must not cost an analyst that has other evidence."""

    def test_analyze_isr_still_returns_claims(self, mock_llm: MagicMock) -> None:
        """The behaviour the fix exists for: an ISR, not an exception.

        Fails against the pre-fix code, where the bare ``_initialize_mcp_client``
        let this straight through to ``safe_analyze``.
        """
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value=_CLAIM_BLOCK),
        ):
            isr = agent.analyze_isr(_SANDBOX_JSON)

        assert isr.claims, "the sandbox JSON is evidence on its own"
        assert isr.claims[0].technique_id == "T1547"
        assert isr.domain == "dynamic"

    def test_the_text_path_degrades_the_same_way(self, mock_llm: MagicMock) -> None:
        """``analyze`` and ``analyze_isr`` both call the initializer; both must degrade."""
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value="Found T1055 injection"),
        ):
            result = agent.analyze(_SANDBOX_JSON)

        assert "T1055" in result

    def test_the_loop_runs_with_no_tools_rather_than_stale_ones(self, mock_llm: MagicMock) -> None:
        """Degrading means *no* toolkit, not a half-initialized one.

        A partially-attached toolkit would be worse than none: the ReAct loop
        would offer tools whose transport is already dead and burn the whole
        step budget on calls that cannot answer.
        """
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        agent.tools = []
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value=_CLAIM_BLOCK) as loop,
        ):
            agent.analyze_isr(_SANDBOX_JSON)

        assert loop.called
        assert agent.tools == []

    @pytest.mark.parametrize(
        "failure",
        [
            _transport_died(),
            ConnectionRefusedError("[Errno 111] Connection refused"),
            TimeoutError("cape-mcp-init exceeded 60s"),
            RuntimeError("Attempted to exit cancel scope in a different task"),
        ],
        ids=["self-cancel", "refused", "our-timeout", "anyio-scope"],
    )
    def test_every_way_the_forward_fails_is_survivable(
        self, mock_llm: MagicMock, failure: Exception
    ) -> None:
        """A half-dead forward fails differently on different days.

        Degradation keyed to one exception type would work in the test and not
        in the field, so the guard is written against all four shapes actually
        seen from ``:19004``.
        """
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=failure),
            patch.object(agent, "execute_tool_loop", return_value=_CLAIM_BLOCK),
        ):
            assert agent.analyze_isr(_SANDBOX_JSON).claims

    def test_the_warning_names_the_analyst_and_the_real_cause(
        self, mock_llm: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Silent degradation is its own bug.

        The run still has to say why it is shallower than usual, and it has to
        say something more useful than a bare class name — the erased
        ``CancelledError`` is what cost a day of investigation.
        """
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with (
            caplog.at_level(logging.WARNING),
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value=_CLAIM_BLOCK),
        ):
            agent.analyze_isr(_SANDBOX_JSON)

        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "degrading without saying so is how this went unnoticed"
        joined = " ".join(warnings)
        assert "DynamicAnalyst" in joined
        assert "cape-mcp-init" in joined, "the failing service must be identifiable"
        assert "cancelled from inside" in joined, "the cause must survive, not just the type"


class TestStaticStillFailsLoudly:
    """The deliberate asymmetry — not an inconsistency to be tidied away."""

    def test_a_dead_ghidra_aborts_the_static_analyst(self, mock_llm: MagicMock) -> None:
        """For static there is no second evidence source; degrading would lie."""
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value=_CLAIM_BLOCK),
            pytest.raises(AgentLoopCancelled),
        ):
            agent.analyze_isr("/samples/sample.exe")

    def test_the_static_text_path_fails_too(self, mock_llm: MagicMock) -> None:
        agent = StaticAnalyst(llm=mock_llm, name="StaticAnalyst")
        with (
            patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()),
            patch.object(agent, "execute_tool_loop", return_value="anything"),
            pytest.raises(AgentLoopCancelled),
        ):
            agent.analyze("/samples/sample.exe")

    def test_static_does_not_route_through_the_degrading_helper(self) -> None:
        """Structural, because the failure mode is a plausible-looking edit.

        Swapping static's bare call for ``_try_initialize_mcp`` is a two-word
        change that makes the analysts look pleasingly uniform and silently
        converts every Ghidra outage into a confident report about a PE header.
        """
        import inspect

        from maljan.agents import static_analyst

        source = inspect.getsource(static_analyst.StaticAnalyst)
        assert "_try_initialize_mcp" not in source, (
            "static must keep failing loudly; see the module docstring above"
        )


class TestTheHelperItselfIsTotal:
    """``_try_initialize_mcp`` is the seam; it must never be the thing that raises."""

    def test_it_reports_failure_instead_of_raising(self, mock_llm: MagicMock) -> None:
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")
        with patch.object(agent, "_initialize_mcp_client", side_effect=_transport_died()):
            assert agent._try_initialize_mcp() is False

    def test_a_successful_init_with_no_tools_is_also_false(self, mock_llm: MagicMock) -> None:
        """An empty toolkit is a failed init that forgot to say so."""
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")

        def _attach_nothing() -> None:
            agent.tools = []

        with patch.object(agent, "_initialize_mcp_client", side_effect=_attach_nothing):
            assert agent._try_initialize_mcp() is False

    def test_a_real_init_reports_true(self, mock_llm: MagicMock) -> None:
        agent = DynamicAnalyst(llm=mock_llm, name="DynamicAnalyst")

        def _attach_one() -> None:
            tool: Any = MagicMock()
            tool.name = "get_task_report"
            agent.tools = [tool]

        with patch.object(agent, "_initialize_mcp_client", side_effect=_attach_one):
            assert agent._try_initialize_mcp() is True
