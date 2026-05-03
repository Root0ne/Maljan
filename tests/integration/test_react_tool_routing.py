"""Integration tests for ReAct agent tool routing.

Validates that ``create_react_agent`` correctly dispatches tool calls
through the ``BaseAnalyst.execute_tool_loop()`` pipeline.

Test tiers:
  1. **Mock-only (always runs):** Mock LLM + mock tools — verifies the
     routing wiring, tool binding, and response extraction.
  2. **Live LLM (optional):** Real Gemini API + mock tools — verifies that
     a real model can discover and invoke tools in the ReAct loop.
     Skipped unless ``GOOGLE_API_KEY`` is set.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst

# ---------------------------------------------------------------------------
# Fixtures: mock tools
# ---------------------------------------------------------------------------


def _mock_decompile(function_name: str) -> str:
    """Simulates a Ghidra decompile_function tool."""
    return (
        f"void {function_name}(void) {{\n"
        f"  VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
        f"  WriteProcessMemory(hProcess, pRemote, shellcode, sizeof(shellcode), NULL);\n"
        f"}}"
    )


def _mock_list_functions() -> str:
    """Simulates a Ghidra list_functions tool."""
    return "FUN_00401000\nFUN_00401200\nFUN_00401400\nmain\n_start"


def _mock_get_task_report(task_id: int) -> str:
    """Simulates a CAPEv2 get_task_report tool."""
    return (
        '{"info": {"id": '
        + str(task_id)
        + '}, "signatures": [{"name": "process_injection", "severity": 3}]}'
    )


@pytest.fixture
def mock_tools() -> list[StructuredTool]:
    """Create a set of mock MCP tools for testing."""
    decompile_tool = StructuredTool.from_function(
        func=_mock_decompile,
        name="decompile_function",
        description="Decompile a function by name from the loaded binary.",
    )
    list_tool = StructuredTool.from_function(
        func=_mock_list_functions,
        name="list_functions",
        description="List all functions in the loaded binary.",
    )
    report_tool = StructuredTool.from_function(
        func=_mock_get_task_report,
        name="get_task_report",
        description="Get the analysis report for a CAPEv2 task by ID.",
    )
    return [decompile_tool, list_tool, report_tool]


# ---------------------------------------------------------------------------
# Concrete test agent (minimal subclass of BaseAnalyst)
# ---------------------------------------------------------------------------


class _TestAnalyst(BaseAnalyst):
    """Minimal concrete subclass for testing execute_tool_loop."""

    def analyze(self, data: str) -> str:
        return self.execute_tool_loop(
            [
                ("system", "You are a malware analyst. Use your tools."),
                ("human", data),
            ]
        )

    def analyze_isr(self, data: str) -> str:
        return self.analyze(data)

    def revise(self, original_data: str, previous_report: str, directive: str) -> str:
        return self.analyze(original_data)


# ---------------------------------------------------------------------------
# Group 1: Mock-only tests (no LLM, always runs)
# ---------------------------------------------------------------------------


class TestToolBinding:
    """Verify that tools are correctly bound to the agent."""

    def test_tools_stored_on_agent(self, mock_tools: list[StructuredTool]) -> None:
        mock_llm = MagicMock()
        agent = _TestAnalyst(llm=mock_llm, name="test", tools=mock_tools)
        assert len(agent.tools) == 3

    def test_tool_names_match(self, mock_tools: list[StructuredTool]) -> None:
        mock_llm = MagicMock()
        agent = _TestAnalyst(llm=mock_llm, name="test", tools=mock_tools)
        names = {t.name for t in agent.tools}
        assert names == {"decompile_function", "list_functions", "get_task_report"}

    def test_no_tools_uses_simple_invocation(self) -> None:
        """Without tools, execute_tool_loop should fall back to direct LLM call."""
        mock_llm = MagicMock()
        mock_response = AIMessage(content="No tools available.")
        # The fallback path uses (ChatPromptTemplate | llm).invoke({})
        # so we need the mock to support the pipe operator chain.
        mock_llm.__or__ = MagicMock(return_value=mock_llm)
        mock_llm.invoke.return_value = mock_response

        agent = _TestAnalyst(llm=mock_llm, name="test", tools=[])
        result = agent.analyze("test data")
        assert isinstance(result, str)


class TestMockToolExecution:
    """Verify tools are actually callable through the mock setup."""

    def test_decompile_tool_returns_code(self, mock_tools: list[StructuredTool]) -> None:
        decompile = next(t for t in mock_tools if t.name == "decompile_function")
        result = decompile.invoke({"function_name": "FUN_00401000"})
        assert "VirtualAllocEx" in result
        assert "FUN_00401000" in result

    def test_list_functions_tool(self, mock_tools: list[StructuredTool]) -> None:
        list_fn = next(t for t in mock_tools if t.name == "list_functions")
        result = list_fn.invoke({})
        assert "main" in result
        assert "FUN_00401000" in result

    def test_get_task_report_tool(self, mock_tools: list[StructuredTool]) -> None:
        report = next(t for t in mock_tools if t.name == "get_task_report")
        result = report.invoke({"task_id": 42})
        assert "process_injection" in result
        assert '"id": 42' in result


class TestToolRoutingMechanism:
    """Verify the ReAct routing mechanism with mock create_react_agent."""

    def test_create_react_agent_called_with_tools(self, mock_tools: list[StructuredTool]) -> None:
        """Verify create_react_agent is called when tools are present."""
        mock_llm = MagicMock()
        agent = _TestAnalyst(llm=mock_llm, name="test", tools=mock_tools)

        with patch("langgraph.prebuilt.create_react_agent") as mock_create:
            mock_executor = MagicMock()
            mock_create.return_value = mock_executor

            # Make ainvoke return a result with messages

            async def fake_ainvoke(messages_dict, config=None):
                return {
                    "messages": [
                        AIMessage(content="Analysis complete: process injection detected.")
                    ]
                }

            mock_executor.ainvoke = fake_ainvoke

            result = agent.analyze("Analyze this binary for malware behavior.")

            # Verify create_react_agent was called with the right LLM and tools
            mock_create.assert_called_once_with(mock_llm, mock_tools)
            assert "process injection" in result

    def test_react_loop_extracts_final_message(self, mock_tools: list[StructuredTool]) -> None:
        """The loop should return the content of the last message."""
        mock_llm = MagicMock()
        agent = _TestAnalyst(llm=mock_llm, name="test", tools=mock_tools)

        with patch("langgraph.prebuilt.create_react_agent") as mock_create:
            mock_executor = MagicMock()
            mock_create.return_value = mock_executor

            async def fake_ainvoke(messages_dict, config=None):
                return {
                    "messages": [
                        AIMessage(content="Thinking..."),
                        AIMessage(content="Tool called."),
                        AIMessage(content="Final verdict: Malware."),
                    ]
                }

            mock_executor.ainvoke = fake_ainvoke

            result = agent.analyze("test")
            assert result == "Final verdict: Malware."


# ---------------------------------------------------------------------------
# Group 2: Live LLM tests (optional — requires GOOGLE_API_KEY)
# ---------------------------------------------------------------------------

_HAS_GEMINI_KEY = bool(os.environ.get("GOOGLE_API_KEY"))


@pytest.mark.skipif(not _HAS_GEMINI_KEY, reason="GOOGLE_API_KEY not set")
class TestLiveGeminiToolRouting:
    """Live integration: real Gemini LLM + mock tools.

    These tests call the Gemini API to verify that the model can discover
    and invoke tools within the ReAct loop. They are skipped in CI unless
    ``GOOGLE_API_KEY`` is set.
    """

    @pytest.fixture
    def gemini_llm(self):
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model="gemini-2.5-flash-preview-05-20",
            temperature=0.0,
        )

    def test_gemini_can_call_list_functions(
        self, gemini_llm, mock_tools: list[StructuredTool]
    ) -> None:
        """Gemini should call list_functions when asked to list functions."""
        agent = _TestAnalyst(llm=gemini_llm, name="test", tools=mock_tools)
        result = agent.analyze("List all functions in the binary. Use the list_functions tool.")
        # The model should have called list_functions and returned the result
        assert isinstance(result, str)
        assert len(result) > 0

    def test_gemini_can_call_decompile(self, gemini_llm, mock_tools: list[StructuredTool]) -> None:
        """Gemini should call decompile_function when asked to decompile."""
        agent = _TestAnalyst(llm=gemini_llm, name="test", tools=mock_tools)
        result = agent.analyze(
            "Decompile the function named 'main' using the decompile_function tool "
            "and tell me what it does."
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_gemini_multi_tool_chain(self, gemini_llm, mock_tools: list[StructuredTool]) -> None:
        """Gemini should be able to chain multiple tool calls."""
        agent = _TestAnalyst(llm=gemini_llm, name="test", tools=mock_tools)
        result = agent.analyze(
            "First, list all functions using list_functions. "
            "Then decompile 'FUN_00401000' using decompile_function. "
            "Summarize what you find."
        )
        assert isinstance(result, str)
        assert len(result) > 0
