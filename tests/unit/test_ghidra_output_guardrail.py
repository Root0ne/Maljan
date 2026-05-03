"""Unit tests for MCPLangChainToolkit output guardrail.

Validates that large MCP tool outputs are compressed or truncated
before being returned to the LLM context window.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.agents.mcp_client import MCPLangChainToolkit


@pytest.fixture
def server_params() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# _apply_output_guardrail tests
# ---------------------------------------------------------------------------


class TestOutputGuardrailPassthrough:
    """Outputs under the limit should pass through untouched."""

    def test_short_output_unchanged(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params, max_output_chars=1000)
        text = "short output"
        assert toolkit._apply_output_guardrail(text) == text

    def test_exact_limit_unchanged(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params, max_output_chars=100)
        text = "A" * 100
        assert toolkit._apply_output_guardrail(text) == text


class TestOutputGuardrailTruncation:
    """Outputs over the limit should be truncated when no guardrail callback is set."""

    def test_large_output_truncated(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params, max_output_chars=100)
        text = "B" * 500
        result = toolkit._apply_output_guardrail(text)

        # Should be truncated to max_output_chars + marker
        assert len(result) < len(text)
        assert result.endswith("[OUTPUT TRUNCATED]")
        # The payload portion should be exactly 100 chars
        payload = result.split("\n\n[OUTPUT TRUNCATED]")[0]
        assert len(payload) == 100

    def test_truncation_marker_present(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params, max_output_chars=50)
        text = "C" * 200
        result = toolkit._apply_output_guardrail(text)
        assert "[OUTPUT TRUNCATED]" in result


class TestOutputGuardrailWithCallback:
    """When a guardrail callback is provided, it should be called for large outputs."""

    def test_guardrail_called_for_large_output(self, server_params: MagicMock) -> None:
        mock_guardrail = MagicMock(return_value="summarized output")
        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=mock_guardrail,
            max_output_chars=100,
        )
        text = "D" * 500
        result = toolkit._apply_output_guardrail(text)

        mock_guardrail.assert_called_once_with(text)
        assert result == "summarized output"

    def test_guardrail_not_called_for_small_output(self, server_params: MagicMock) -> None:
        mock_guardrail = MagicMock(return_value="should not be called")
        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=mock_guardrail,
            max_output_chars=1000,
        )
        text = "E" * 50
        result = toolkit._apply_output_guardrail(text)

        mock_guardrail.assert_not_called()
        assert result == text

    def test_guardrail_error_falls_back_to_truncation(self, server_params: MagicMock) -> None:
        def failing_guardrail(text: str) -> str:
            raise RuntimeError("LLM connection failed")

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=failing_guardrail,
            max_output_chars=100,
        )
        text = "F" * 500
        result = toolkit._apply_output_guardrail(text)

        # Should fall back to truncation, not raise
        assert "[OUTPUT TRUNCATED]" in result
        assert len(result) < len(text)


class TestOutputGuardrailWithFunctionSummarizer:
    """Integration test with a mock FunctionSummarizer.summarize_chunk."""

    def test_summarizer_as_guardrail(self, server_params: MagicMock) -> None:
        """Simulates FunctionSummarizer.summarize_chunk being used as guardrail."""
        # Simulate what FunctionSummarizer.summarize_chunk does
        mock_llm_response = MagicMock()
        mock_llm_response.content = (
            "Function performs process injection via VirtualAllocEx "
            "and WriteProcessMemory. Creates remote thread for code execution."
        )
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = mock_llm_response

        from maljan.analysis.function_summarizer import FunctionSummarizer

        summarizer = FunctionSummarizer(llm=mock_llm, max_summary_words=150)

        toolkit = MCPLangChainToolkit(
            server_params,
            output_guardrail=summarizer.summarize_chunk,
            max_output_chars=100,
        )

        # Simulate a large decompile output
        large_decompile = (
            "void FUN_00401000(void) {\n"
            "  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);\n"
            "  LPVOID pRemote = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
            "  WriteProcessMemory(hProcess, pRemote, shellcode, sizeof(shellcode), NULL);\n"
            "  CreateRemoteThread(hProcess, NULL, 0, pRemote, NULL, 0, NULL);\n"
            "}\n" * 20  # Repeat to make it large
        )

        result = toolkit._apply_output_guardrail(large_decompile)

        # Should have been summarized by the mock LLM
        assert "process injection" in result
        assert "VirtualAllocEx" in result
        # LLM was actually called
        assert mock_llm.invoke.call_count == 1


class TestToolkitConstructorDefaults:
    """Verify constructor defaults for guardrail parameters."""

    def test_default_no_guardrail(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params)
        assert toolkit._output_guardrail is None
        assert toolkit._max_output_chars == 8000

    def test_custom_max_chars(self, server_params: MagicMock) -> None:
        toolkit = MCPLangChainToolkit(server_params, max_output_chars=4000)
        assert toolkit._max_output_chars == 4000
