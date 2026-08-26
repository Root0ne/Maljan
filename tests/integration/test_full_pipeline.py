"""End-to-end pipeline integration tests.

These tests verify that MaljanApp.arun() completes successfully with
mocked or minimal real dependencies, asserting correct state transitions
and output structure.
"""

from __future__ import annotations

import pytest

from maljan.app import MaljanApp
from maljan.core.config import Settings


@pytest.fixture
def mock_settings() -> Settings:
    s = Settings()
    s.llm.provider = "ollama"  # will be mocked via MALJAN_MOCK_MODE
    s.negotiation.max_iterations = 1  # fast
    return s


class TestMockPipeline:
    """Tests with MALJAN_MOCK_MODE=true — no LLM calls."""

    def test_mock_pipeline_completes(self, mock_settings: Settings) -> None:
        """Mock pipeline runs end-to-end and returns expected keys."""
        app = MaljanApp(config=mock_settings, mock=True)
        result = app.run("deadbeef" * 8, file_name="test.exe")

        assert result["final_decision"] == "Malware"
        assert "stix_output" in result
        assert "run_summary" in result
        assert "reports" in result
        assert "isr_reports" in result
        assert "discussion_history" in result
        assert result["iteration_count"] >= 0

    def test_mock_pipeline_with_sandbox_report(self, mock_settings: Settings) -> None:
        """Mock pipeline accepts a sandbox_report in state."""
        app = MaljanApp(config=mock_settings, mock=True)
        # In mock mode sandbox submission is skipped, but we verify the
        # sample_path argument is accepted without error.
        result = app.run(
            "deadbeef" * 8,
            file_name="test.exe",
            sample_path="/tmp/fake.exe",
        )
        assert result["final_decision"] == "Malware"


class TestAsyncPipeline:
    """Async variant tests."""

    @pytest.mark.asyncio
    async def test_async_mock_pipeline_completes(self, mock_settings: Settings) -> None:
        """Async mock pipeline completes within reasonable time."""
        import asyncio

        app = MaljanApp(config=mock_settings, mock=True)

        # Wrap in wait_for to guarantee it does not hang
        result = await asyncio.wait_for(
            app.arun("cafebabe" * 8, file_name="async_test.exe"),
            timeout=10.0,
        )

        assert result["final_decision"] == "Malware"
        assert result["stix_output"] is not None
