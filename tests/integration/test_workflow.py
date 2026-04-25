"""Integration tests for the full Maljan pipeline.

These tests exercise the entire LangGraph workflow in mock mode — no real LLM
calls, no API keys required. They validate that all subsystems are correctly
wired together: analyst nodes, negotiation loop, judge verdict, and the
new Phase 1–3 / Observability systems.

Test groups:
  - Core pipeline (existing tests, backward-compatible)
  - New state fields (ISR reports, confidence history, sycophancy)
  - Chunked analyst node wiring (load_chunked path + merge)
  - Analyst node non-mock integration (mocked LLM, real node logic)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.app import MaljanApp
from maljan.core.config import ChunkingConfig, NegotiationConfig, Settings
from maljan.pipeline.nodes import make_analyst_node
from maljan.schemas.isr_models import AgentISR

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_app() -> MaljanApp:
    """Reusable mock-mode MaljanApp with default settings."""
    return MaljanApp(mock=True)


@pytest.fixture
def mock_result(mock_app: MaljanApp) -> dict:
    """Run the full mock pipeline and cache the result."""
    return mock_app.run("sample_1", file_name="test.exe")


# ---------------------------------------------------------------------------
# Group 1: Core pipeline (backward-compatible, pre-existing tests)
# ---------------------------------------------------------------------------

def test_pipeline_mock_mode_end_to_end() -> None:
    """Full pipeline runs in mock mode and produces a verdict."""
    app = MaljanApp(mock=True)
    result = app.run("sample_1", file_name="test.exe")

    reports = result.get("reports", {})
    assert "static" in reports
    assert "dynamic" in reports
    assert "network" in reports

    assert result["iteration_count"] >= 1

    if result["iteration_count"] > 1:
        revised = result.get("revised_reports", {})
        assert len(revised) >= 1

    assert result["final_decision"] == "Malware"
    assert len(result.get("discussion_history", [])) >= 1


def test_pipeline_graph_compiles() -> None:
    """Graph compiles without errors."""
    app = MaljanApp(mock=True)
    assert app.graph is not None


def test_pipeline_consensus_iterations() -> None:
    """Mock pipeline reaches consensus within reasonable iterations."""
    app = MaljanApp(mock=True)
    result = app.run("sample_1")

    assert result["iteration_count"] <= 3
    assert result["final_decision"] is not None


def test_pipeline_respects_max_iterations() -> None:
    """Pipeline respects custom max_iterations from config."""
    config = Settings(negotiation=NegotiationConfig(max_iterations=1))
    app = MaljanApp(config=config, mock=True)
    result = app.run("sample_1")

    assert result["iteration_count"] == 1
    assert result["final_decision"] is not None


# ---------------------------------------------------------------------------
# Group 2: New state fields — ISR, confidence history, sycophancy
# ---------------------------------------------------------------------------

class TestNewStateFields:
    def test_isr_reports_present_for_all_agents(self, mock_result: dict) -> None:
        """ISR reports should be populated for all three analyst agents."""
        isr_reports = mock_result.get("isr_reports", {})
        assert "static" in isr_reports
        assert "dynamic" in isr_reports
        assert "network" in isr_reports

    def test_isr_reports_are_agent_isr_objects(self, mock_result: dict) -> None:
        """Each entry in isr_reports should be an AgentISR instance."""
        isr_reports = mock_result.get("isr_reports", {})
        for name, isr in isr_reports.items():
            assert isinstance(isr, AgentISR), f"isr_reports['{name}'] is not AgentISR"

    def test_isr_agent_ids_match_keys(self, mock_result: dict) -> None:
        """agent_id in each ISR should match the dict key."""
        for key, isr in (mock_result.get("isr_reports") or {}).items():
            assert isr.agent_id == key

    def test_confidence_history_populated(self, mock_result: dict) -> None:
        """Confidence history should have at least one entry after pipeline run."""
        history = mock_result.get("confidence_history", [])
        assert isinstance(history, list)
        assert len(history) >= 1

    def test_confidence_history_values_in_range(self, mock_result: dict) -> None:
        """All confidence values must be in [0.0, 1.0]."""
        for val in (mock_result.get("confidence_history") or []):
            assert 0.0 <= val <= 1.0, f"Confidence {val} out of range"

    def test_sycophancy_detected_field_exists(self, mock_result: dict) -> None:
        """sycophancy_detected must be present in the final state."""
        assert "sycophancy_detected" in mock_result

    def test_sycophancy_detected_is_bool(self, mock_result: dict) -> None:
        assert isinstance(mock_result.get("sycophancy_detected"), bool)

    def test_discussion_history_has_agent_arguments(self, mock_result: dict) -> None:
        """Discussion history entries should have agent_name and confidence_score."""
        history = mock_result.get("discussion_history", [])
        assert len(history) >= 1
        first = history[0]
        assert hasattr(first, "agent_name")
        assert hasattr(first, "confidence_score")

    def test_stix_output_is_dict(self, mock_result: dict) -> None:
        """stix_output should always be a dict (may be empty in mock mode)."""
        stix = mock_result.get("stix_output")
        assert isinstance(stix, dict)

    def test_run_summary_key_present(self, mock_result: dict) -> None:
        """run_summary key must exist in the final state dict."""
        assert "run_summary" in mock_result

    def test_run_summary_is_none_in_mock_mode(self, mock_result: dict) -> None:
        """In mock mode, the judge node skips RunSummaryBuilder → run_summary is None."""
        # This is expected behavior: the mock judge node returns early
        # before the RunSummaryBuilder is invoked. RunSummary is only
        # built in real (non-mock) runs.
        assert mock_result.get("run_summary") is None

    def test_file_hash_preserved(self, mock_result: dict) -> None:
        assert mock_result.get("file_hash") == "sample_1"

    def test_file_name_preserved(self, mock_result: dict) -> None:
        assert mock_result.get("file_name") == "test.exe"


# ---------------------------------------------------------------------------
# Group 3: Analyst node wiring — load_chunked integration
# ---------------------------------------------------------------------------

class TestAnalystNodeChunkedWiring:
    """Tests that make_analyst_node() correctly uses load_chunked().

    These are 'semi-integration' tests: they use the real node factory but
    replace the container and LLM with mocks. This verifies the wiring
    between the node factory and the chunked loading path without triggering
    real file I/O or LLM calls.
    """

    def _make_mock_container(
        self,
        chunks: list | None = None,
        is_mock: bool = False,
    ) -> MagicMock:
        """Build a mock ServiceContainer that returns configured chunks."""
        from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

        if chunks is None:
            chunks = [
                TextChunk(
                    index=0, total=1,
                    strategy=ChunkStrategy.SLIDING_WINDOW,
                    content="sample analysis data",
                    char_count=20, token_estimate=5,
                    domain="static",
                )
            ]

        container = MagicMock()
        container.is_mock = is_mock
        container.load_chunked.return_value = chunks

        # Mock agent: safe_analyze_isr returns a minimal ISR
        mock_agent = MagicMock()
        mock_isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[],
            dissent_items=[],
            revision_round=0,
        )
        mock_agent.safe_analyze_isr.return_value = mock_isr
        mock_agent.safe_analyze_isr_chunked.return_value = mock_isr
        mock_agent.safe_analyze.return_value = "analysis report"
        container.get_agent.return_value = mock_agent

        return container

    def _make_state(self) -> dict:
        return {"file_hash": "abc123", "file_name": "test.exe"}

    def test_single_chunk_calls_safe_analyze_isr(self) -> None:
        """Single chunk → safe_analyze_isr() called, not chunked path."""
        container = self._make_mock_container()
        node_fn = make_analyst_node("static", container)
        result = node_fn(self._make_state())

        agent = container.get_agent.return_value
        agent.safe_analyze_isr.assert_called_once()
        agent.safe_analyze_isr_chunked.assert_not_called()

        assert "static" in result.get("isr_reports", {})
        assert "static" in result.get("reports", {})

    def test_multi_chunk_calls_safe_analyze_isr_chunked(self) -> None:
        """Multiple chunks → safe_analyze_isr_chunked() called."""
        from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

        chunks = [
            TextChunk(
                index=i, total=3,
                strategy=ChunkStrategy.SLIDING_WINDOW,
                content=f"chunk {i} content",
                char_count=15, token_estimate=4,
                domain="static",
            )
            for i in range(3)
        ]
        container = self._make_mock_container(chunks=chunks)
        node_fn = make_analyst_node("static", container)
        result = node_fn(self._make_state())

        agent = container.get_agent.return_value
        agent.safe_analyze_isr_chunked.assert_called_once()
        agent.safe_analyze_isr.assert_not_called()

        assert "static" in result.get("isr_reports", {})

    def test_node_uses_load_chunked_not_load_data(self) -> None:
        """Analyst node must call container.load_chunked(), not container.load_data()."""
        container = self._make_mock_container()
        node_fn = make_analyst_node("static", container)
        node_fn(self._make_state())

        container.load_chunked.assert_called_once_with("abc123", "static")
        container.load_data.assert_not_called()

    def test_node_returns_error_isr_on_failure(self) -> None:
        """If load_chunked raises, node returns an error ISR without crashing."""
        from maljan.core.exceptions import LLMError

        container = self._make_mock_container()
        container.load_chunked.side_effect = LLMError("loader failed")
        node_fn = make_analyst_node("static", container)
        result = node_fn(self._make_state())

        isr = result.get("isr_reports", {}).get("static")
        assert isr is not None
        assert isr.claims == []
        report = result.get("reports", {}).get("static", "")
        assert "[ERROR]" in report

    def test_mock_mode_bypasses_load_chunked(self) -> None:
        """In mock mode, node returns before calling load_chunked."""
        container = self._make_mock_container(is_mock=True)
        node_fn = make_analyst_node("static", container)
        result = node_fn(self._make_state())

        container.load_chunked.assert_not_called()
        assert "static" in result.get("reports", {})


# ---------------------------------------------------------------------------
# Group 4: Chunked path end-to-end via config
# ---------------------------------------------------------------------------

class TestChunkedConfigPath:
    def test_very_small_chunk_limit_still_produces_verdict(self) -> None:
        """Pipeline completes even with a tiny chunk limit (forces multi-chunk path)."""
        config = Settings(
            negotiation=NegotiationConfig(max_iterations=1),
            chunking=ChunkingConfig(
                max_tokens_per_chunk=1,   # force splitting
                overlap_tokens=0,
                skip_if_fits=False,
            ),
        )
        # In mock mode, analyst nodes return early (before chunking).
        # This test validates that the config flows through without crash.
        app = MaljanApp(config=config, mock=True)
        result = app.run("sample_1")
        assert result["final_decision"] == "Malware"

    def test_chunking_config_respected_by_container(self) -> None:
        """ChunkingConfig passed to Settings is accessible via ServiceContainer."""
        config = Settings(
            chunking=ChunkingConfig(max_tokens_per_chunk=500, overlap_tokens=50)
        )
        app = MaljanApp(config=config, mock=True)
        assert app.container.config.chunking.max_tokens_per_chunk == 500
        assert app.container.config.chunking.overlap_tokens == 50


# ---------------------------------------------------------------------------
# Group 5: Pipeline configuration variants
# ---------------------------------------------------------------------------

class TestPipelineConfigVariants:
    def test_pipeline_with_file_name_none(self) -> None:
        """Pipeline works without file_name (optional parameter)."""
        app = MaljanApp(mock=True)
        result = app.run("sample_1")
        assert result["final_decision"] is not None
        assert result.get("file_name") is None

    def test_multiple_runs_with_same_app_instance(self) -> None:
        """Same MaljanApp instance can run multiple analyses sequentially."""
        app = MaljanApp(mock=True)
        result1 = app.run("sample_1", file_name="first.exe")
        result2 = app.run("sample_1", file_name="second.exe")
        assert result1["final_decision"] is not None
        assert result2["final_decision"] is not None

    def test_pipeline_initial_state_has_all_required_keys(self) -> None:
        """All required state keys are initialized before graph invocation."""
        app = MaljanApp(mock=True)
        result = app.run("sample_1")
        required_keys = [
            "file_hash", "file_name", "reports", "revised_reports",
            "isr_reports", "discussion_history", "sycophancy_detected",
            "confidence_history", "iteration_count", "is_consensus",
            "final_decision", "judge_report", "stix_output", "run_summary",
        ]
        for key in required_keys:
            assert key in result, f"Missing key in final state: '{key}'"
