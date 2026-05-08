"""Application facade - the main entry point for running the analysis pipeline.

This is the Composition Root: it wires together the ServiceContainer,
builds the graph, and provides a clean API for the CLI and tests.

The run() method returns a result dict containing:
  - final_decision: Malware / Benign / Suspicious
  - stix_output: STIX 2.1 bundle dict
  - run_summary: Serialized RunSummary dict (observability report)
  - discussion_history, reports, isr_reports, etc.
"""

import asyncio
import time
from typing import Any

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.logger import logger
from maljan.pipeline.builder import build_graph
from maljan.pipeline.state import AnalysisState


class MaljanApp:
    """High-level application facade.

    Usage:
        app = MaljanApp(mock=True)
        result = app.run("sample_hash", file_name="evil.exe")
        print(result["run_summary"])   # observability dict
        print(result["stix_output"])   # STIX 2.1 bundle
    """

    def __init__(
        self,
        config: Settings | None = None,
        mock: bool = False,
        samples_dir: str = "data/samples",
    ) -> None:
        self.config = config or Settings()
        self.container = ServiceContainer(
            config=self.config,
            mock=mock,
            samples_dir=samples_dir,
        )
        self.graph = build_graph(self.container)

    def run(
        self,
        file_hash: str,
        file_name: str | None = None,
        sample_path: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline synchronously.

        Args:
            file_hash: Sample identifier.
            file_name: Optional human-readable name.
            sample_path: Optional path to the original sample file for sandbox submission.

        Returns:
            The final state dict including:
              - final_decision, stix_output, run_summary
              - reports, isr_reports, discussion_history, etc.
        """
        start = time.time()
        logger.info("=" * 60)
        logger.info("MALJAN - Multi-Agent Malware Analysis Pipeline")
        logger.info("=" * 60)
        logger.info(f"Sample: {file_hash} ({file_name or 'unnamed'})")
        logger.info(f"Mode: {'MOCK' if self.container.is_mock else self.config.llm.provider}")
        logger.info(f"Registered agents: {self.container.agent_registry.list_agents()}")
        logger.info(f"Max iterations: {self.config.negotiation.max_iterations}")
        logger.info("-" * 60)

        initial_state: AnalysisState = {
            "file_hash": file_hash,
            "file_name": file_name,
            "sample_path": sample_path,
            "sandbox_report": None,
            "reports": {},
            "revised_reports": {},
            "isr_reports": {},
            "discussion_history": [],
            "sycophancy_detected": False,
            "confidence_history": [],
            "iteration_count": 0,
            "is_consensus": False,
            "final_decision": None,
            "judge_report": None,
            "stix_output": None,
            "run_summary": None,
            "_max_iterations": self.config.negotiation.max_iterations,
        }

        result = asyncio.run(self.graph.ainvoke(initial_state))

        elapsed = time.time() - start
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE (%.1fs)", elapsed)
        logger.info("=" * 60)

        return result

    async def arun(
        self,
        file_hash: str,
        file_name: str | None = None,
        sample_path: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline asynchronously.

        This prevents the need for spinning up separate threads and manually
        managing event loops in async contexts (like ARQ workers), which
        solves the 'Event loop is closed' issue with google-genai.
        """
        start = time.time()
        logger.info("=" * 60)
        logger.info("MALJAN - Multi-Agent Malware Analysis Pipeline")
        logger.info("=" * 60)
        logger.info(f"Sample: {file_hash} ({file_name or 'unnamed'})")
        logger.info(f"Mode: {'MOCK' if self.container.is_mock else self.config.llm.provider}")
        logger.info(f"Registered agents: {self.container.agent_registry.list_agents()}")
        logger.info(f"Max iterations: {self.config.negotiation.max_iterations}")
        logger.info("-" * 60)

        initial_state: AnalysisState = {
            "file_hash": file_hash,
            "file_name": file_name,
            "sample_path": sample_path,
            "sandbox_report": None,
            "reports": {},
            "revised_reports": {},
            "isr_reports": {},
            "discussion_history": [],
            "sycophancy_detected": False,
            "confidence_history": [],
            "iteration_count": 0,
            "is_consensus": False,
            "final_decision": None,
            "judge_report": None,
            "stix_output": None,
            "run_summary": None,
            "_max_iterations": self.config.negotiation.max_iterations,
        }

        result = await self.graph.ainvoke(initial_state)

        elapsed = time.time() - start
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE (%.1fs)", elapsed)
        logger.info("=" * 60)

        return result
