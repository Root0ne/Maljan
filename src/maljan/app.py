"""Application facade - the main entry point for running the analysis pipeline.

This is the Composition Root: it wires together the ServiceContainer,
builds the graph, and provides a clean API for the CLI and tests.
"""

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
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline synchronously.

        Args:
            file_hash: Sample identifier.
            file_name: Optional human-readable name.

        Returns:
            The final state dict with verdict, reports, and STIX output.
        """
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
            "reports": {},
            "revised_reports": {},
            "discussion_history": [],
            "iteration_count": 0,
            "is_consensus": False,
            "final_decision": None,
            "judge_report": None,
            "stix_output": None,
        }

        result = self.graph.invoke(initial_state)

        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("=" * 60)

        return result
