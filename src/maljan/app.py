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
        # Delegate to async implementation so sandbox submission and graph
        # execution share the same event loop (avoids nested asyncio.run).
        return asyncio.run(self.arun(file_hash, file_name, sample_path))

    async def _submit_to_sandbox(
        self, sample_path: str | None
    ) -> dict[str, Any] | None:
        """Submit sample to sandbox and return normalized report.

        Returns None if no sample_path is provided or if submission fails.
        """
        if not sample_path or self.container.is_mock:
            return None

        from pathlib import Path

        path = Path(sample_path)
        if not path.exists():
            logger.warning("Sample path does not exist: %s", sample_path)
            return None

        try:
            client = self.container.get_sandbox_client()
            logger.info("Submitting sample to sandbox: %s", sample_path)

            # submit_and_wait is available on TriageClient but may not be on
            # all SandboxClient implementations (e.g. MockSandboxClient).
            if hasattr(client, "submit_and_wait"):
                result = await client.submit_and_wait(path)
            else:
                # Fallback: manual submit + wait + fetch for protocol-compliant clients
                task_id = client.submit(sample_path)
                status = client.wait_for_completion(task_id)
                from maljan.loaders.sandbox_client import SubmissionResult
                result = SubmissionResult(
                    task_id=task_id,
                    status=status,
                    report={},
                    error="" if status == "reported" else f"Sandbox status: {status}",
                )

            if result.status in ("reported", "partial") and result.report:
                logger.info(
                    "Sandbox analysis complete: %s tasks, %d signatures, %d TTPs.",
                    len(result.report.get("_triage_raw_tasks", [])),
                    len(result.report.get("signatures", [])),
                    len(result.report.get("ttp_tags", [])),
                )
                return result.report
            logger.warning("Sandbox task ended with status=%s: %s", result.status, result.error)
            return None
        except Exception as exc:
            logger.error("Sandbox submission failed: %s", exc)
            return None

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

        # Phase 2: Submit to sandbox if sample_path is provided
        sandbox_report = await self._submit_to_sandbox(sample_path)

        initial_state: AnalysisState = {
            "file_hash": file_hash,
            "file_name": file_name,
            "sample_path": sample_path,
            "sandbox_report": sandbox_report,
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
