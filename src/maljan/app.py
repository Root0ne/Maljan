"""Application facade - the main entry point for running the analysis pipeline.

This is the Composition Root: it wires together the ServiceContainer,
builds the graph, and provides a clean API for the CLI and tests.

The run() method returns a result dict containing:
  - final_decision: Malware / Benign / Suspicious
  - stix_output: STIX 2.1 bundle dict
  - run_summary: Serialized RunSummary dict (observability report)
  - discussion_history, reports, isr_reports, etc.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.logger import logger
from maljan.loaders.sandbox_client import SubmissionResult
from maljan.pipeline.builder import build_graph
from maljan.pipeline.events import EventSink
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
        event_sink: EventSink | None = None,
    ) -> None:
        self.config = config or Settings()
        self.container = ServiceContainer(
            config=self.config,
            mock=mock,
            samples_dir=samples_dir,
            event_sink=event_sink,
        )
        self.graph = build_graph(self.container)

    async def aclose(self) -> None:
        """Release the container's agents, toolkits and per-job caches.

        The app owns the container, the container owns the agents, and the
        agents own their MCP toolkits — so the release has to start here. Never
        raises: this runs from a ``finally`` around a completed analysis, and
        teardown must not be able to turn a finished run into a failed one.
        """
        try:
            await self.container.aclose()
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("MaljanApp.aclose failed (non-fatal): %s", exc)

    async def __aenter__(self) -> MaljanApp:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def run(
        self,
        file_hash: str,
        file_name: str | None = None,
        sample_path: str | None = None,
        static_sample_path: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline synchronously.

        Args:
            file_hash: Sample identifier.
            file_name: Optional human-readable name.
            sample_path: Optional path to the original sample file for sandbox submission.
            static_sample_path: Optional container-visible path the static analyst's
                Ghidra MCP server can read. See ``arun`` for full context.

        Returns:
            The final state dict including:
              - final_decision, stix_output, run_summary
              - reports, isr_reports, discussion_history, etc.
        """
        # Delegate to async implementation so sandbox submission and graph
        # execution share the same event loop (avoids nested asyncio.run).
        return asyncio.run(self.arun(file_hash, file_name, sample_path, static_sample_path))

    def _infer_sample_platform(
        self,
        sample_path: str | None,
        sandbox_report: dict[str, Any] | None,
    ) -> tuple[str, str]:
        """Compute ``(file_type, platform)`` for the pipeline state.

        Thin shim over the sample-identity extractor so the bootstrap
        in ``arun`` doesn't have to know about magic-byte parsing or
        sandbox-OS fallback. Returns ``("unknown", "unknown")`` when the
        sample bytes are unreachable AND the sandbox didn't disambiguate.
        """
        from maljan.extractors.sample_identity import _detect_file_type, _infer_platform

        file_type = "unknown"
        mime_type: str | None = None
        if sample_path:
            try:
                path = Path(sample_path)
                if path.exists() and path.is_file():
                    blob = path.read_bytes()
                    file_type = _detect_file_type(path, blob)
            except OSError as exc:
                logger.warning("_infer_sample_platform: could not read %s (%s)", sample_path, exc)

        # Best-effort MIME from the sandbox file block when we couldn't
        # read the bytes ourselves.
        target = (sandbox_report or {}).get("target", {})
        if isinstance(target, dict):
            sb_file = target.get("file") if isinstance(target.get("file"), dict) else {}
            mt = sb_file.get("type") if isinstance(sb_file, dict) else None
            if isinstance(mt, str):
                mime_type = mt

        platform = _infer_platform(file_type, mime_type, sandbox_report)
        return file_type, platform

    async def _submit_to_sandbox(self, sample_path: str | None) -> dict[str, Any] | None:
        """Submit sample to sandbox and return normalized report.

        Returns None if no sample_path is provided or if submission fails.
        """
        if not sample_path or self.container.is_mock:
            return None

        path = Path(sample_path)
        if not path.exists():
            logger.warning("Sample path does not exist: %s", sample_path)
            return None

        try:
            client = self.container.get_sandbox_client()
            provider = self.container.get_sandbox_provider()
            caps = provider.capabilities
            if not caps.can_submit and caps.accepts_uploaded_report:
                # No detonation: the evidence is already here.
                try:
                    run = provider.fetch("uploaded")
                except Exception as exc:  # noqa: BLE001 — same degrade contract as a failed submit
                    logger.error("Attached sandbox report unusable: %s", exc)
                    return None
                from maljan.providers.cape_view import to_cape_shaped_dict

                return to_cape_shaped_dict(run.report)
            logger.info("Submitting sample to sandbox: %s", sample_path)

            # ``submit_and_wait`` is an optional convenience method some
            # SandboxClient implementations expose; fall back to the
            # Protocol triad (submit + wait + fetch_report) when missing.
            if hasattr(client, "submit_and_wait"):
                result = await client.submit_and_wait(path)
            else:
                task_id = client.submit(sample_path)
                # Thread the configured completion timeout + poll interval
                # (SANDBOX__CAPE2_TIMEOUT_SECONDS / _POLL_INTERVAL_SECONDS)
                # into the poll loop. Without this the client's 300s default
                # was used regardless of config, and a real CAPE detonation
                # (win10 guest run alone is ~280s + processing) timed out
                # before the report was ready — silently degrading every run
                # to static-only. All SandboxClient impls share this signature.
                status = client.wait_for_completion(
                    task_id,
                    timeout_seconds=self.config.sandbox.cape2.timeout_seconds,
                    poll_interval_seconds=self.config.sandbox.cape2.poll_interval_seconds,
                )
                if status == "reported":
                    result = client.fetch_report(task_id)
                    # Pull the raw PCAP alongside the JSON report so the network
                    # analyst can deep-inspect the capture with its local PCAP
                    # MCP (per-packet beaconing / tunnelling / TLS-SNI) — the
                    # structured ``network`` block can't express that. Best
                    # effort: a missing/failed PCAP just leaves the analyst on
                    # the structured IOCs. Only CAPEv2Client exposes fetch_pcap.
                    if hasattr(client, "fetch_pcap") and isinstance(result.report, dict):
                        try:
                            import tempfile

                            pcap_dir = Path(tempfile.gettempdir()) / "maljan-cape-pcap"
                            pcap_path = client.fetch_pcap(task_id, pcap_dir)
                            if pcap_path:
                                net = result.report.setdefault("network", {})
                                if isinstance(net, dict):
                                    net["pcap_local_path"] = pcap_path
                        except Exception as exc:
                            logger.warning("PCAP fetch/attach failed (non-fatal): %s", exc)
                else:
                    result = SubmissionResult(
                        task_id=task_id,
                        status=status,
                        report={},
                        error=f"Sandbox status: {status}",
                    )

            if result.status in ("reported", "partial") and result.report:
                if not isinstance(result.report, dict):
                    logger.warning(
                        "Sandbox returned success status but report is not a dict (type=%s). "
                        "Treating as failure.",
                        type(result.report).__name__,
                    )
                    return None
                logger.info(
                    "Sandbox analysis complete: %d signatures, %d TTPs.",
                    len(result.report.get("signatures", [])),
                    len(result.report.get("ttp_tags", [])),
                )
                return result.report  # type: ignore[no-any-return]
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
        static_sample_path: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline asynchronously.

        Args:
            file_hash: Sample identifier (sha256).
            file_name: Optional human-readable name.
            sample_path: Optional host path to the original sample file for
                sandbox submission (CAPE upload).
            static_sample_path: Optional container-visible path the static
                analyst's Ghidra MCP server can read. Worker on the host
                writes the sample into ``data/samples/<sha256><ext>`` (bound
                into the Ghidra container at ``/data/samples/``); the
                analyst node then asks the LLM to call ``load_program(file=
                static_sample_path)``. ``None`` falls back to the legacy
                metadata-only prompt where the LLM had to guess the path
                and timed out.

        This prevents the need for spinning up separate threads and manually
        managing event loops in async contexts (like ARQ workers), which
        solves the 'Event loop is closed' issue with google-genai.
        """
        start = time.time()
        logger.info("=" * 60)
        logger.info("MALJAN - Multi-Agent Malware Analysis Pipeline")
        logger.info("=" * 60)
        logger.info("Sample: %s (%s)", file_hash, file_name or "unnamed")
        logger.info("Mode: %s", "MOCK" if self.container.is_mock else self.config.llm.provider)
        logger.info("Registered agents: %s", self.container.agent_registry.list_agents())
        logger.info("Max iterations: %d", self.config.negotiation.max_iterations)
        logger.info("-" * 60)

        # OS-support scope (2026-06-02): Windows + Linux only. Reject a
        # definitely-foreign sample (a non-Win/Linux executable format) up
        # front — before any sandbox submission, so no run is wasted — rather
        # than routing it to an unsupported sandbox. Magic-byte based, so a
        # legitimate Win/Linux sample is never blocked.
        from maljan.core.exceptions import UnsupportedSampleError
        from maljan.extractors.sample_identity import unsupported_os_reason

        unsupported = unsupported_os_reason(sample_path)
        if unsupported:
            logger.warning("Rejecting unsupported-OS sample (%s): %s", unsupported, sample_path)
            raise UnsupportedSampleError(
                f"Unsupported sample OS: {unsupported}. Only Windows and Linux are supported."
            )

        # Phase 2: Submit to sandbox if sample_path is provided
        sandbox_report = await self._submit_to_sandbox(sample_path)

        # Wave 4 (2026-05-28): compute file_type + canonical platform up
        # front so the judge node's Sigma/YARA scanners + TTP cascade can
        # filter platform-incompatible rules. Without this the pipeline is
        # platform-blind and yields cross-OS FPs (e.g. a Windows-only rule
        # firing against a Linux sample). The detector is deterministic +
        # cheap so we just run it here, even on samples we couldn't read off
        # disk (platform stays "unknown", which the cascade treats as
        # fall-open).
        file_type, platform = self._infer_sample_platform(sample_path, sandbox_report)
        logger.info("Sample platform inferred: file_type=%s platform=%s", file_type, platform)

        initial_state: AnalysisState = {
            "file_hash": file_hash,
            "file_name": file_name,
            "sample_path": sample_path,
            "static_sample_path": static_sample_path,
            "sandbox_report": sandbox_report,
            "file_type": file_type,
            "platform": platform,
            "reports": {},
            "revised_reports": {},
            "isr_reports": {},
            "tool_evidence": {},
            "discussion_history": [],
            "sycophancy_detected": False,
            "confidence_history": [],
            "iteration_count": 0,
            "is_consensus": False,
            "final_decision": None,
            "judge_report": None,
            "stix_output": None,
            "run_summary": None,
            "malware_report": None,
            "malware_report_markdown": None,
            "stix_bundle_extended": None,
            "report_error": None,
            "degraded_mode": False,
            "degradation_reasons": [],
            # F10: declared AnalysisState channels, populated later by the
            # attribution/RAG nodes. Must be initialised so the TypedDict is
            # complete (and the LangGraph channels exist from the first step).
            "function_hash_matches": [],
            "family_rag_candidates": [],
            "attck_case_candidates": [],
            "tool_artifact_matches": [],
        }

        result = await self.graph.ainvoke(initial_state)

        elapsed = time.time() - start
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE (%.1fs)", elapsed)
        logger.info("=" * 60)

        return result
