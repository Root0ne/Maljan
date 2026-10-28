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
from typing import Any, cast

from maljan.core.cancellation import bound
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.logger import logger
from maljan.loaders.cape2_client import BODY_SHOWN
from maljan.loaders.sandbox_client import SubmissionResult
from maljan.pipeline.builder import build_graph
from maljan.pipeline.events import EventSink
from maljan.pipeline.state import AnalysisState
from maljan.schemas.sandbox_document import sandbox_document

# How much of a sandbox failure's words the degradation reason carries, the
# cut mark included: room for the client's own prefix and the response body it
# quotes (``loaders.cape2_client.BODY_SHOWN``) twice over, and no more of an
# outside text in the judge's prompt and the report than that.
SANDBOX_FAILURE_CHARS = 2 * BODY_SHOWN


def _remember_the_secrets_of(config: Settings) -> None:
    """Register the secret values ``config`` holds with the scrub, under the ``app`` scope.

    Replaced each time an app is built, so a secret no longer configured is not
    masked by the next one. Never raises: the shape rules still run without it.
    """
    try:
        from maljan.core.settings_catalog import configured_secret_values
        from maljan.pipeline.events import remember_secret_values

        remember_secret_values(configured_secret_values(config), scope="app")
    except Exception as exc:  # noqa: BLE001 — never worth an app
        try:
            from maljan.pipeline.events import secret_registration_failed

            secret_registration_failed("app")
        except Exception:  # noqa: BLE001 — the shape rules still run
            pass
        logger.warning(
            "The configured values were not handed to the scrub (%s).", type(exc).__name__
        )


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
        job_id: str = "",
        analyst_mode: Any = None,
        remember_secrets: bool = True,
        memory_owner: str | None = None,
        ignore_earlier_runs: bool = False,
    ) -> None:
        self.config = config or Settings()
        # The secrets these settings hold are masked by value wherever the
        # scrub runs in this process: on the command line this is the one
        # place that knows them. The worker registers a job's settings itself
        # (``remember_configured_secrets``) and builds its app without this.
        if remember_secrets:
            _remember_the_secrets_of(self.config)
        self.container = ServiceContainer(
            config=self.config,
            mock=mock,
            samples_dir=samples_dir,
            event_sink=event_sink,
            job_id=job_id,
            # Resolved by the caller off its event loop where it has one
            # (``pipeline.analyst_mode.resolve_for``): resolving it names
            # hosts and asks a server for its slot count.
            resolved_mode=analyst_mode,
            # Whose long-term memory the job reads and writes; ``None`` is the
            # unscoped memory (``long_term_memory.recall``).
            memory_owner=memory_owner,
            # Whether the job starts without an earlier run's memory of its
            # sample (``long_term_memory.earlier_case_of``).
            ignore_earlier_runs=ignore_earlier_runs,
        )
        self.graph = build_graph(self.container)
        # What the report node built, with the state it built it from, as soon
        # as the node returned: kept so that a run which fails after the report
        # was built still has it (``_stream_the_graph``). ``None`` until then.
        self.built_report: dict[str, Any] | None = None
        # Where the graph failed, when it did: ``node <name>``, or the step
        # whose writes could not be applied. ``None`` on a run that returned.
        self.failed_step: str | None = None
        # The state after the last complete graph step, kept as each step
        # lands: what a run stopped part-way (a job timeout, the operator's
        # cancel, the worker shutting down) had produced when it stopped. An
        # empty dict until the first step completes.
        self.latest_state: dict[str, Any] = {}
        # The questions this run was asked (``arun``), kept here as well as on
        # the state, so a run stopped before its first graph step still prints
        # each of them (``stopped_run.stopped_state``).
        self.questions: list[str] = []

    async def aclose(self) -> None:
        """Release the container's agents, toolkits and per-job caches.

        The app owns the container, the container owns the agents, and the
        agents own their MCP toolkits — so the release has to start here. Never
        raises: this runs from a ``finally`` around a completed analysis, and
        teardown must not be able to turn a finished run into a failed one.

        The container takes this run's staging directory away as the last thing
        it does, so a caller with no worker behind it — the command line — has
        a teardown that leaves nothing on disk.
        """
        try:
            await self.container.aclose()
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("MaljanApp.aclose failed (non-fatal): %s", exc)

    def remember_the_run(self) -> bool:
        """Store this run's long-term-memory case, once its job has completed.

        The judge builds the case and holds it; a caller that has recorded the
        job as completed calls this. Never raises.
        """
        return self.container.remember_the_run()

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
        static_sample_paths: dict[str, str] | None = None,
        server_sample_paths: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full analysis pipeline synchronously.

        Args:
            file_hash: Sample identifier.
            file_name: Optional human-readable name.
            sample_path: Optional path to the original sample file for sandbox submission.
            static_sample_path: Optional container-visible path the static analyst's
                Ghidra MCP server can read. See ``arun`` for full context.
            static_sample_paths: One container-visible path per static provider
                this job's profile uses, keyed by provider id; the globally
                configured provider's entry is also ``static_sample_path``.
            server_sample_paths: The path each tool server that declares a
                ``sample_mount`` opens the sample at, keyed by server key.

        Returns:
            The final state dict including:
              - final_decision, stix_output, run_summary
              - reports, isr_reports, discussion_history, etc.
        """
        # Delegate to async implementation so sandbox submission and graph
        # execution share the same event loop (avoids nested asyncio.run).
        return asyncio.run(
            self.arun(
                file_hash,
                file_name,
                sample_path,
                static_sample_path,
                static_sample_paths,
                server_sample_paths=server_sample_paths,
            )
        )

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
        from maljan.extractors.sample_identity import detect_file_type, infer_platform

        file_type = "unknown"
        mime_type: str | None = None
        if sample_path:
            try:
                path = Path(sample_path)
                if path.exists() and path.is_file():
                    blob = path.read_bytes()
                    # The routing reads the sample in this process: the run's
                    # isolation part names the worker's own readers.
                    from maljan.analysis.isolation import (
                        WORKER_LABEL,
                        WORKER_SOURCE,
                        note_read_in_worker,
                    )

                    note_read_in_worker(self.container, WORKER_SOURCE, WORKER_LABEL)
                    file_type = detect_file_type(path, blob)
            except OSError as exc:
                logger.warning("_infer_sample_platform: could not read %s (%s)", sample_path, exc)

        # Best-effort MIME from the sandbox file block when we couldn't
        # read the bytes ourselves.
        from maljan.schemas.sandbox_document import place

        target = place(sandbox_report, "target", {})
        if isinstance(target, dict):
            sb_file = target.get("file") if isinstance(target.get("file"), dict) else {}
            mt = sb_file.get("type") if isinstance(sb_file, dict) else None
            if isinstance(mt, str):
                mime_type = mt

        platform = infer_platform(file_type, mime_type, sandbox_report)
        return file_type, platform

    def _poll_budget(self, provider: Any) -> tuple[int | None, int | None]:
        """The poll budget this provider's own config block sets, ``None`` where it sets none.

        Read from the block named by the provider's id (``sandbox.cape2`` for
        CAPE, ``sandbox.triage`` for Triage). A provider with no such block
        (a plugin's, the mock) gets ``None`` for each number, and is then
        handed nothing, so it polls with its own defaults rather than with
        CAPE's detonation timeout.
        """
        block = getattr(self.config.sandbox, str(provider.id), None)
        timeout = getattr(block, "timeout_seconds", None)
        interval = getattr(block, "poll_interval_seconds", None)
        return (
            int(timeout) if timeout is not None else None,
            int(interval) if interval is not None else None,
        )

    def _poll_arguments(self, provider: Any, task_id: str) -> dict[str, int]:
        """The poll numbers to hand ``provider.wait_for_completion``.

        The numbers its own block sets (``_poll_budget``). One it sets none
        for is left out when the provider's method has a default of its own
        for it, so the provider polls by its own rule; the base contract has
        no default, and a provider written to it is given CAPE's number, the
        one thing the call cannot go without.
        """
        import inspect

        timeout, interval = self._poll_budget(provider)
        cape = self.config.sandbox.cape2
        wanted = {
            "timeout_seconds": (timeout, cape.timeout_seconds),
            "poll_interval_seconds": (interval, cape.poll_interval_seconds),
        }
        try:
            params = inspect.signature(provider.wait_for_completion).parameters
        except (TypeError, ValueError):
            params = inspect.Signature().parameters
        out: dict[str, int] = {}
        for name, (own, fallback) in wanted.items():
            if own is not None:
                out[name] = own
            elif name in params and params[name].default is inspect.Parameter.empty:
                out[name] = int(fallback)
            elif name not in params:
                out[name] = int(fallback)
        return out

    def _note_the_reader(self, provider: Any, run: Any) -> None:
        """Which reader produced this job's report, and the signature scale its provider gives."""
        from maljan.core.report_formats import effective_formats
        from maljan.schemas.sandbox_report import reader_of

        self.container.sandbox_normalised = reader_of(run.report)
        try:
            scale = provider.signature_scale(
                run, effective_formats(self.config.sandbox.report_formats)
            )
        except Exception as exc:  # noqa: BLE001 — a scale is a reading aid, never a reason to fail
            logger.warning("Sandbox signature scale unavailable: %s", exc)
            scale = None
        self.container.sandbox_signature_scale = scale.record() if scale is not None else None

    async def _submit_to_sandbox(self, sample_path: str | None) -> dict[str, Any] | None:
        """Submit sample to sandbox and return the neutral report's document.

        The document every consumer reads (``schemas.sandbox_document``), laid
        out from the ``SandboxReport`` the provider's registered reader filled.
        Returns None if no sample_path is provided or if submission fails.
        """
        # Which reader produced this job's report, for the sandbox sections;
        # cleared first so a job with no report never reads the last one's.
        self.container.sandbox_normalised = None
        self.container.sandbox_signature_scale = None
        self.container.sample_uploads = []
        self.container.sandbox_failure = None
        self.container.artefact_fetch_failures = []
        self.container.sandbox_target_claim = None
        if not sample_path or self.container.is_mock:
            return None

        path = Path(sample_path)
        if not path.exists():
            logger.warning("Sample path does not exist: %s", sample_path)
            self._sandbox_failed("the sample file to submit was not found")
            return None

        # Where the submission was when it failed, so a failure says which step
        # it was (an unreachable sandbox, a task that never finished, a report
        # that could not be read) and not only that there was one.
        stage = "choosing the sandbox"
        claim: dict[str, str] | None = None
        try:
            provider = self.container.get_sandbox_provider()
            caps = provider.capabilities
            if not caps.can_submit and caps.accepts_uploaded_report:
                # No detonation: the evidence is already here.
                stage = "reading the attached report"
                try:
                    run = provider.fetch("uploaded")
                except Exception as exc:  # noqa: BLE001 — same degrade contract as a failed submit
                    logger.error("Attached sandbox report unusable: %s", exc)
                    self._sandbox_failed(f"the attached sandbox report is unusable: {exc}")
                    return None
                self._note_the_reader(provider, run)
                return sandbox_document(run.report)
            logger.info("Submitting sample to sandbox: %s", sample_path)

            # Every provider call below is synchronous: the Triage provider
            # drives an ``httpx.Client`` and polls with ``time.sleep``, so
            # awaited bare they stop the worker's event loop — and its
            # heartbeat — for the whole detonation. The provider
            # objects are plain HTTP clients with no loop affinity, so a
            # thread changes nothing but where the blocking happens.
            #
            # The submission is recorded before it is made, as one that did
            # not complete, with the host the provider resolves its submission
            # URL to, and marked submitted once the provider answers: a
            # submission that raised may still have sent the sample, and the
            # run's disclosure block says so rather than nothing. A provider
            # whose submission never leaves the worker records none.
            from maljan.analysis.disclosure import submission_host, upload_record

            stage = "preparing the submission"
            host = submission_host(provider)
            if host is not None:
                self.container.sample_uploads.append(
                    upload_record(provider.id, submitted=False, host=host)
                )
            stage = "submitting the sample"
            task_id = await asyncio.to_thread(provider.submit, str(path))
            if host is not None:
                self.container.sample_uploads[-1] = upload_record(
                    provider.id, submitted=True, host=host
                )
            # Thread the active provider's own completion timeout + poll
            # interval into the poll loop (see ``_poll_budget``). Without
            # this the ABC's 300s default — or another provider's config read
            # from the wrong block — was used regardless of which sandbox was
            # configured, and a real CAPE detonation (win10 guest run alone is
            # ~280s + processing) timed out before the report was ready —
            # silently degrading every run to static-only.
            stage = "waiting for the analysis"
            budget = self._poll_arguments(provider, task_id)
            # The job's sandbox deadline: the poll's own budget, from when the
            # wait began. An artefact fetched after the report is retried only
            # inside it (``_fetch_capture``).
            sandbox_deadline = time.monotonic() + float(
                budget.get("timeout_seconds", self.config.sandbox.cape2.timeout_seconds)
            )
            status = await asyncio.to_thread(
                lambda: provider.wait_for_completion(task_id, **budget)
            )
            if status == "reported":
                stage = "fetching the report"
                run = await asyncio.to_thread(provider.fetch, task_id)
                self._note_the_reader(provider, run)
                if not (run.report.synthetic or run.report.recorded_fixture):
                    # The target the sandbox says it ran, for the worker to
                    # compare with the sample, kept once the report is used
                    # (below); a stand-in or a recorded fixture ran nothing
                    # during this run and names none.
                    claim = {
                        "provider": str(provider.id),
                        "task_id": str(run.task_id),
                        "sha256": str(run.report.target.sha256 or ""),
                    }
                result = SubmissionResult(
                    task_id=run.task_id,
                    sample_sha256=run.sample_sha256,
                    sample_name=run.sample_name,
                    status=run.status,
                    report=sandbox_document(run.report),
                    error=run.error,
                    normalized=run.report,
                )
                # Pull the raw PCAP alongside the JSON report so the network
                # analyst can deep-inspect the capture with its local PCAP
                # MCP (per-packet beaconing / tunnelling / TLS-SNI) — the
                # structured ``network`` block can't express that. Best
                # effort: a missing/failed PCAP just leaves the analyst on
                # the structured IOCs. A capture offered and not fetched is
                # never lost silently: it is kept as a degradation reason
                # that names why (``ArtefactFetchFailed``), apart from a
                # sandbox that offers none. Only providers that declare it.
                if caps.can_fetch_pcap and isinstance(result.report, dict):
                    from maljan.providers.errors import PACKET_CAPTURE, ArtefactFetchFailed
                    from maljan.tools import staging

                    pcap_path: str | None = None
                    try:
                        # This job's own capture directory, inside its staging
                        # directory: named as a root for this job's sidecars
                        # and for no later one, removed with everything else
                        # the job staged, and swept by the same TTL. A capture
                        # is a full record of the detonation — the operator's
                        # addressing, the C2 exchange, whatever the malware
                        # sent in the clear — and ``pcap_path`` is a qualified
                        # argument the *model* writes, so a directory shared
                        # between jobs was one instruction inside a sample away
                        # from an earlier job's traffic.
                        pcap_dir = staging.open_capture_dir(self.container.job_key())
                        # Off the event loop, as every other sandbox call is:
                        # a retried fetch waits, and the worker's heartbeat,
                        # cancel poller and job clock run on this loop.
                        pcap_path = await asyncio.to_thread(
                            self._fetch_capture, provider, task_id, str(pcap_dir), sandbox_deadline
                        )
                    except ArtefactFetchFailed as exc:
                        # Logged with its cause where it failed.
                        self.container.artefact_fetch_failures.append(exc.record())
                    except Exception as exc:
                        logger.warning("PCAP fetch failed (non-fatal): %s", type(exc).__name__)
                        self.container.artefact_fetch_failures.append(
                            ArtefactFetchFailed(PACKET_CAPTURE, type(exc).__name__).record()
                        )
                    if pcap_path:
                        try:
                            staging.make_private(Path(pcap_path))
                            net = result.report.setdefault("network", {})
                            if not isinstance(net, dict):
                                raise TypeError("the report's network section is not a mapping")
                            net["pcap_local_path"] = pcap_path
                        except Exception as exc:
                            # Fetched, and then not attached: no reader will
                            # open it, so it goes, and the run says which step
                            # lost it.
                            logger.warning("PCAP attach failed (non-fatal): %s", type(exc).__name__)
                            Path(pcap_path).unlink(missing_ok=True)
                            self.container.artefact_fetch_failures.append(
                                ArtefactFetchFailed(
                                    PACKET_CAPTURE, f"attach {type(exc).__name__}"
                                ).record()
                            )
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
                    self._sandbox_failed(
                        f"the sandbox report is a {type(result.report).__name__}, not a document"
                    )
                    return None
                logger.info(
                    "Sandbox analysis complete: %d signatures, %d TTPs.",
                    len(result.report.get("signatures", [])),
                    len(result.report.get("ttp_tags", [])),
                )
                self.container.sandbox_target_claim = claim
                return result.report  # type: ignore[no-any-return]
            logger.warning("Sandbox task ended with status=%s: %s", result.status, result.error)
            ended = f"sandbox task {result.task_id} ended with status {result.status!r}"
            if result.status in ("reported", "partial"):
                ended += " and no report"
            elif result.error and result.error != f"Sandbox status: {result.status}":
                ended += f": {result.error}"
            self._sandbox_failed(ended)
            return None
        except Exception as exc:
            logger.error("Sandbox submission failed: %s", exc)
            self._sandbox_failed(f"{stage}: {str(exc) or type(exc).__name__}")
            return None

    def _fetch_capture(
        self, provider: Any, task_id: str, dest_dir: str, deadline: float
    ) -> str | None:
        """``provider.fetch_pcap`` under the job's bounds; run in a worker thread.

        Its retries stop at ``deadline`` (``time.monotonic``) and wait on the
        job's cancellation, so a cancel ends a wait at once and no try follows
        it, and each try is tracked by it, so a cancel ends the request in
        flight too (``providers.sandbox.triage.FetchBudget``).
        """
        from maljan.providers.sandbox.triage import FetchBudget, fetch_budget

        cancellation = self.container.cancellation
        bounds = FetchBudget(
            deadline=deadline,
            now=time.monotonic,
            sleep=cancellation.wait,
            cancelled=lambda: cancellation.is_cancelled,
            track=cancellation.track,
        )
        with fetch_budget(bounds):
            return cast("str | None", provider.fetch_pcap(task_id, dest_dir))

    def _sandbox_failed(self, reason: str) -> None:
        """Keep why this job has no sandbox report, for its degradation reason.

        The words are the sandbox's or an exception's, and they reach the
        judge's prompt and the report: a URL loses its credentials
        (``redact_url``), every line break becomes a space so the text cannot
        start a line of its own, and it is cut to ``SANDBOX_FAILURE_CHARS``
        with the cut mark. The degradation reason then quotes it as one value
        (``pipeline.nodes.sandbox_degradation_reason``).
        """
        from maljan.core.settings_overrides import redact_url
        from maljan.utils.marked_cut import marked_cut

        one_line = " ".join(redact_url(str(reason)).splitlines())
        self.container.sandbox_failure = marked_cut(one_line, SANDBOX_FAILURE_CHARS)

    async def arun(
        self,
        file_hash: str,
        file_name: str | None = None,
        sample_path: str | None = None,
        static_sample_path: str | None = None,
        static_sample_paths: dict[str, str] | None = None,
        started_at: float | None = None,
        server_sample_paths: dict[str, str] | None = None,
        questions: list[str] | None = None,
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
            static_sample_paths: One container-visible path per static provider
                this job's profile uses, keyed by provider id; the globally
                configured provider's entry is also ``static_sample_path``.
            server_sample_paths: The path each tool server that declares a
                ``sample_mount`` opens the sample at, keyed by server key: the
                worker's copy under that mount, which an agent bound to the
                server is held to (``agents.composition``).
            started_at: When the caller's own clock says this run began, as a
                Unix timestamp. The worker starts counting before the sample
                reaches this method, and the report's elapsed time is the
                figure a reader compares against the job's duration, so the two
                are measured from the same instant. Absent, this call's entry
                is the start.
            questions: The questions the analyst asked of this run, which the
                report answers in a fixed vocabulary
                (``reporting.question_round``). None or empty asks nothing,
                and the report is the one a run without them has.

        This prevents the need for spinning up separate threads and manually
        managing event loops in async contexts (like ARQ workers), which
        solves the 'Event loop is closed' issue with google-genai.
        """
        start = float(started_at) if started_at else time.time()
        self.questions = list(questions or [])
        logger.info("=" * 60)
        logger.info("MALJAN - Multi-Agent Malware Analysis Pipeline")
        logger.info("=" * 60)
        logger.info("Sample: %s (%s)", file_hash, file_name or "unnamed")
        logger.info("Mode: %s", "MOCK" if self.container.is_mock else self.config.llm.provider)
        logger.info("Analysts: %s", self.container.analyst_keys())
        logger.info("Max iterations: %d", self.config.negotiation.max_iterations)
        logger.info("-" * 60)

        # Where this run's sample is, for the tool sidecars. They read a path
        # argument only inside the roots they were given, and the directory
        # holding the sample the caller named is one of them: the caller is
        # the operator or the worker, never a model. A run with no sample path
        # names nothing, and the sidecars read only what they staged.
        if sample_path:
            from maljan.tools.roots import add_sample_root

            add_sample_root(Path(sample_path).parent)

        # How long a failed ATT&CK index build is believed. Set here, before
        # the pipeline opens the sidecar registry, because the knowledge
        # sidecar is the process where that build actually happens and it
        # reads its environment rather than the settings store. The in-process
        # module is told directly, for the lookups this worker makes itself.

        # Everything from here runs under this job's cancellation: the graph's
        # nodes check it on the way in, and every model call the job makes —
        # in a node, on the agent loop, in a thread started from either —
        # checks it before it sends anything (``core.cancellation``).
        with bound(self.container.cancellation):
            result = await self._run_the_pipeline(
                start,
                file_hash=file_hash,
                file_name=file_name,
                sample_path=sample_path,
                static_sample_path=static_sample_path,
                static_sample_paths=static_sample_paths,
                server_sample_paths=server_sample_paths,
                questions=questions,
            )

        elapsed = time.time() - start
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETE (%.1fs)", elapsed)
        logger.info("=" * 60)

        return result

    async def _run_the_pipeline(
        self,
        start: float,
        *,
        file_hash: str,
        file_name: str | None,
        sample_path: str | None,
        static_sample_path: str | None,
        static_sample_paths: dict[str, str] | None,
        server_sample_paths: dict[str, str] | None = None,
        questions: list[str] | None = None,
    ) -> dict[str, Any]:
        """The sandbox submission and the graph, for ``arun``."""
        # Submit to sandbox if sample_path is provided
        sandbox_report = await self._submit_to_sandbox(sample_path)

        # Compute file_type + canonical platform up front. It routes the
        # analysis (which prompt fragment an analyst is given, which rules the
        # scanning tools keep), fills the report's identity block, and is what
        # the FP linter checks a technique's platform against. The detector is
        # deterministic and cheap, so it runs here even for a sample that could
        # not be read off disk — the platform then stays "unknown", which every
        # consumer treats as "do not filter on this".
        file_type, platform = self._infer_sample_platform(sample_path, sandbox_report)
        logger.info("Sample platform inferred: file_type=%s platform=%s", file_type, platform)
        # The analysts are built lazily by the container, from nodes that do
        # not all carry the graph state, so the routing answer is handed to the
        # container as well: it is what their prompts' format fragment is
        # assembled from.
        self.container.sample_format = (file_type, platform)
        # Same reason, same place: ``ToolRef(kind="sandbox")`` resolves to
        # tools over this report, and resolution happens off the graph state.
        self.container.sandbox_report = sandbox_report
        self.container.sample_path = sample_path
        self.container.sample_sha256 = file_hash
        self.container.server_sample_paths = dict(server_sample_paths or {})
        self.container.static_sample_paths = {
            **({"": static_sample_path} if static_sample_path else {}),
            **dict(static_sample_paths or {}),
        }
        # The paths files were handed to servers at belong to one run.
        self.container.artefact_paths = []

        initial_state: AnalysisState = {
            "file_hash": file_hash,
            "file_name": file_name,
            "run_started_at": start,
            "sample_path": sample_path,
            "static_sample_path": static_sample_path,
            "static_sample_paths": dict(static_sample_paths or {}),
            "stage_results": {},
            "remote_sample_paths": {},
            "sandbox_report": sandbox_report,
            "file_type": file_type,
            "platform": platform,
            "reports": {},
            "revised_reports": {},
            "isr_reports": {},
            "evidence_ledger": [],
            "tool_evidence": {},
            "discussion_history": [],
            "sycophancy_detected": False,
            "confidence_history": [],
            "iteration_count": 0,
            "is_consensus": False,
            "consensus_applicable": True,
            "final_decision": None,
            "judge_report": None,
            "stix_output": None,
            "stix_labels": None,
            "stix_written": None,
            "run_summary": None,
            "malware_report": None,
            "malware_report_markdown": None,
            "stix_bundle_extended": None,
            "report_error": None,
            # No verdict has been written by anything yet, least of all by
            # this pipeline standing in for a judge that did not answer.
            "verdict_fallback": None,
            "degraded_mode": False,
            "degradation_reasons": [],
            "operator_choices": [],
            # F10: declared AnalysisState channels, populated later by the
            # attribution/RAG nodes. Must be initialised so the TypedDict is
            # complete (and the LangGraph channels exist from the first step).
            "function_hash_matches": [],
            "family_rag_candidates": [],
            "validation_findings": {},
            "validation_retries": 0,
            "validation_fed_back": {},
            "revision_replacements": [],
            "revision_rounds": [],
            "debate_starts": {},
            "dropped_claims": [],
            "validation_not_run": [],
            "validation_unparsed_answers": [],
            "triage_facts": {},
            "analyst_questions": list(questions or []),
            "nudge_retry_modes": {},
            "budget_records": {},
        }

        return await self._stream_the_graph(initial_state)

    async def _stream_the_graph(self, initial_state: AnalysisState) -> dict[str, Any]:
        """Run the graph, watching each node's output as it lands.

        The final state is the one ``ainvoke`` returns: ``ainvoke`` is this
        same stream in the same two modes with the same output keys, keeping
        the last ``values`` chunk. What streaming adds is the ``updates``
        chunks, one per node as it returns. When the report node returns a
        report it is kept on ``built_report``, merged into the state it was
        built from through the graph's own reducers, so a later step that
        raises — including LangGraph refusing the writes of the report's own
        step — no longer takes a finished report down with it. The graph has
        no checkpointer, and an ``ainvoke`` that raises returns nothing.
        """
        from langgraph.channels.binop import BinaryOperatorAggregate

        from maljan.pipeline.builder import FAILED_NODE_ATTR
        from maljan.pipeline.topology import REPORT_NODE

        self.built_report = None
        self.failed_step = None
        self.latest_state = {}
        latest: dict[str, Any] = {}
        # The nodes whose output arrived since the last complete step.
        step: list[str] = []
        try:
            async for mode, payload in self.graph.astream(
                initial_state,
                stream_mode=["updates", "values"],
                output_keys=self.graph.output_channels,
            ):
                if mode == "values":
                    latest = cast("dict[str, Any]", payload)
                    self.latest_state = latest
                    step = []
                    continue
                updates = payload if isinstance(payload, dict) else {}
                for node, update in updates.items():
                    step.append(str(node))
                    if node != REPORT_NODE or not isinstance(update, dict):
                        continue
                    if not update.get("malware_report"):
                        continue
                    # The state the report was built from is the last complete
                    # step, and only the report's own update is merged into it.
                    # With every stage joined on all its upstream stages
                    # (``pipeline.builder``), the report runs after the verdict
                    # stage and nothing a team declares runs beside it; a node
                    # of the same step would not be what the report read.
                    built = dict(latest)
                    for key, value in update.items():
                        channel = self.graph.channels.get(key)
                        if isinstance(channel, BinaryOperatorAggregate) and key in built:
                            built[key] = channel.operator(built[key], value)
                        else:
                            built[key] = value
                    self.built_report = built
        except Exception as exc:
            node = getattr(exc, FAILED_NODE_ATTR, None)
            if node:
                self.failed_step = f"node {node}"
            elif step:
                self.failed_step = f"the graph step of nodes {', '.join(step)}"
            else:
                self.failed_step = "the graph"
            raise
        return latest
