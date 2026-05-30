"""Generic node factories for the LangGraph pipeline.

Each factory returns a node function bound to a specific agent name and the
shared ServiceContainer. The factories work with any agent in the registry —
no per-agent branching exists.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.analysis.schema_pruner import infer_malware_category
from maljan.analysis.ttp_cascade import TTPCascadeEngine
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.memory.long_term_memory import build_stored_case
from maljan.pipeline.state import AgentArgument, AnalysisState
from maljan.pipeline.sycophancy_detector import build_revision_directive, detect_sycophancy
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _empty_isr(agent_name: str, revision_round: int = 0) -> AgentISR:
    """Build an empty placeholder ISR (e.g. for mock or error paths)."""
    return AgentISR(
        agent_id=agent_name,
        domain=agent_name,
        claims=[],
        dissent_items=[],
        revision_round=revision_round,
    )


def _augment_static_chunks_with_path(chunks: list, state: AnalysisState) -> list:
    """Inject the container-visible sample path into the static analyst's chunks.

    Wave 6 (2026-05-28, GHIDRA-DELIVERY-01). The static analyst's data
    surface is a JSON-stringified ``target`` block from the sandbox report
    (or a raw chunk when no sandbox ran). Before Wave 6 the chunk only
    carried ``{sha256, md5, name, size}`` — there was no way for the LLM
    to know which path to hand ``load_program``, so it either guessed
    (always wrong, since the file lived in the host tempdir invisible to
    the Ghidra container) or skipped the call entirely. We now splice
    ``analysis_file_path`` into the JSON when the worker recorded a
    container-visible mirror via ``state['static_sample_path']``.

    The chunk objects are immutable dataclasses; rebuild with the same
    chunker so downstream code (token budget, chunk_text) keeps working.
    Best-effort: if the chunk content isn't valid JSON, return chunks
    unchanged — the static analyst's own placeholder guard handles the
    "no path, no analysis" path.
    """
    import json

    static_path = state.get("static_sample_path")
    if not static_path or not chunks:
        return chunks

    head = chunks[0]
    try:
        parsed = json.loads(head.content)
    except (json.JSONDecodeError, ValueError):
        return chunks
    if not isinstance(parsed, dict):
        return chunks

    parsed["analysis_file_path"] = static_path
    new_content = json.dumps(parsed, indent=2, default=str)

    import dataclasses as _dc

    try:
        rebuilt = _dc.replace(
            head,
            content=new_content,
            char_count=len(new_content),
            token_estimate=len(new_content) // 4,
        )
    except TypeError:
        # Not a dataclass (e.g. a future chunk type) — give up gracefully
        # rather than crashing the analyst node over a presentation detail.
        return chunks
    return [rebuilt, *chunks[1:]]


def _decide_from_bundle(bundle: Bundle) -> str:
    """Map a final STIX bundle to a high-level verdict.

    Heuristic:
      * a ``malware`` object marks the sample malicious.
      * an ``indicator``/``attack-pattern``/``relationship`` set with no
        ``malware`` object but suspicious confidence is "Suspicious".
      * an explicitly empty findings set (no indicators, no attack patterns,
        no malware) maps to "Benign".
    """
    has_malware = False
    has_suspicious_indicator = False
    for obj in bundle.objects:
        obj_type = getattr(obj, "type", "")
        if obj_type == "malware":
            has_malware = True
            break
        if obj_type in {"indicator", "attack-pattern", "relationship"}:
            has_suspicious_indicator = True

    if has_malware:
        return "Malware"
    if has_suspicious_indicator:
        return "Suspicious"
    return "Benign"


# ---------------------------------------------------------------------------
# Analyst node
# ---------------------------------------------------------------------------


def make_analyst_node(
    agent_name: str,
    container: ServiceContainer,
) -> Any:
    """Factory: creates a LangGraph node function for the given agent."""

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            return {
                "reports": {agent_name: f"MOCK: {agent_name} analysis complete."},
                "isr_reports": {agent_name: _empty_isr(agent_name)},
            }

        try:
            agent = container.get_agent(agent_name)

            sandbox_report = state.get("sandbox_report")
            if sandbox_report:
                chunks = container.load_sandbox_data_for_agent(agent_name, sandbox_report)
                logger.info(
                    "Agent '%s': using sandbox report data (%d chunks).",
                    agent_name,
                    len(chunks),
                )
            else:
                chunks = container.load_chunked(state["file_hash"], agent_name)

            # Wave 6 (2026-05-28, GHIDRA-DELIVERY-01): the static analyst
            # needs to know the container-visible path to call
            # ``load_program(file=...)``. Inject it into the chunk's JSON
            # under ``analysis_file_path`` so the existing chunk-text flow
            # carries the path into the LLM prompt without a new state hop.
            if agent_name == "static":
                chunks = _augment_static_chunks_with_path(chunks, state)

            if not chunks:
                # Wave 9 (2026-05-29): the 2026-05-29 Linux ELF audit
                # found that an ELF sample with no PCAP / Triage network
                # trace caused the network analyst to fail-hard with an
                # AnalystError ([ERROR] prefix), which then routed into
                # ``failed_analysts`` and forced ``degraded_mode=true``.
                # For analysts whose absence of input data is normal (a
                # PE without dynamic, or a Linux ELF without PCAP), this
                # is graceful degradation, not failure — emit a [WARN]
                # report with an empty ISR so the rest of the pipeline
                # treats the analyst as "absent" rather than "broken".
                logger.info(
                    "Agent '%s': no data chunks available — emitting empty ISR "
                    "as graceful degradation (Wave 9 no-data path).",
                    agent_name,
                )
                return {
                    "reports": {
                        agent_name: (
                            f"[WARN] {agent_name}: no {agent_name} data available "
                            "for this sample — analyst skipped."
                        )
                    },
                    "isr_reports": {agent_name: _empty_isr(agent_name)},
                }

            if len(chunks) == 1:
                isr = agent.safe_analyze_isr(chunks[0].content)
                fallback_text = chunks[0].content
            else:
                logger.info(
                    "Agent '%s': processing %d chunks for sample '%s'.",
                    agent_name,
                    len(chunks),
                    state["file_hash"],
                )
                isr = agent.safe_analyze_isr_chunked(chunks)
                # Multi-chunk: never re-run analyze() on a single chunk as a
                # fallback — that would silently drop the rest of the sample.
                fallback_text = ""

            if isr.claims:
                report = isr.to_text_summary()
            elif fallback_text:
                report = agent.safe_analyze(fallback_text)
            else:
                report = (
                    f"[WARN] {agent_name}: ISR produced no claims (multi-chunk fallback empty)."
                )

            return {
                "reports": {agent_name: report},
                "isr_reports": {agent_name: isr},
            }
        except (AnalystError, LLMError) as e:
            # OPS-ANALYST-ERROR-TRACKING-01 + OBS-STRUCTURED-LOGS-MISSING-FIELDS-01
            # (audit 2026-05-19): structured error event so Loki/Promtail
            # can aggregate ``event_type=analyst_error`` instead of regex-
            # scanning free-text. ``sample_hash`` is short-fingerprinted so
            # the log line stays human-skim-friendly.
            logger.error(
                "%s analysis failed: %s",
                agent_name,
                e,
                extra={
                    "event_type": "analyst_error",
                    "agent": agent_name,
                    "sample_hash": (state.get("file_hash") or "")[:16],
                    "error_type": type(e).__name__,
                },
            )
            return {
                "reports": {agent_name: f"[ERROR] {agent_name} analysis failed: {e}"},
                "isr_reports": {agent_name: _empty_isr(agent_name)},
            }
        except (ValueError, RuntimeError) as e:
            logger.exception(
                "%s analysis crashed with %s.",
                agent_name,
                type(e).__name__,
                extra={
                    "event_type": "analyst_error",
                    "agent": agent_name,
                    "sample_hash": (state.get("file_hash") or "")[:16],
                    "error_type": type(e).__name__,
                    "fatal": True,
                },
            )
            return {
                "reports": {agent_name: f"[ERROR] {agent_name} crashed: {e}"},
                "isr_reports": {agent_name: _empty_isr(agent_name)},
            }

    node_fn.__name__ = f"{agent_name}_analyst_node"
    node_fn.__doc__ = f"Auto-generated analysis node for '{agent_name}' agent."
    return node_fn


# ---------------------------------------------------------------------------
# Revision context builder
# ---------------------------------------------------------------------------


def _build_revision_context(
    state: AnalysisState,
    container: ServiceContainer,
    agent_name: str,
) -> str:
    """Select the appropriate original_data context for a revision round.

    For single-chunk samples the raw chunk text is used. For multi-chunk
    samples the agent's consolidated analysis summary is used instead of
    re-loading data, because load_data() silently truncates large samples
    and would make revision grounding inconsistent with initial analysis.
    """
    file_hash = state.get("file_hash", "")

    try:
        chunks = container.load_chunked(file_hash, agent_name)
    except Exception as exc:
        logger.warning(
            "_build_revision_context: load_chunked failed for '%s/%s' (%s). "
            "Falling back to load_data().",
            file_hash,
            agent_name,
            exc,
        )
        return container.load_data(file_hash, agent_name)

    if len(chunks) == 1:
        return str(chunks[0].content)

    revised = state.get("revised_reports") or {}
    reports = state.get("reports") or {}
    summary_text = revised.get(agent_name) or reports.get(agent_name, "")

    if not summary_text:
        logger.warning(
            "_build_revision_context: no summary for '%s' in state. Falling back to load_data().",
            agent_name,
        )
        return container.load_data(file_hash, agent_name)

    total_chunks = getattr(chunks[0], "total", len(chunks))
    strategy_obj = getattr(chunks[0], "strategy", None)
    strategy = getattr(strategy_obj, "name", "unknown")
    header = (
        f"[CHUNKED ANALYSIS CONTEXT | domain={agent_name} | "
        f"chunks={total_chunks} | strategy={strategy}]\n"
        "This is your consolidated analysis summary produced from all "
        f"{total_chunks} chunks of the sample. Use it as grounding context "
        "for your revision; do not contradict findings without evidence.\n"
        "--- Consolidated Analysis Summary ---"
    )
    return f"{header}\n\n{summary_text}"


# ---------------------------------------------------------------------------
# Negotiation node
# ---------------------------------------------------------------------------


def make_negotiation_node(container: ServiceContainer) -> Any:
    """Factory: creates the mediator negotiation node."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        iteration = state.get("iteration_count", 0)
        agent_names = container.agent_registry.list_agents()

        revised = state.get("revised_reports") or {}
        original = state.get("reports") or {}
        active_reports = {name: revised.get(name) or original.get(name, "") for name in agent_names}

        current_isrs = list((state.get("isr_reports") or {}).values())

        if container.is_mock:
            is_consensus = iteration >= 1
            mean_conf = 0.95 if is_consensus else 0.4
            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "sycophancy_detected": False,
                "confidence_history": [mean_conf],
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=(
                            "MOCK: All experts agree. Confidence: 0.95"
                            if is_consensus
                            else "MOCK: Contradictions found. Confidence: 0.4"
                        ),
                        confidence_score=mean_conf,
                    )
                ],
            }

        # Sycophancy detector skips the first round internally.
        syco = detect_sycophancy(current_isrs, iteration=iteration) if current_isrs else False

        try:
            judge = container.get_judge_agent(role="expert")
            argument, is_consensus = await judge.mediate(
                reports=active_reports,
                history=state.get("discussion_history") or [],
                isr_reports=state.get("isr_reports") or {},
            )

            mean_conf = (
                sum(isr.mean_confidence for isr in current_isrs) / len(current_isrs)
                if current_isrs
                else argument.confidence_score
            )

            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "sycophancy_detected": syco,
                "confidence_history": [mean_conf],
                "discussion_history": [argument],
            }
        except (AnalystError, LLMError) as e:
            logger.error("Negotiation failed: %s", e)
            return {
                "iteration_count": iteration + 1,
                "is_consensus": False,
                "sycophancy_detected": syco,
                "confidence_history": [0.0],
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=f"[ERROR] Mediation failed: {e}",
                        confidence_score=0.0,
                    )
                ],
            }

    node_fn.__name__ = "negotiation_node"
    return node_fn


# ---------------------------------------------------------------------------
# Revision node
# ---------------------------------------------------------------------------


def make_revision_node(container: ServiceContainer) -> Any:
    """Factory: creates the revision node where all agents revise concurrently."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        agent_names = container.agent_registry.list_agents()
        iteration = state.get("iteration_count", 0)

        history = state.get("discussion_history") or []
        mediator_feedback = ""
        for arg in reversed(history):
            if arg.agent_name == "Mediator":
                mediator_feedback = arg.finding
                break

        syco_detected = state.get("sycophancy_detected", False)
        revision_directive = build_revision_directive(syco_detected, mediator_feedback)

        original_reports = state.get("reports") or {}

        if container.is_mock:
            mock_isrs: dict[str, AgentISR] = {
                name: _empty_isr(name, revision_round=iteration) for name in agent_names
            }
            return {
                "revised_reports": {
                    name: f"MOCK REVISED: {name} analysis updated." for name in agent_names
                },
                "isr_reports": mock_isrs,
            }

        async def _revise_one(name: str) -> tuple[str, AgentISR]:
            data = _build_revision_context(state, container, name)
            agent = container.get_agent(name)
            own_report = original_reports.get(name, "")
            peer_reports = {k: v for k, v in original_reports.items() if k != name}
            return await asyncio.to_thread(
                agent.safe_revise_isr,
                data,
                own_report,
                peer_reports,
                revision_directive,
                iteration,
            )

        tasks = [_revise_one(name) for name in agent_names]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        revised: dict[str, str] = {}
        revised_isrs: dict[str, AgentISR] = {}

        # strict=True: agent_names and results MUST be equal length; mismatch
        # is a programming error and must surface, not be silently truncated.
        for name, result in zip(agent_names, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("%s revision failed: %s", name, result)
                revised[name] = original_reports.get(name, "")
                revised_isrs[name] = _empty_isr(name, revision_round=iteration)
            else:
                revised_text, isr = result
                revised[name] = revised_text
                revised_isrs[name] = isr

        return {"revised_reports": revised, "isr_reports": revised_isrs}

    node_fn.__name__ = "revision_node"
    return node_fn


# ---------------------------------------------------------------------------
# Judge node
# ---------------------------------------------------------------------------


def make_judge_node(container: ServiceContainer) -> Any:
    """Factory: creates the final judge verdict node."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            return {
                "final_decision": "Malware",
                "judge_report": "MOCK: Evaluated all indicators.",
                "stix_output": {},
                "run_summary": None,
            }

        try:
            judge = container.get_judge_agent(role="judge")

            revised = state.get("revised_reports") or {}
            original = state.get("reports") or {}
            reports = {
                name: revised.get(name) or original.get(name, "")
                for name in container.agent_registry.list_agents()
            }

            attck_validator = None
            try:
                from maljan.memory.attck_validator import ATTCKValidator

                attck_validator = ATTCKValidator.get_instance()
            except Exception as e:
                logger.warning("ATTCKValidator unavailable: %s. Skipping TTP validation.", e)

            isr_reports: dict[str, AgentISR] = dict(state.get("isr_reports") or {})

            # Wave 4: pick up the platform the bootstrap inferred. The
            # rule layers + cascade use this to drop platform-mismatched
            # signals (the 2026-05-28 audit found 6/7 sigma matches on
            # an APK were Windows/macOS/cloud rules).
            sample_platform = state.get("platform") or "unknown"

            async def _run_yara_scan() -> AgentISR | None:
                try:
                    yara_layer = container.get_yara_layer()
                    if yara_layer.rule_count > 0:
                        scan_parts: list[str] = list((state.get("reports") or {}).values())
                        for isr_obj in isr_reports.values():
                            scan_parts.extend(c.evidence_ref for c in isr_obj.claims)
                        scan_text = " ".join(scan_parts)
                        yara_layer.reset_filter_stats()
                        yara_matches = await asyncio.to_thread(
                            yara_layer.scan, scan_text, sample_platform
                        )
                        if yara_matches:
                            yara_isr: AgentISR = yara_layer.to_isr(yara_matches)
                            logger.info(
                                "YARA Layer 0: %d match(es), %d rule(s) dropped "
                                "by platform=%s -> cascade domain='yara'.",
                                len(yara_matches),
                                yara_layer.last_filtered_count,
                                sample_platform,
                            )
                            return yara_isr
                except Exception as e:
                    logger.warning("YARA Layer 0 scan failed: %s. Skipping.", e)
                return None

            async def _run_sigma_scan() -> AgentISR | None:
                try:
                    sigma_layer = container.get_sigma_layer()
                    if sigma_layer.rule_count > 0:
                        sigma_scan_parts: list[str] = list((state.get("reports") or {}).values())
                        for isr_obj in isr_reports.values():
                            sigma_scan_parts.extend(c.evidence_ref for c in isr_obj.claims)
                        sigma_scan_text = "\n".join(sigma_scan_parts)
                        sigma_layer.reset_filter_stats()
                        sigma_matches = await asyncio.to_thread(
                            sigma_layer.scan_report_text,
                            sigma_scan_text,
                            sample_platform,
                        )
                        if sigma_matches or sigma_layer.last_filtered_count:
                            logger.info(
                                "Sigma Layer 0: %d match(es), %d rule(s) dropped "
                                "by platform=%s -> cascade domain='sigma'.",
                                len(sigma_matches),
                                sigma_layer.last_filtered_count,
                                sample_platform,
                            )
                        if sigma_matches:
                            sigma_isr = sigma_layer.to_isr(sigma_matches)
                            return sigma_isr
                except Exception as e:
                    logger.warning("Sigma Layer 0 scan failed: %s. Skipping.", e)
                return None

            yara_result, sigma_result = await asyncio.gather(_run_yara_scan(), _run_sigma_scan())
            if yara_result is not None:
                isr_reports["yara_layer"] = yara_result
            if sigma_result is not None:
                isr_reports["sigma_layer"] = sigma_result

            cascade_summary = None
            try:
                cascade_summary = TTPCascadeEngine().compute(
                    isr_reports, sample_platform=sample_platform
                )
            except Exception as e:
                logger.warning("TTP cascade failed: %s. Skipping.", e)

            # Wave 9 (2026-05-29): capture pre-cascade platform-filter
            # counters from both Layer 0 evaluators so the audit gate
            # G-FP-8 can prove the filter ran even when the cascade has
            # nothing to drop.
            _sigma_dropped_total = 0
            _yara_dropped_total = 0
            try:
                _yara_dropped_total = container.get_yara_layer().last_filtered_count
            except Exception as e:
                logger.debug("Could not read yara_layer.last_filtered_count: %s", e)
            try:
                _sigma_dropped_total = container.get_sigma_layer().last_filtered_count
            except Exception as e:
                logger.debug("Could not read sigma_layer.last_filtered_count: %s", e)

            start_time = time.time()

            memory_store: MemoryStore | None = None
            try:
                memory_store = container.get_memory_store()
            except Exception as e:
                logger.warning("Memory store unavailable: %s. Skipping LTM context.", e)

            # Audit 2026-05-17 J-02: build evidence corpus so the judge
            # post-processor can drop hallucinated indicators whose
            # pattern values never appeared in deterministic findings.
            evidence_corpus: set[str] = set()
            try:
                from maljan.agents.judge_postprocess import build_evidence_corpus

                # Best-effort — interesting strings come from a partial
                # MalwareReport build later in the pipeline, so we pull
                # from the raw sandbox report and any pre-built static
                # block that's already in state.
                sandbox_report = state.get("sandbox_report") or {}
                evidence_corpus = build_evidence_corpus(
                    interesting_strings=None,
                    sandbox_report=sandbox_report if isinstance(sandbox_report, dict) else None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Evidence corpus build skipped: %s", exc)

            # Sandbox CTI — when the active sandbox client synthesises a
            # flat CTI block (currently TriageClient), forward it to the
            # judge so deterministic family / C2 / extracted-secret
            # evidence influences the verdict directly.
            _cti_block: dict[str, Any] | None = None
            _sb = state.get("sandbox_report")
            if isinstance(_sb, dict):
                _maybe = _sb.get("cti")
                if isinstance(_maybe, dict):
                    _cti_block = _maybe

            bundle = await judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
                isr_reports=isr_reports,
                attck_validator=attck_validator,
                cascade_summary=cascade_summary,
                memory_store=memory_store,
                evidence_corpus=evidence_corpus or None,
                current_sample_id=state.get("file_hash"),
                cti_block=_cti_block,
            )

            stix_output: dict[str, Any] = {}
            if isinstance(bundle, Bundle):
                stix_output = bundle.model_dump()

            decision = _decide_from_bundle(bundle) if isinstance(bundle, Bundle) else "Suspicious"

            ttp_validation_summary = None
            if attck_validator and hasattr(attck_validator, "validate_isr_reports") and isr_reports:
                try:
                    ttp_validation_summary = attck_validator.validate_isr_reports(isr_reports)
                except Exception as exc:
                    logger.debug("validate_isr_reports failed: %s", exc, exc_info=True)

            # CONF-INFL-01 (2026-05-19 audit): compute corroboration /
            # failure signals up front so we can feed the LTM quality
            # gate (LTM-01, below) AND the run_summary builder. Without
            # this, a run where every LLM analyst silently fails (zero
            # claims, only YARA+Sigma layer matches) yields a 0.95+
            # confidence verdict that visually matches a fully
            # corroborated one.
            _corroborated = cascade_summary.corroborated_count if cascade_summary is not None else 0
            _technique_count = (
                cascade_summary.total_techniques if cascade_summary is not None else 0
            )
            _failed_analysts = [
                name
                for name, text in (state.get("reports") or {}).items()
                if isinstance(text, str) and text.strip().startswith("[ERROR]")
            ]
            # D10: surface anti-emulation / anti-VM / sandbox-detection
            # signatures so the existing DEGRADED RUN banner can explain
            # the empty dynamic tab (sandbox traced nothing because the
            # sample noticed it was being observed). Pattern matched
            # case-insensitively against the signature name + description
            # so Triage's verbose copy ("Listens for changes in the
            # sensor environment (might be used to detect emulation)") is
            # caught the same as CAPE's short ("anti-vm").
            _ANTI_EMU_RE = re.compile(
                r"emulation|anti[\s_-]?vm|anti[\s_-]?debug|sandbox\s*detect|"
                r"qemu|virtualbox|vmware|hyper[\s_-]?v",
                re.IGNORECASE,
            )
            _anti_emu_hits: list[str] = []
            for sig in (state.get("sandbox_report") or {}).get("signatures") or []:
                if not isinstance(sig, dict):
                    continue
                _haystack = f"{sig.get('name', '')} {sig.get('description', '')}"
                if _ANTI_EMU_RE.search(_haystack):
                    _hit_name = str(sig.get("name") or "").strip()
                    if _hit_name and _hit_name not in _anti_emu_hits:
                        _anti_emu_hits.append(_hit_name)
            _degradation_reasons: list[str] = []
            if _corroborated == 0 and _technique_count > 0:
                _degradation_reasons.append(
                    f"zero cross-layer corroboration ({_technique_count} single-layer techniques)"
                )
            if _failed_analysts:
                _degradation_reasons.append(f"analyst failures: {', '.join(_failed_analysts)}")
            if _anti_emu_hits:
                _short = _anti_emu_hits[0]
                _suffix = f" (+{len(_anti_emu_hits) - 1} more)" if len(_anti_emu_hits) > 1 else ""
                _degradation_reasons.append(
                    f"sandbox detected anti-emulation behaviour: {_short}{_suffix}"
                )
            _degraded_mode = bool(_degradation_reasons)
            if _degraded_mode:
                logger.warning(
                    "Degraded run detected (%s). Final confidence will be "
                    "capped in the report node.",
                    "; ".join(_degradation_reasons),
                )

            run_summary_dict = None
            try:
                max_iters = container.config.negotiation.max_iterations
                negotiation_state = {
                    "confidence_history": state.get("confidence_history") or [],
                    "iteration_count": state.get("iteration_count", 0),
                    "is_consensus": state.get("is_consensus", False),
                    "sycophancy_detected": state.get("sycophancy_detected", False),
                    "discussion_history": state.get("discussion_history") or [],
                }
                summary = (
                    RunSummaryBuilder(start_time=start_time)
                    .set_sample(state.get("file_hash", ""), state.get("file_name"))
                    .set_verdict(decision, len(bundle.objects) if isinstance(bundle, Bundle) else 0)
                    .set_negotiation(negotiation_state, max_iterations=max_iters)
                    .set_isr_stats(isr_reports)
                    .set_validation_summary(ttp_validation_summary)
                    .set_cascade_summary(cascade_summary)
                    .set_platform_filter_summary(
                        sigma_dropped=_sigma_dropped_total,
                        yara_dropped=_yara_dropped_total,
                        sample_platform=str(sample_platform),
                    )
                    .set_degraded_mode(_degraded_mode, _degradation_reasons)
                    .set_failed_analysts(_failed_analysts)
                    .build()
                )
                run_summary_dict = summary.to_dict()
                logger.info(
                    "RunSummary built: verdict=%s, rounds=%d, techniques=%d",
                    decision,
                    summary.negotiation.rounds_completed,
                    summary.cascade.total_techniques if summary.cascade else 0,
                )
            except Exception as exc:
                logger.warning("RunSummary build failed (%s). Skipping.", exc)

            if memory_store is not None and isr_reports:
                # Audit 2026-05-17 LTM-01: quality gate. Skip the upsert
                # when the run is clearly degraded (no corroboration, no
                # techniques, failed analysts, etc.). A polluted entry
                # poisons future analyses via the few-shot prior block.
                _ltm_skip_reason: str | None = None
                if _corroborated == 0 and _technique_count <= 1:
                    _ltm_skip_reason = (
                        f"low-quality cascade: corroborated={_corroborated}, "
                        f"techniques={_technique_count}"
                    )
                elif _failed_analysts:
                    _ltm_skip_reason = f"analyst failures: {', '.join(_failed_analysts)}"
                elif state.get("iteration_count", 0) == 0 and not state.get("is_consensus", False):
                    _ltm_skip_reason = "no negotiation rounds completed"

                if _ltm_skip_reason is not None:
                    logger.info(
                        "LTM: skipping store for '%s' (reason: %s).",
                        state.get("file_hash", "unknown")[:16],
                        _ltm_skip_reason,
                    )
                else:
                    try:
                        category = infer_malware_category(
                            reports=state.get("reports") or {},
                            isr_reports=isr_reports,
                        ).value
                        case = build_stored_case(
                            sample_id=state.get("file_hash", "unknown"),
                            isr_reports=isr_reports,
                            stix_bundle_json=(
                                bundle.model_dump_json() if isinstance(bundle, Bundle) else ""
                            ),
                            malware_category=category,
                            corroborated_count=_corroborated,
                            total_techniques=_technique_count,
                            has_analyst_errors=bool(_failed_analysts),
                        )
                        memory_store.store(case)
                        logger.info(
                            "LTM: stored case '%s' (category=%s, techniques=%d).",
                            case.sample_id,
                            case.malware_category,
                            len(case.technique_ids),
                        )
                    except Exception as e:
                        logger.warning(
                            "LTM store failed (%s). Analysis result is unaffected.",
                            e,
                        )

            return {
                "final_decision": decision,
                "judge_report": "Analyzed negotiation history and expert reports.",
                "stix_output": stix_output,
                "run_summary": run_summary_dict,
                # Persist YARA/Sigma layer ISRs so callers can inspect them.
                "isr_reports": isr_reports,
                # CONF-INFL-01: surface degraded-mode signal to the report
                # node and downstream consumers (API/dashboard).
                "degraded_mode": _degraded_mode,
                "degradation_reasons": _degradation_reasons,
                # Sandbox CTI surface for the report node — persisted into
                # the extended STIX bundle so the UI / API / paper export
                # can render the full deterministic threat-intel snapshot.
                "sandbox_cti": _cti_block,
            }
        except (AnalystError, LLMError) as e:
            logger.error("Judge verdict failed: %s", e)
            return {
                "final_decision": "Suspicious",
                "judge_report": f"[ERROR] Judge failed: {e}",
                "stix_output": {},
            }

    node_fn.__name__ = "judge_node"
    return node_fn


# ---------------------------------------------------------------------------
# Report node — assembles the comprehensive MalwareReport (Faz 2)
# ---------------------------------------------------------------------------


def make_report_node(container: ServiceContainer) -> Any:
    """Factory: builds the final ``MalwareReport`` and renders markdown + STIX.

    Runs after the judge node. The narrative LLM round and the auto-generated
    detection signatures are added in later phases; for now we ship a
    deterministic fallback narrative so the report never leaves a consumer
    with empty prose.
    """

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        try:
            cfg = container.config.reporting
        except AttributeError:
            cfg = None

        # Feature flag: when reporting is disabled we leave the new state
        # fields untouched so downstream consumers see ``None`` and fall back
        # to ``judge_report`` / ``stix_output``.
        if cfg is not None and not cfg.enabled:
            return {}

        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.renderers import ExtendedSTIXRenderer, MarkdownRenderer
        from maljan.schemas.stix_models import Bundle

        isr_reports = dict(state.get("isr_reports") or {})

        # Wave 4: re-run the cascade with the same sample_platform the judge
        # node used, so the report_node's cascade output stays consistent
        # with what the verdict + STIX bundle saw.
        report_sample_platform = state.get("platform") or "unknown"

        cascade_summary = None
        try:
            cascade_summary = TTPCascadeEngine().compute(
                isr_reports, sample_platform=report_sample_platform
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("report_node: cascade recompute skipped (%s).", exc)

        # Derive overall confidence — last entry of the confidence history if
        # available, otherwise the negotiation block of run_summary, otherwise
        # 0.0 (safe default for the severity heuristic).
        confidence_history = state.get("confidence_history") or []
        overall_confidence: float = 0.0
        if confidence_history:
            try:
                overall_confidence = float(confidence_history[-1])
            except (TypeError, ValueError):
                overall_confidence = 0.0
        run_summary_state = state.get("run_summary") or {}
        if not overall_confidence:
            try:
                overall_confidence = float(
                    (run_summary_state.get("negotiation") or {}).get("final_confidence") or 0.0
                )
            except (TypeError, ValueError):
                overall_confidence = 0.0

        # CONF-INFL-01 (2026-05-19 audit): cap confidence when the judge
        # node flagged the run as degraded. Without this, a verdict drawn
        # entirely from YARA/Sigma deterministic layers (with all three
        # LLM analysts silently producing zero claims) lands at 0.98+ and
        # is indistinguishable in the UI from a fully corroborated
        # finding. The 0.60 ceiling is the same threshold the dashboard
        # uses to render "low confidence" styling.
        _DEGRADED_CONFIDENCE_CAP = 0.60
        if state.get("degraded_mode") and overall_confidence > _DEGRADED_CONFIDENCE_CAP:
            logger.warning(
                "report_node: capping overall_confidence %.3f -> %.2f (degraded run: %s).",
                overall_confidence,
                _DEGRADED_CONFIDENCE_CAP,
                "; ".join(state.get("degradation_reasons") or []) or "no reason recorded",
            )
            overall_confidence = _DEGRADED_CONFIDENCE_CAP

        # Best-effort malware category — cheap and fully deterministic.
        #
        # CAT-PERSIST-01 (2026-05-19 audit): the previous implementation
        # swallowed every exception at DEBUG level, so a silently-failing
        # ``.value`` access (e.g. when the inference returned a string
        # instead of an enum, or when the schema_pruner module raised on a
        # malformed ISR) left the DB row with ``malware_category = NULL``
        # despite the worker log claiming "Schema pruning: inferred
        # category 'rat'." in the judge phase. Promote the failure to
        # WARNING and coerce non-enum returns to ``str`` so the field
        # actually lands.
        malware_category: str | None = None
        try:
            inferred = infer_malware_category(
                reports=state.get("reports") or {},
                isr_reports=isr_reports,
            )
            # ``infer_malware_category`` returns ``MalwareCategory`` (Enum)
            # but a custom override could return a bare str; accept both.
            raw_value = getattr(inferred, "value", inferred)
            if isinstance(raw_value, str) and raw_value:
                malware_category = raw_value
            else:
                logger.warning(
                    "report_node: malware_category inference returned non-string %r;"
                    " field will stay NULL.",
                    raw_value,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "report_node: malware_category inference failed (%s: %s).",
                type(exc).__name__,
                exc,
            )

        discussion_history = [
            arg.model_dump() if hasattr(arg, "model_dump") else dict(arg)
            for arg in (state.get("discussion_history") or [])
        ]

        try:
            builder = MalwareReportBuilder(
                file_hash=state.get("file_hash"),
                file_name=state.get("file_name"),
                sample_path=state.get("sample_path"),
                sandbox_report=state.get("sandbox_report"),
                reports=state.get("reports"),
                isr_reports=isr_reports,
                stix_output=state.get("stix_output"),
                run_summary=run_summary_state,
                discussion_history=discussion_history,
                final_decision=state.get("final_decision") or "Suspicious",
                overall_confidence=overall_confidence,
                cascade_summary=cascade_summary,
                malware_category=malware_category,
            )
            report = builder.build_deterministic()
        except Exception as exc:  # noqa: BLE001
            logger.error("report_node: deterministic build failed (%s).", exc, exc_info=True)
            return {}

        # Narrative LLM round (Faz 3). NarrativeAgent is None in mock mode;
        # also returns None when the structured-output and manual-parse
        # fallbacks both fail. In every "no narrative" branch we apply the
        # deterministic template so the report never ships with empty prose.
        narrative_dict: dict[str, Any] | None = None
        try:
            narrative_agent = container.get_narrative_agent()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: NarrativeAgent unavailable (%s); using fallback.", exc)
            narrative_agent = None

        if narrative_agent is not None:
            try:
                narrative_output = await narrative_agent.generate(report)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: NarrativeAgent.generate raised (%s); using fallback.",
                    exc,
                )
                narrative_output = None
            if narrative_output is not None:
                narrative_dict = narrative_output.model_dump(mode="json")

        if narrative_dict is not None:
            report = MalwareReportBuilder.apply_narrative(report, narrative_dict)
            logger.info(
                "report_node: narrative LLM round succeeded (summary_chars=%d, "
                "paragraphs=%d, recs=%d).",
                len(report.executive_summary),
                len(report.capabilities_narrative),
                len(report.defensive_recommendations),
            )
        else:
            report = MalwareReportBuilder.apply_fallback_narrative(report)

        # Detection signatures (Faz 4) — template-based YARA/Sigma/Suricata
        # generation. Runs after narrative so the LLM-written family name can
        # influence rule metadata. Disabled via config when desired.
        if cfg is None or cfg.auto_generate_detection_rules:
            try:
                report = MalwareReportBuilder.attach_detection_signatures(report)
                logger.info(
                    "report_node: detection rules generated (count=%d, errors=%d).",
                    len(report.detection_signatures),
                    sum(1 for r in report.detection_signatures if r.compile_error),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_node: detection rule generation failed (%s).", exc)

        markdown = MarkdownRenderer().render(report)

        extended_dump: dict[str, Any] | None = None
        if cfg is None or cfg.include_extended_stix:
            try:
                base = (
                    Bundle.model_validate(state["stix_output"])
                    if state.get("stix_output")
                    else None
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: judge bundle could not be re-validated (%s). "
                    "Falling back to fresh extended bundle.",
                    exc,
                )
                base = None
            try:
                extended_bundle = ExtendedSTIXRenderer().render(report, base)
                extended_dump = extended_bundle.model_dump(mode="json")
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_node: extended STIX render failed (%s).", exc)
                extended_dump = None

        if extended_dump is not None:
            # Attach the sandbox CTI block as a custom STIX extension so the
            # full deterministic threat-intel snapshot is preserved with the
            # report (paper exports / API consumers / dashboards can quote
            # it directly without re-parsing the raw sandbox report).
            sandbox_cti = state.get("sandbox_cti")
            if isinstance(sandbox_cti, dict) and sandbox_cti:
                extended_dump.setdefault("x_maljan_cti", sandbox_cti)

            # D20 fix: rewrite the malware SDO description when the judge
            # emitted a fallback placeholder (timeout / non-JSON output).
            # The fallback writes a stale verdict that cross-layer
            # aggregation may upgrade — STIX consumers should see the
            # FINAL verdict in the user-visible description, not the
            # intermediate ``judge fallback`` text.
            _final_desc = (
                f"Verdict: {report.verdict} "
                f"(confidence={report.overall_confidence:.2f}; "
                f"severity={report.severity.rating})"
            )
            for obj in extended_dump.get("objects", []) or []:
                if obj.get("type") != "malware":
                    continue
                _desc = str(obj.get("description", "")).lower()
                if "judge fallback" in _desc or "verdict pending" in _desc:
                    obj["description"] = _final_desc
                    break

            report.stix_bundle_extended = extended_dump

        # Wave 4 Step 8: post-pipeline FP linter. Run after every other
        # mutation has happened (narrative + detection sigs + STIX dump)
        # so the linter sees the exact payload a downstream consumer
        # will see. Findings are merged into ``run_summary`` so the API
        # serialiser ships them without further work.
        try:
            from maljan.qa.fp_linter import lint_report as _lint_report

            fp_warnings = [w.to_dict() for w in _lint_report(report, report_sample_platform)]
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: FP linter raised (%s); continuing.", exc)
            fp_warnings = []

        if fp_warnings:
            logger.warning(
                "FP linter: %d warning(s) — %s",
                len(fp_warnings),
                ", ".join(w["rule"] for w in fp_warnings),
            )
            run_summary_dict = report.run_summary or {}
            run_summary_dict["fp_warnings"] = fp_warnings
            report.run_summary = run_summary_dict

        logger.info(
            "report_node: built MalwareReport (verdict=%s, severity=%s, "
            "markdown_chars=%d, extended_objects=%d, cti=%s, fp_warnings=%d).",
            report.verdict,
            report.severity.rating,
            len(markdown),
            len(extended_dump.get("objects", [])) if extended_dump else 0,
            "yes"
            if isinstance(state.get("sandbox_cti"), dict) and state.get("sandbox_cti")
            else "no",
            len(fp_warnings),
        )

        # Wave 9 HOTFIX-09 (2026-05-29): surface ``fp_warnings`` into the
        # pipeline state's ``run_summary`` so the worker writes them to the
        # ``reports.run_summary`` JSONB column. Without this the warnings
        # only landed on ``MalwareReport.run_summary`` (saved to the
        # ``malware_report`` column / ``/full`` endpoint); the UI SUMMARY
        # tab reads from the ``/reports/{id}`` DTO which surfaces the
        # narrower ``run_summary`` column, so the QA WARNINGS banner
        # stayed empty even when the linter had real findings to show.
        #
        # Only override state["run_summary"] when there are warnings to
        # add — leaving it untouched preserves the mock-mode contract
        # (state.run_summary remains None when the judge node skipped
        # RunSummaryBuilder, exercised by test_run_summary_is_none_in_mock_mode).
        result: dict[str, Any] = {
            "malware_report": report.model_dump(mode="json"),
            "malware_report_markdown": markdown,
            "stix_bundle_extended": extended_dump,
        }
        if fp_warnings:
            result["run_summary"] = {
                **(state.get("run_summary") or {}),
                "fp_warnings": fp_warnings,
            }
        return result

    node_fn.__name__ = "report_node"
    return node_fn
