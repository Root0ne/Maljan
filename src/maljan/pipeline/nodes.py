"""Generic node factories for the LangGraph pipeline.

Each factory returns a node function bound to a specific agent name and the
shared ServiceContainer. The factories work with any agent in the registry —
no per-agent branching exists.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any, cast

from maljan.analysis.lolbin_layer import build_lolbin_isr
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.analysis.schema_pruner import infer_malware_category
from maljan.analysis.ttp_cascade import TTPCascadeEngine
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.extractors.network_extractor import (
    build_dga_isr,
    build_network_iocs,
)
from maljan.memory.long_term_memory import build_stored_case
from maljan.pipeline.events import (
    claims_to_payload,
    emit,
    emit_agent_message,
    summarize_claims,
)
from maljan.pipeline.state import AgentArgument, AnalysisState
from maljan.pipeline.sycophancy_detector import build_revision_directive, detect_sycophancy
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore
    from maljan.reporting.models import StaticAnalysis


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


# The file-loader placeholder for a missing per-sample fixture
# ("No static data available for sample <sha>."). Local copy of the
# BUG-07 pattern from static_analyst to avoid a nodes->agents import edge.
_STATIC_PLACEHOLDER_RE = re.compile(r"^\s*no\s+\w+\s+data\s+available\b", re.IGNORECASE)

# Hard ceiling for the synthesized head-chunk content. The augmented chunk
# is spliced in via ``dataclasses.replace`` AFTER chunking, so it never
# re-passes the token-budget check — the cap here is load-bearing.
_MAX_SYNTH_CHUNK_CHARS = 40_000

# CONF-INFL-01: the confidence ceiling for a degraded run. Public, and
# module-level, because it is a cross-layer contract rather than an
# implementation detail of the report node: the worker persists whatever ends
# up under it, the dashboard styles "low confidence" at the same threshold, and
# the 2026-07-26 audit found the value silently disagreeing between layers. One
# name, so a change cannot land in only half of them.
DEGRADED_CONFIDENCE_CAP = 0.60


def _compact_static_summary(static: StaticAnalysis) -> dict[str, Any]:
    """Serialize a StaticAnalysis into a size-capped dict for the LLM prompt.

    Caps keep the synthesized head chunk inside the prompt budget:
    imports <= 60 rows (suspicious-first), strings <= 40, exports <= 40,
    ``embedded_resources`` reduced to a count. Truncation markers record
    how many rows were dropped so the model doesn't mistake a cap for
    an empty artefact.
    """
    dump = static.model_dump(mode="json")
    out: dict[str, Any] = {
        "sections": dump.get("sections", []),
        "packer_hint": dump.get("packer_hint"),
        "obfuscation_indicators": dump.get("obfuscation_indicators", []),
        "embedded_resources_count": len(dump.get("embedded_resources", [])),
    }
    imports = sorted(
        dump.get("imports", []),
        key=lambda r: not bool(r.get("is_suspicious")),
    )
    if len(imports) > 60:
        out["imports_truncated"] = len(imports) - 60
    out["imports"] = imports[:60]
    strings = dump.get("interesting_strings", [])
    if len(strings) > 40:
        out["strings_truncated"] = len(strings) - 40
    out["interesting_strings"] = strings[:40]
    exports = dump.get("exports", [])
    if len(exports) > 40:
        out["exports_truncated"] = len(exports) - 40
    out["exports"] = exports[:40]
    return out


def _augment_static_chunks_with_path(
    chunks: list,
    state: AnalysisState,
    static: StaticAnalysis | None = None,
) -> list:
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

    Ghidra-path fix (2026-07-12, job 60df48cb): when the head chunk is the
    file-loader placeholder ("No static data available for sample <sha>"),
    synthesize a real JSON chunk instead of passing the placeholder through.
    Without it the LLM never sees ``analysis_file_path``, hallucinates a
    path for ``load_program`` and reports "file was not found on the server
    filesystem" even though the mirror succeeded. The synthesized chunk
    carries the paths plus a deterministic PE summary (``static``) so fresh
    samples get a real data surface. Non-placeholder non-JSON chunks (legacy
    raw decompile output) still pass through unchanged.

    The chunk objects are immutable dataclasses; rebuild with the same
    chunker so downstream code (token budget, chunk_text) keeps working.
    """
    import json

    static_path = state.get("static_sample_path")
    if not static_path or not chunks:
        return chunks

    head = chunks[0]
    parsed: dict[str, Any] | None = None
    try:
        loaded = json.loads(head.content)
        if isinstance(loaded, dict):
            parsed = loaded
    except (json.JSONDecodeError, ValueError):
        parsed = None

    if parsed is None:
        if not _STATIC_PLACEHOLDER_RE.match(head.content.strip()):
            # Legacy raw (non-JSON, non-placeholder) chunk — pass through.
            return chunks
        parsed = {
            "note": (
                "Live analysis run: no pre-extracted static fixture exists "
                "for this sample. The deterministic PE summary below was "
                "parsed on the host; use your Ghidra tools for deeper "
                "analysis."
            ),
            "sha256": state.get("file_hash") or "",
            "static_summary": (_compact_static_summary(static) if static is not None else None),
        }

    parsed["analysis_file_path"] = static_path
    # Also carry the HOST-readable path (when present) so the static-feature
    # family classifier can read the raw bytes — ember reads the file on the
    # host, unlike Ghidra which reads the container-visible ``analysis_file_path``.
    host_path = state.get("sample_path")
    if isinstance(host_path, str) and host_path:
        parsed["host_sample_path"] = host_path
    new_content = json.dumps(parsed, indent=2, default=str)
    if len(new_content) > _MAX_SYNTH_CHUNK_CHARS and "static_summary" in parsed:
        # The spliced chunk bypasses the token-budget re-check; drop the
        # summary rather than blow the prompt window.
        parsed["static_summary"] = None
        parsed["static_summary_omitted"] = "too large"
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

        # Analysts run sequentially on the single-slot local model, so a
        # per-agent "started" event is the only way the UI can say which one is
        # actually working — the worker's up-front announcement marks them all
        # busy at once and is a poor proxy.
        emit(container.event_sink, "agent_progress", {"agent": agent_name, "phase": "analyzing"})

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
                # Ghidra-path fix (2026-07-12): compute the deterministic PE
                # summary ONCE and reuse it for both the synthesized head
                # chunk and the dynamic-tool-selection categories below.
                _st: StaticAnalysis | None = None
                try:
                    from maljan.extractors.pe_extractor import build_static_analysis

                    _sp = state.get("sample_path")
                    if _sp:
                        _st = build_static_analysis(sample_path=str(_sp))
                except Exception as _e:  # noqa: BLE001
                    logger.debug("static summary extraction skipped: %s", _e)

                chunks = _augment_static_chunks_with_path(chunks, state, static=_st)

                # Pin the container-visible path on the agent so the
                # load_program tool wrapper can override hallucinated paths.
                # Assign unconditionally — agents are cached across samples;
                # a stale path from the previous sample must be cleared.
                agent._analysis_file_path = (  # type: ignore[attr-defined]
                    state.get("static_sample_path") or None
                )

                # 2026-07 round 3: hand the static analyst the sample's capability
                # categories (from the PE import classification) so dynamic Ghidra
                # tool selection works regardless of whether the chunk carried a
                # readable path. state["sample_path"] is reliably host-readable.
                try:
                    from maljan.analysis.import_capability_layer import _imports_by_category

                    agent._sample_categories = (  # type: ignore[attr-defined]
                        set(_imports_by_category(_st).keys()) if _st else set()
                    )
                except Exception as _e:  # noqa: BLE001
                    logger.debug("static category hint skipped: %s", _e)

            if not chunks:
                # Wave 9 (2026-05-29): the 2026-05-29 Linux ELF audit
                # found that an ELF sample with no PCAP / sandbox network
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
                no_data_text = (
                    f"[WARN] {agent_name}: no {agent_name} data available "
                    "for this sample — analyst skipped."
                )
                emit_agent_message(
                    container.event_sink,
                    speaker=agent_name,
                    role="analyst",
                    text=no_data_text,
                    status="no_data",
                )
                return {
                    "reports": {agent_name: no_data_text},
                    "isr_reports": {agent_name: _empty_isr(agent_name)},
                }

            if len(chunks) == 1:
                # View-decomposition pilot (findings-log §3.6): when enabled,
                # split the single text bundle into N focused, equal-budget
                # sub-prompts and merge. Default 0 keeps the monolithic path.
                _views = int(getattr(container.config.llm, "view_decomposition_views", 0) or 0)
                if _views >= 2:
                    _budget = int(getattr(container.config.llm, "expert_max_tokens", 0) or 0)
                    # Item 3 (LAMD): "tier" reinterprets the N knob as sequential
                    # vertical reasoning tiers; "facet" (default) keeps the §3.6
                    # horizontal concurrent views. Both share the equal budget.
                    _mode = str(
                        getattr(container.config.llm, "view_decomposition_mode", "facet") or "facet"
                    )
                    if _mode == "tier":
                        isr = agent.safe_analyze_isr_tiered(
                            chunks[0].content,
                            _views,
                            total_max_tokens=_budget or None,
                        )
                    else:
                        isr = agent.safe_analyze_isr_views(
                            chunks[0].content,
                            _views,
                            total_max_tokens=_budget or None,
                        )
                else:
                    isr = agent.safe_analyze_isr(chunks[0].content)
                fallback_text = chunks[0].content
            else:
                # TraceRAG function-level retrieval (findings-log §4 Item 2):
                # for large static binaries, feed only the behavior-relevant
                # function chunks instead of every chunk. Default top_k=0 keeps
                # the full linear path (zero behaviour change).
                if agent_name == "static":
                    _rag_k = int(
                        getattr(container.config.preprocessing, "static_function_rag_top_k", 0) or 0
                    )
                    _rag_min = int(
                        getattr(container.config.preprocessing, "static_function_rag_min_chunks", 6)
                        or 6
                    )
                    if _rag_k > 0 and len(chunks) > _rag_min:
                        from maljan.memory.function_index import select_relevant_chunks

                        chunks = select_relevant_chunks(chunks, _rag_k)
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

            # Report-reshaping Phase 1: carry the captured tool-loop outputs
            # (decompiled functions, crypto constants, emulation/dataflow) into
            # state so report_node can ground the deep technical spine. Best-
            # effort — a capture read must never break the analyst node.
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=summarize_claims(isr.claims, speaker=agent_name),
                round_index=0,
                status="complete" if isr.claims else "no_data",
                claims=claims_to_payload(isr.claims),
                dissent=list(isr.dissent_items or []),
            )

            node_out: dict[str, Any] = {
                "reports": {agent_name: report},
                "isr_reports": {agent_name: isr},
            }
            try:
                _ev = agent.get_last_tool_evidence()
                if _ev:
                    node_out["tool_evidence"] = {agent_name: [o.model_dump() for o in _ev]}
            except Exception as _ev_exc:  # noqa: BLE001
                logger.debug("tool-evidence read skipped for %s: %s", agent_name, _ev_exc)
            return node_out
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
            failed_text = f"[ERROR] {agent_name} analysis failed: {e}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=failed_text,
                status="failed",
            )
            return {
                "reports": {agent_name: failed_text},
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
            crashed_text = f"[ERROR] {agent_name} crashed: {e}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=crashed_text,
                status="failed",
            )
            return {
                "reports": {agent_name: crashed_text},
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

            emit_agent_message(
                container.event_sink,
                speaker="Mediator",
                role="negotiator",
                text=argument.finding,
                round_index=iteration + 1,
                status="complete",
                confidence=argument.confidence_score,
            )
            if syco:
                emit_agent_message(
                    container.event_sink,
                    speaker="Sycophancy detector",
                    role="system",
                    text=(
                        "Agents converged without new evidence — flagged as sycophantic "
                        "agreement. The next revision round carries a directive to "
                        "re-argue from evidence rather than defer to peers."
                    ),
                    round_index=iteration + 1,
                    status="complete",
                )

            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "sycophancy_detected": syco,
                "confidence_history": [mean_conf],
                "discussion_history": [argument],
            }
        except Exception as e:  # noqa: BLE001 — per-run fault-isolation boundary
            # The mediation step calls the LLM; on a constrained / local host that
            # call can fail in many ways (AnalystError, LLMError, a bare asyncio
            # TimeoutError re-raised by judge_agent.execute_tool_loop, or a transient
            # openai APIConnectionError under concurrent analyst load). A single
            # failed mediation round must NOT crash the whole graph — degrade
            # gracefully to "no consensus" and carry the current ISRs forward (they
            # are already populated by the analyst nodes), so the run still returns a
            # scoreable result instead of aborting an entire batch on one blip.
            label = "timed out" if isinstance(e, TimeoutError) else "failed"
            logger.error("Negotiation %s: %s", label, e or type(e).__name__)
            emit_agent_message(
                container.event_sink,
                speaker="Mediator",
                role="negotiator",
                text=f"[ERROR] Mediation {label}: {e or type(e).__name__}",
                round_index=iteration + 1,
                status="timeout" if isinstance(e, TimeoutError) else "failed",
            )
            return {
                "iteration_count": iteration + 1,
                "is_consensus": False,
                "sycophancy_detected": syco,
                "confidence_history": [0.0],
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=f"[ERROR] Mediation {label}: {e or type(e).__name__}",
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

        # Slot-topology parity with the initial fan-out (builder.py). On a
        # single-slot local llama-server the analysts' revise calls must NOT
        # run concurrently or they clobber each other's per-slot recurrent
        # DeltaNet state → full re-prefill every step (the 2026-07-13 root
        # cause; see LLMConfig.parallel_analysts). The initial pass is
        # serialised by the graph edges, but this revision node fans out
        # itself, so it must honour the same flag. When sequential, await each
        # revise in turn (exclusive slot use); when parallel, keep the
        # concurrent gather for hosted multi-slot APIs. Both branches tolerate
        # a per-analyst failure (mirrors gather(return_exceptions=True)) so one
        # bad revise never aborts the round.
        parallel = True
        try:
            parallel = bool(container.config.llm.parallel_analysts)
        except AttributeError:
            parallel = True

        results: list[Any] = []
        if parallel:
            tasks = [_revise_one(name) for name in agent_names]
            results = list(await asyncio.gather(*tasks, return_exceptions=True))
        else:
            for name in agent_names:
                try:
                    results.append(await _revise_one(name))
                except Exception as exc:  # noqa: BLE001 — parity with gather()
                    results.append(exc)

        revised: dict[str, str] = {}
        revised_isrs: dict[str, AgentISR] = {}

        # strict=True: agent_names and results MUST be equal length; mismatch
        # is a programming error and must surface, not be silently truncated.
        for name, result in zip(agent_names, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("%s revision failed: %s", name, result)
                revised[name] = original_reports.get(name, "")
                revised_isrs[name] = _empty_isr(name, revision_round=iteration)
                emit_agent_message(
                    container.event_sink,
                    speaker=name,
                    role="reviser",
                    text=f"[ERROR] {name} revision failed: {result}",
                    round_index=iteration,
                    status="failed",
                )
            else:
                revised_text, isr = result
                revised[name] = revised_text
                revised_isrs[name] = isr
                emit_agent_message(
                    container.event_sink,
                    speaker=name,
                    role="reviser",
                    text=summarize_claims(isr.claims, speaker=name),
                    round_index=iteration,
                    status="complete" if isr.claims else "no_data",
                    claims=claims_to_payload(isr.claims),
                    dissent=list(isr.dissent_items or []),
                )

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

                attck_validator = ATTCKValidator.get_instance(
                    backend=container.config.preprocessing.attck_index_backend
                )
            except Exception as e:
                logger.warning("ATTCKValidator unavailable: %s. Skipping TTP validation.", e)

            isr_reports: dict[str, AgentISR] = dict(state.get("isr_reports") or {})

            # Wave 4: pick up the platform the bootstrap inferred. The
            # rule layers + cascade use this to drop platform-mismatched
            # signals (e.g. a Windows-only Sigma rule firing against a
            # Linux sample).
            sample_platform = state.get("platform") or "unknown"

            # 2026-07 audit: YARA scans the sample BYTES (not analyst prose) so
            # an API-name pattern only fires when the string is really in the
            # binary. Read from the worker-visible host path (same one the PE
            # extractor / family RAG use), not the container Ghidra path.
            def _read_sample_bytes() -> bytes | None:
                from pathlib import Path as _Path

                raw = state.get("sample_path") or state.get("static_sample_path")
                if not raw:
                    return None
                try:
                    return _Path(str(raw)).read_bytes()
                except Exception as _e:  # noqa: BLE001
                    logger.warning("YARA Layer 0: sample unreadable (%s). Skipping.", _e)
                    return None

            async def _run_yara_scan() -> AgentISR | None:
                try:
                    yara_layer = container.get_yara_layer()
                    if yara_layer.rule_count > 0:
                        sample_bytes = await asyncio.to_thread(_read_sample_bytes)
                        if not sample_bytes:
                            return None
                        yara_layer.reset_filter_stats()
                        yara_matches = await asyncio.to_thread(
                            yara_layer.scan, sample_bytes, sample_platform
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

            # 2026-07 audit: Sigma scans structured events built from real
            # sandbox telemetry (strict field matching) instead of analyst
            # prose. No telemetry -> no events -> no matches (correct for
            # static-only runs).
            async def _run_sigma_scan() -> AgentISR | None:
                try:
                    from maljan.analysis.sigma_layer import build_events_from_sandbox

                    sigma_layer = container.get_sigma_layer()
                    if sigma_layer.rule_count > 0:
                        _sbx = state.get("sandbox_report")
                        _sbx = _sbx if isinstance(_sbx, dict) else None
                        sigma_events = build_events_from_sandbox(_sbx)
                        if not sigma_events:
                            return None
                        sigma_layer.reset_filter_stats()
                        sigma_matches = await asyncio.to_thread(
                            sigma_layer.scan_events,
                            sigma_events,
                            "sandbox",
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

            # Deterministic network / command-line heuristic Layer 0 (2026-06-03):
            # surface DGA domains as T1568.002 and suspicious LOLBin execution as
            # T1218.x, mirroring the Sigma/YARA layers. Confidence is capped and
            # evidence-cited so a lone heuristic can't drive the verdict — the
            # cascade only boosts it on cross-layer corroboration. Both fail-safe.
            _sandbox_report = state.get("sandbox_report")
            _sandbox_report = _sandbox_report if isinstance(_sandbox_report, dict) else None
            try:
                dga_isr = build_dga_isr(build_network_iocs(_sandbox_report))
                if dga_isr is not None:
                    isr_reports["network_dga"] = dga_isr
                    logger.info(
                        "Network DGA Layer 0: %d T1568.002 claim(s) -> cascade domain='network'.",
                        len(dga_isr.claims),
                    )
            except Exception as e:  # noqa: BLE001
                logger.warning("Network DGA Layer 0 failed: %s. Skipping.", e)
            try:
                lolbin_isr = build_lolbin_isr(_sandbox_report)
                if lolbin_isr is not None:
                    isr_reports["lolbin"] = lolbin_isr
            except Exception as e:  # noqa: BLE001
                logger.warning("LOLBin Layer 0 failed: %s. Skipping.", e)

            # Import-capability Layer 0 (2026-07 round 2): turn the PE extractor's
            # deterministic import classification (+ static-string IOCs) into
            # grounded ATT&CK techniques (e.g. WS2_32 client + hard-coded domain
            # -> T1071). Closes the under-reporting gap the byte-scan YARA corpus
            # leaves. Fail-safe; builds static from the worker-readable path.
            try:
                from maljan.analysis.import_capability_layer import (
                    build_import_capability_isr,
                )
                from maljan.extractors.pe_extractor import build_static_analysis

                _host_imp = state.get("sample_path")
                if _host_imp:
                    _static_imp = build_static_analysis(sample_path=str(_host_imp))
                    import_isr = build_import_capability_isr(_static_imp)
                    if import_isr is not None:
                        isr_reports["import_capability"] = import_isr
            except Exception as e:  # noqa: BLE001
                logger.warning("Import-capability Layer 0 failed: %s. Skipping.", e)

            # Deterministic ATT&CK technique-ID correction (2026-06-01). Run
            # BEFORE the cascade so corrected IDs flow into corroboration, the
            # judge's grounding, the report and the STIX bundle. Re-grounds each
            # LLM analyst claim against the full-catalog TF-IDF index, replacing
            # the small model's loop-prone ID-recall guess. Layer-0 yara/sigma
            # ISRs are skipped (rule-authoritative). Fail-safe + config-gated.
            if (
                container.config.preprocessing.use_attck_autocorrect
                and attck_validator is not None
                and hasattr(attck_validator, "correct_isr_reports")
            ):
                try:
                    # Semantic cosine scores on a different scale than TF-IDF, so
                    # the backend selects which alignment threshold to apply.
                    _prep = container.config.preprocessing
                    _min_align = (
                        _prep.attck_autocorrect_min_alignment_semantic
                        if _prep.attck_index_backend == "semantic"
                        else _prep.attck_autocorrect_min_alignment
                    )
                    # Mutates claim.technique_id in place on the shared AgentISR
                    # objects, which this node already returns as "isr_reports"
                    # (below), so report_node / LTM see the corrected IDs.
                    # swap_valid defaults off (zero-regression: only fix invalid
                    # IDs) per the §1.5.2 ablation.
                    _n_corrected = attck_validator.correct_isr_reports(
                        isr_reports,
                        min_alignment=_min_align,
                        swap_valid=_prep.attck_autocorrect_swap_valid,
                    )
                    if _n_corrected:
                        logger.info(
                            "ATT&CK autocorrect: %d technique id(s) re-grounded before cascade.",
                            _n_corrected,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("ATT&CK autocorrect skipped: %s", exc, exc_info=True)

            # 2026-07 audit: mark domains that had no real input data this run so
            # the cascade can't count an absent layer as corroboration (the
            # T1497 "1.00 across dynamic,network,static,yara" inflation).
            _dyn_empty = True
            if isinstance(_sandbox_report, dict):
                _beh = _sandbox_report.get("behavior") or {}
                _dyn_empty = not (
                    (isinstance(_beh, dict) and (_beh.get("processes") or _beh.get("calls")))
                    or _sandbox_report.get("signatures")
                )
            _net_empty = True
            try:
                _net_iocs = build_network_iocs(_sandbox_report)
                _net_empty = not (
                    _net_iocs and (_net_iocs.domains or _net_iocs.ips or _net_iocs.urls)
                )
            except Exception as e:  # noqa: BLE001
                logger.debug("network-empty probe failed: %s (treating as empty).", e)
            _empty_domains = frozenset(
                d for d, empty in (("dynamic", _dyn_empty), ("network", _net_empty)) if empty
            )

            cascade_summary = None
            try:
                cascade_summary = TTPCascadeEngine().compute(
                    isr_reports,
                    sample_platform=sample_platform,
                    empty_domains=_empty_domains,
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

            bundle = await judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
                isr_reports=isr_reports,
                attck_validator=attck_validator,
                cascade_summary=cascade_summary,
                memory_store=memory_store,
                evidence_corpus=evidence_corpus or None,
                current_sample_id=state.get("file_hash"),
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
            # F2b (2026-07-05): an LLM analyst whose ReAct loop AND forced
            # synthesis both fail (e.g. a request timeout on a large binary)
            # yields an empty ISR, but if a later revision round emits
            # anything the analyst is reported as ``complete`` and never
            # lands in ``_failed_analysts`` above. Surface analysts that
            # produced *zero* claims as their own degradation signal so a
            # verdict assembled without a functioning primary analyst is not
            # presented at full confidence. (A benign sample still yields at
            # least one observational claim, so a truly empty ISR is a
            # failure signal, not a clean result.)
            _ANALYST_AGENTS = ("static", "dynamic", "network")
            _empty_analysts = [
                name
                for name in _ANALYST_AGENTS
                if name in isr_reports and not getattr(isr_reports.get(name), "claims", None)
            ]
            # D10: surface anti-emulation / anti-VM / sandbox-detection
            # signatures so the existing DEGRADED RUN banner can explain
            # the empty dynamic tab (sandbox traced nothing because the
            # sample noticed it was being observed). Pattern matched
            # case-insensitively against the signature name + description
            # so a sandbox's verbose copy ("Listens for changes in the
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
            # CONF-INFL-01 fix (2026-07-05): the previous guard required
            # ``_technique_count > 0`` and so silently *missed* the most
            # degraded outcome of all — a run with zero corroboration AND
            # zero techniques (every LLM analyst failed and no YARA/Sigma
            # layer fired). That left ``degraded_mode = False`` and shipped
            # an uncapped confidence for an evidence-free verdict. The LTM
            # quality gate below (``_corroborated == 0 and _technique_count
            # <= 1``) already treated that case as low-quality, so the two
            # gates disagreed. Trigger on zero corroboration regardless of
            # technique count and word the reason for the empty case.
            if _corroborated == 0:
                _degradation_reasons.append(
                    f"zero cross-layer corroboration ({_technique_count} single-layer techniques)"
                    if _technique_count > 0
                    else "no techniques mapped (no corroborating evidence)"
                )
            # Audit 2026-07-26 (Ö2): a missing sandbox report is itself a
            # degradation, and it was the one cause NOT represented here. With
            # CAPE unreachable ``_submit_to_sandbox`` swallows the error and
            # returns None, so the run silently becomes static-only; the
            # anti-emulation reason below cannot fire either because it needs a
            # sandbox report to inspect. If static analysis alone corroborated a
            # technique, ``degraded_mode`` stayed False and an uncapped
            # confidence shipped for a verdict formed without any dynamic
            # evidence. Verified live: the only operator signal was a single
            # "Sandbox submission failed" line in the worker log.
            if not state.get("sandbox_report"):
                _degradation_reasons.append(
                    "no sandbox report (dynamic detonation unavailable) — static-only evidence"
                )
            if _failed_analysts:
                _degradation_reasons.append(f"analyst failures: {', '.join(_failed_analysts)}")
            if _empty_analysts:
                _degradation_reasons.append(
                    f"analysts produced no claims: {', '.join(_empty_analysts)}"
                )
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
                    .set_token_usage(container.get_token_ledger().snapshot())
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

            # Function-hash attribution (deterministic, exact opcode-hash).
            # Read side: which known families this sample shares code with
            # (threaded into the report). Write side: upsert this sample's
            # function hashes under its inferred family so the corpus grows.
            # Fully gated + fail-safe; never affects the verdict.
            _func_hash_report: list[dict[str, Any]] = []
            _family_rag_report: list[dict[str, Any]] = []
            _attck_case_report: list[dict[str, Any]] = []
            try:
                from maljan.core.config import get_settings

                _cfg = get_settings()
                _static_path = state.get("static_sample_path")
                if (
                    _cfg.preprocessing.use_function_hash_attribution
                    and _cfg.mcp.ghidra.transport == "http"
                    and _cfg.memory.backend == "qdrant"
                    and _static_path
                ):
                    from maljan.analysis.function_hash_attribution import (
                        aggregate_matches,
                        fetch_bulk_function_hashes,
                        to_report_dicts,
                    )
                    from maljan.memory.function_hash_store import FunctionHashStore

                    _sample_id = state.get("file_hash", "") or ""
                    _funcs = fetch_bulk_function_hashes(
                        base_url=_cfg.mcp.ghidra.url,
                        auth_token=_cfg.mcp.ghidra.auth_token,
                        file_path=_static_path,
                        min_instructions=_cfg.preprocessing.function_hash_min_instructions,
                    )
                    if _funcs:
                        _fh_store = FunctionHashStore(
                            url=_cfg.memory.qdrant_url,
                            collection=_cfg.memory.qdrant_function_hash_collection,
                        )
                        # Read side: surface prior family overlap in the report.
                        _func_hash_report = to_report_dicts(
                            aggregate_matches(
                                _fh_store.match(
                                    [h for _n, h in _funcs],
                                    exclude_sample_id=_sample_id or None,
                                ),
                                max_families=_cfg.preprocessing.function_hash_max_matches,
                            )
                        )
                        # Write side: only persist under a grounded family so an
                        # UNKNOWN verdict cannot pollute the attribution corpus.
                        _family = infer_malware_category(
                            reports=state.get("reports") or {},
                            isr_reports=isr_reports,
                        ).value
                        if _family and _family.upper() != "UNKNOWN":
                            _fh_store.upsert_sample(_sample_id, _family, _funcs)
            except Exception as _e:
                logger.warning("Function-hash attribution skipped (%s). Verdict unaffected.", _e)

            # Family-feature RAG (read side): record the families retrieved by
            # static-feature similarity as report evidence. Reads the HOST binary
            # (pe_extractor), so it uses ``sample_path`` (not the container path).
            # LLM-centric: these are candidates the analyst weighed, not a verdict.
            # Fail-safe and gated OFF by default (no catalog -> no rows).
            try:
                from maljan.core.config import get_settings as _get_settings

                _cfg2 = _get_settings()
                _host = state.get("sample_path")
                if _cfg2.preprocessing.use_family_feature_rag and _host:
                    from maljan.analysis.family_feature_rag import (
                        build_sample_profile_text,
                        retrieve_candidates,
                    )
                    from maljan.analysis.family_feature_rag import (
                        to_report_dicts as _rag_to_report_dicts,
                    )
                    from maljan.extractors.pe_extractor import build_static_analysis
                    from maljan.memory.family_fingerprint_index import load_family_index

                    _static = build_static_analysis(sample_path=str(_host))
                    _index = load_family_index(_cfg2.preprocessing.family_fingerprint_catalog_path)
                    if _static is not None and _index is not None:
                        _cands = retrieve_candidates(
                            build_sample_profile_text(_static),
                            _index,
                            top_k=_cfg2.preprocessing.family_rag_top_k,
                            min_score=_cfg2.preprocessing.family_rag_min_score,
                        )
                        _family_rag_report = _rag_to_report_dicts(_cands)
            except Exception as _e:
                logger.warning("Family-feature RAG skipped (%s). Verdict unaffected.", _e)

            # ATT&CK case-prior RAG (§4 U2, read side): record the ATT&CK techniques
            # recurring in behaviourally-similar prior cases (mined from our own LTM)
            # as report evidence. Same host static profile as the family RAG, different
            # KB. LLM-centric: these are candidates the analyst weighed, not a verdict.
            # Fail-safe and gated OFF by default (no corpus -> no rows).
            try:
                from maljan.core.config import get_settings as _get_settings3

                _cfg3 = _get_settings3()
                _host3 = state.get("sample_path")
                if _cfg3.preprocessing.use_attck_case_rag and _host3:
                    from maljan.analysis.attck_case_rag import (
                        retrieve_techniques,
                    )
                    from maljan.analysis.attck_case_rag import (
                        to_report_dicts as _attck_to_report_dicts,
                    )
                    from maljan.analysis.family_feature_rag import build_sample_profile_text
                    from maljan.extractors.pe_extractor import build_static_analysis
                    from maljan.memory.attck_case_index import load_attck_case_index

                    _static3 = build_static_analysis(sample_path=str(_host3))
                    _index3 = load_attck_case_index(_cfg3.preprocessing.attck_case_corpus_path)
                    if _static3 is not None and _index3 is not None:
                        _techs = retrieve_techniques(
                            build_sample_profile_text(_static3),
                            _index3,
                            top_k=_cfg3.preprocessing.attck_case_rag_top_k,
                            min_score=_cfg3.preprocessing.attck_case_rag_min_score,
                            max_techniques=_cfg3.preprocessing.attck_case_rag_max_techniques,
                        )
                        _attck_case_report = _attck_to_report_dicts(_techs)
            except Exception as _e:
                logger.warning("ATT&CK-case RAG skipped (%s). Verdict unaffected.", _e)

            emit_agent_message(
                container.event_sink,
                speaker="Judge",
                role="judge",
                text=(
                    f"Verdict: {decision}."
                    + (
                        " Run flagged as degraded — "
                        + "; ".join(_degradation_reasons)
                        + ". Confidence is capped accordingly."
                        if _degraded_mode
                        else " All layers corroborated."
                    )
                ),
                round_index=state.get("iteration_count", 0),
                status="complete",
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
                # Exact opcode-hash family overlap, surfaced into the report's
                # FamilyAttribution.function_hash_matches by the report node.
                "function_hash_matches": _func_hash_report,
                # Family-feature RAG candidates (retrieved by static-feature
                # similarity), surfaced into FamilyAttribution.family_rag_candidates
                # by the report node. Empty unless the RAG is enabled with a catalog.
                "family_rag_candidates": _family_rag_report,
                # ATT&CK case-prior RAG candidates (recurring TTPs from similar prior
                # cases), surfaced into FamilyAttribution.attck_case_candidates by the
                # report node. Empty unless the RAG is enabled with a case corpus.
                "attck_case_candidates": _attck_case_report,
            }
        except Exception as e:  # noqa: BLE001 — per-run fault-isolation boundary
            # give_verdict() drives the LLM; on a constrained / local host it can
            # fail with a bare asyncio TimeoutError or a transient openai
            # APIConnectionError as well as AnalystError / LLMError. A failed final
            # verdict must degrade to a conservative "Suspicious" result, not abort
            # the run (and, in a batch eval, drop the whole sample).
            logger.error("Judge verdict %s: %s", type(e).__name__, e or "")
            emit_agent_message(
                container.event_sink,
                speaker="Judge",
                role="judge",
                text=(
                    f"[ERROR] Judge failed ({type(e).__name__}): {e or ''}. "
                    "Falling back to a conservative Suspicious verdict; the run is "
                    "marked degraded and its confidence capped."
                ),
                round_index=state.get("iteration_count", 0),
                status="failed",
            )
            # F16 (2026-07-05): a judge-body failure must ALSO flag the run as
            # degraded so the report node caps ``overall_confidence`` (CONF-INFL-01)
            # and the UI shows the DEGRADED banner. Without these keys the report
            # node saw ``degraded_mode`` unset and could ship an uncapped
            # confidence for a verdict the judge never actually produced.
            return {
                "final_decision": "Suspicious",
                "judge_report": f"[ERROR] Judge failed ({type(e).__name__}): {e or ''}",
                "stix_output": {},
                "degraded_mode": True,
                "degradation_reasons": [f"judge failed ({type(e).__name__})"],
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
        # is indistinguishable in the UI from a fully corroborated finding.
        if state.get("degraded_mode") and overall_confidence > DEGRADED_CONFIDENCE_CAP:
            logger.warning(
                "report_node: capping overall_confidence %.3f -> %.2f (degraded run: %s).",
                overall_confidence,
                DEGRADED_CONFIDENCE_CAP,
                "; ".join(state.get("degradation_reasons") or []) or "no reason recorded",
            )
            overall_confidence = DEGRADED_CONFIDENCE_CAP

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
                # Degraded-run signalling: surfaced as a banner so a numerically
                # high verdict/severity on a low-data run is not read as authoritative.
                degraded_mode=bool(state.get("degraded_mode")),
                degradation_reasons=cast("list[str]", state.get("degradation_reasons") or []),
                # Platform-gate persistence scanners (no Windows registry
                # persistence on a Linux sample, and vice versa).
                sample_platform=state.get("platform"),
            )
            report = builder.build_deterministic()
            # Thread the judge node's exact opcode-hash family overlap into the
            # report (deterministic code-reuse links). Best-effort post-build,
            # mirroring how ``similar_samples`` is populated in enrichment.
            _fh_matches = cast("list[dict[str, Any]]", state.get("function_hash_matches") or [])
            if _fh_matches and getattr(report, "attribution", None) is not None:
                report.attribution.function_hash_matches = _fh_matches
            # Same post-build threading for the family-feature RAG candidates.
            _rag_cands = cast("list[dict[str, Any]]", state.get("family_rag_candidates") or [])
            if _rag_cands and getattr(report, "attribution", None) is not None:
                report.attribution.family_rag_candidates = _rag_cands
            # Same post-build threading for the ATT&CK case-prior RAG candidates.
            _attck_cands = cast("list[dict[str, Any]]", state.get("attck_case_candidates") or [])
            if _attck_cands and getattr(report, "attribution", None) is not None:
                report.attribution.attck_case_candidates = _attck_cands
            # Report-reshaping Phase 1: attach the captured tool-loop evidence so
            # the Composer can ground the deep technical spine. Already size-
            # capped upstream (schemas.tool_evidence); stored verbatim here.
            _tool_ev = cast("dict[str, list[dict[str, Any]]]", state.get("tool_evidence") or {})
            if _tool_ev:
                report.technical_evidence = _tool_ev
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

        # Report-reshaping Phase 4: section-wise Composer authors the professional
        # spine (intro, technical-analysis subsections, C2 channels, conclusion),
        # each grounded in its isolated evidence bundle. Best-effort — a Composer
        # failure never blocks the report. None in mock / when composer disabled.
        try:
            composer = container.get_report_composer()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: ReportComposer unavailable (%s); skipping spine.", exc)
            composer = None
        if composer is not None:
            try:
                await composer.compose(report, state.get("isr_reports"))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: ReportComposer.compose raised (%s); spine skipped.", exc
                )

        # Report-reshaping Phase 5: deterministic figures (inline SVG + Ghidra
        # code listings) generated from the report's own data — real charts, no
        # fabricated screenshots. Best-effort; empty when data is absent.
        try:
            from maljan.reporting.figures import build_figures

            report.figures = build_figures(report)
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: figure generation failed (%s).", exc)

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
            "markdown_chars=%d, extended_objects=%d, fp_warnings=%d).",
            report.verdict,
            report.severity.rating,
            len(markdown),
            len(extended_dump.get("objects", [])) if extended_dump else 0,
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
