"""Generic node factories for the LangGraph pipeline.

Instead of one hardcoded function per agent, we use a factory that
creates a node function for ANY registered agent. Adding a new agent
to the registry automatically makes it available as a graph node.

All references to specific agent names ("static", "dynamic", "network")
are eliminated — nodes work with whatever agents the registry contains.

Phase 1 additions:
  - Negotiation node runs sycophancy detection after collecting ISR reports.
  - Revision directive is augmented with devil's advocate injection if needed.
  - Confidence history is updated each negotiation round for adaptive termination.

Phase 3 (Chunked Pipeline) additions:
  - make_analyst_node() now calls load_chunked() instead of load_data().
  - When a sample produces >1 chunk (exceeds MAX_TOKENS_PER_CHUNK), each chunk
    is analyzed independently via safe_analyze_isr_chunked(), which calls
    analyze_isr() per chunk and merges results via merge_chunk_isrs().
  - Single-chunk samples take the same code path as before (no overhead).

Phase 3 (Revision Grounding) additions:
  - make_revision_node() no longer calls load_data() for original_data.
  - For single-chunk samples: uses raw text (same as before).
  - For multi-chunk samples: uses the agent's consolidated ISR text summary
    (state["reports"][name]) with a chunking context header, preventing
    the silent data truncation that load_data() caused for large samples.
  - _build_revision_context() implements this selection with zero extra I/O
    (chunk count derived from cached load_chunked() call).

Phase 5 (Long-Term Memory) additions:
  - make_judge_node() retrieves the memory store from the container and passes
    it to give_verdict() for few-shot context injection.
  - After a successful verdict, the result is persisted to the memory store
    via build_stored_case() so future analyses can retrieve it.
  - Store/retrieve errors are caught and logged — never block verdict generation.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.pipeline.state import AgentArgument, AnalysisState
from maljan.pipeline.sycophancy_detector import build_revision_directive, detect_sycophancy
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


def make_analyst_node(
    agent_name: str,
    container: ServiceContainer,
) -> Any:
    """Factory: creates a LangGraph node function for the given agent.

    Phase 3 (Chunked Pipeline):
      - Calls container.load_chunked() to get a list of TextChunk objects.
      - If the sample fits in a single chunk (most common case), falls through
        to the existing single-text ISR path (zero overhead).
      - If the sample produces multiple chunks, runs safe_analyze_isr_chunked()
        which analyzes each chunk independently and merges the results.
    """

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            mock_isr = AgentISR(
                agent_id=agent_name,
                domain=agent_name,  # type: ignore[arg-type]
                claims=[],
                dissent_items=[],
                revision_round=0,
            )
            return {
                "reports": {agent_name: f"MOCK: {agent_name} analysis complete."},
                "isr_reports": {agent_name: mock_isr},
            }

        try:
            agent = container.get_agent(agent_name)

            # Phase 3: Load as chunks — BinaryChunker decides whether to split.
            # When the data fits in one chunk (skip_if_fits=True), we get a
            # single-element list and take the optimised single-text path.
            chunks = container.load_chunked(state["file_hash"], agent_name)

            if len(chunks) == 1:
                # Fast path: no chunking overhead, existing ISR flow.
                isr = agent.safe_analyze_isr(chunks[0].content)
            else:
                # Chunked path: per-chunk analysis + hierarchical merge.
                logger.info(
                    "Agent '%s': processing %d chunks for sample '%s'.",
                    agent_name,
                    len(chunks),
                    state["file_hash"],
                )
                isr = agent.safe_analyze_isr_chunked(chunks)

            report = isr.to_text_summary() if isr.claims else agent.safe_analyze(chunks[0].content)
            return {
                "reports": {agent_name: report},
                "isr_reports": {agent_name: isr},
            }
        except (AnalystError, LLMError) as e:
            logger.error("%s analysis failed: %s", agent_name, e)
            error_isr = AgentISR(
                agent_id=agent_name,
                domain=agent_name,  # type: ignore[arg-type]
                claims=[],
                dissent_items=[],
                revision_round=0,
            )
            return {
                "reports": {agent_name: f"[ERROR] {agent_name} analysis failed: {e}"},
                "isr_reports": {agent_name: error_isr},
            }

    node_fn.__name__ = f"{agent_name}_analyst_node"
    node_fn.__doc__ = f"Auto-generated analysis node for '{agent_name}' agent."
    return node_fn


# ---------------------------------------------------------------------------
# Revision context builder (Phase 3: Chunked Grounding)
# ---------------------------------------------------------------------------


def _build_revision_context(
    state: AnalysisState,
    container: ServiceContainer,
    agent_name: str,
) -> str:
    """Select the appropriate original_data context for a revision round.

    Problem: In revision rounds, agents need 'original_data' as grounding
    context. Previously this was always loaded via container.load_data(),
    which silently truncated large samples via _truncate_input(). This meant
    an agent revising its analysis of a 40k-token sample saw fewer tokens
    during revision than during initial analysis — an inconsistency that
    can introduce hallucinations and unsupported backtracking.

    Solution:
      - Single-chunk samples: use the raw chunk text (same as before, no change).
      - Multi-chunk samples: use the agent's consolidated initial analysis summary
        (state["reports"][agent_name]) with a descriptive header. This is:
          a) Already token-budget-safe (it's a summary, not raw data).
          b) Fully grounded (it was produced from ALL chunks, not a truncated slice).
          c) Zero extra I/O (load_chunked() uses the data cache).

    Args:
        state:       Current pipeline state.
        container:   ServiceContainer for data access.
        agent_name:  Name of the agent being revised.

    Returns:
        A string suitable for passing as original_data to safe_revise_isr().
    """
    file_hash = state.get("file_hash", "")

    try:
        chunks = container.load_chunked(file_hash, agent_name)
    except Exception as exc:
        # Graceful degradation: fall back to raw load_data on any chunker error.
        logger.warning(
            "_build_revision_context: load_chunked failed for '%s/%s' (%s). "
            "Falling back to load_data().",
            file_hash,
            agent_name,
            exc,
        )
        return container.load_data(file_hash, agent_name)

    if len(chunks) == 1:
        # Single-chunk: raw text is safe to use directly (fits in context).
        return str(chunks[0].content)

    # Multi-chunk: use the already-produced ISR summary as context.
    # Prefer the most recent revised report over the initial report.
    revised = state.get("revised_reports") or {}
    reports = state.get("reports") or {}
    summary_text = revised.get(agent_name) or reports.get(agent_name, "")

    if not summary_text:
        # Fallback: no summary available yet (first revision, error path).
        logger.warning(
            "_build_revision_context: no summary for '%s' in state. Falling back to load_data().",
            agent_name,
        )
        return container.load_data(file_hash, agent_name)

    # Build context header so the agent understands its grounding source.
    total_chunks = chunks[0].total
    strategy = chunks[0].strategy.name
    header = (
        f"[CHUNKED ANALYSIS CONTEXT | domain={agent_name} | "
        f"chunks={total_chunks} | strategy={strategy}]\n"
        "This is your consolidated analysis summary produced from all "
        f"{total_chunks} chunks of the sample. Use it as grounding context "
        "for your revision; do not contradict findings without evidence.\n"
        "--- Consolidated Analysis Summary ---"
    )
    return f"{header}\n\n{summary_text}"


def make_negotiation_node(container: ServiceContainer) -> Any:
    """Factory: creates the mediator negotiation node.

    Phase 1 additions:
      - Runs sycophancy detection on the current ISR reports.
      - Stores sycophancy_detected flag and updates confidence_history.
      - The devil's advocate directive is built here; the revision node uses it.
    """

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        iteration = state.get("iteration_count", 0)
        agent_names = container.agent_registry.list_agents()

        # Use revised reports if available, otherwise originals
        revised = state.get("revised_reports") or {}
        original = state.get("reports") or {}
        active_reports = {name: revised.get(name) or original.get(name, "") for name in agent_names}

        # Collect current ISR reports for sycophancy detection
        current_isrs = list((state.get("isr_reports") or {}).values())

        if container.is_mock:
            is_consensus = iteration >= 1
            # Compute mock mean confidence for history
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

        # Sycophancy check (Phase 1)
        syco = detect_sycophancy(current_isrs) if current_isrs else False

        try:
            judge = JudgeAgent(llm=container.get_expert_llm())
            argument, is_consensus = judge.mediate(
                reports=active_reports,
                history=state.get("discussion_history") or [],
                isr_reports=state.get("isr_reports") or {},
            )

            # Compute mean confidence across ISRs for adaptive termination
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


def make_revision_node(container: ServiceContainer) -> Any:
    """Factory: creates the revision node where all agents revise their reports.

    Phase 1 additions:
      - If sycophancy was detected, the devil's advocate directive is prepended
        to the mediator feedback so agents are forced to find counter-evidence.
      - ISR dissent_items are validated: round > 0 with empty dissent_items is
        treated as a convergence signal.
    """

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        agent_names = container.agent_registry.list_agents()
        iteration = state.get("iteration_count", 0)

        # Get latest mediator feedback
        history = state.get("discussion_history") or []
        mediator_feedback = ""
        for arg in reversed(history):
            if arg.agent_name == "Mediator":
                mediator_feedback = arg.finding
                break

        # Inject devil's advocate directive if sycophancy detected (Phase 1)
        syco_detected = state.get("sycophancy_detected", False)
        revision_directive = build_revision_directive(syco_detected, mediator_feedback)

        original_reports = state.get("reports") or {}

        if container.is_mock:
            mock_isrs: dict[str, AgentISR] = {}
            for name in agent_names:
                mock_isrs[name] = AgentISR(
                    agent_id=name,
                    domain=name,  # type: ignore[arg-type]
                    claims=[],
                    dissent_items=[],
                    revision_round=iteration,
                )
            return {
                "revised_reports": {
                    name: f"MOCK REVISED: {name} analysis updated." for name in agent_names
                },
                "isr_reports": mock_isrs,
            }

        revised: dict[str, str] = {}
        revised_isrs: dict[str, AgentISR] = {}

        for name in agent_names:
            try:
                # Phase 3: Use chunked-aware revision context instead of raw load_data().
                # For single-chunk samples: raw text (same as before).
                # For multi-chunk samples: consolidated ISR summary (no truncation).
                data = _build_revision_context(state, container, name)
                agent = container.get_agent(name)
                own_report = original_reports.get(name, "")
                peer_reports = {k: v for k, v in original_reports.items() if k != name}
                # Use ISR-aware revision path
                revised_text, isr = agent.safe_revise_isr(
                    original_data=data,
                    own_report=own_report,
                    peer_reports=peer_reports,
                    mediator_feedback=revision_directive,
                    revision_round=iteration,
                )
                revised[name] = revised_text
                revised_isrs[name] = isr
            except (AnalystError, LLMError) as e:
                logger.error("%s revision failed: %s", name, e)
                revised[name] = original_reports.get(name, "")
                revised_isrs[name] = AgentISR(
                    agent_id=name,
                    domain=name,  # type: ignore[arg-type]
                    claims=[],
                    dissent_items=[],
                    revision_round=iteration,
                )

        return {"revised_reports": revised, "isr_reports": revised_isrs}

    node_fn.__name__ = "revision_node"
    return node_fn


def make_judge_node(container: ServiceContainer) -> Any:
    """Factory: creates the final judge verdict node."""

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        if container.is_mock:
            return {
                "final_decision": "Malware",
                "judge_report": "MOCK: Evaluated all indicators.",
                "stix_output": {},
                "run_summary": None,
            }

        try:
            judge = JudgeAgent(llm=container.get_judge_llm())

            revised = state.get("revised_reports") or {}
            original = state.get("reports") or {}
            reports = {
                name: revised.get(name) or original.get(name, "")
                for name in container.agent_registry.list_agents()
            }

            # Phase 4.2: attempt to obtain the cached ATT&CK validator.
            # If the cache has not been built yet (first run without network),
            # validation is silently skipped — verdict generation always continues.
            attck_validator = None
            try:
                from maljan.memory.attck_validator import ATTCKValidator

                attck_validator = ATTCKValidator.get_instance()
            except Exception as e:
                logger.warning("ATTCKValidator unavailable: %s. Skipping TTP validation.", e)

            # Phase 4.3: compute three-layer TTP cascade from ISR reports.
            # Stateless — runs in microseconds; degrades gracefully on error.
            cascade_summary = None
            isr_reports = state.get("isr_reports") or {}
            try:
                from maljan.analysis.ttp_cascade import TTPCascadeEngine

                cascade_summary = TTPCascadeEngine().compute(isr_reports)
            except Exception as e:
                logger.warning("TTP cascade failed: %s. Skipping.", e)

            # Start timing for RunSummary
            _start_time = time.time()

            # Phase 5: retrieve long-term memory context for few-shot priming.
            # get_memory_store() is cached — no repeated construction cost.
            memory_store: MemoryStore | None = None
            try:
                memory_store = container.get_memory_store()  # type: ignore[assignment]
            except Exception as e:
                logger.warning("Memory store unavailable: %s. Skipping LTM context.", e)

            bundle = judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
                isr_reports=isr_reports,
                attck_validator=attck_validator,
                cascade_summary=cascade_summary,
                memory_store=memory_store,
            )

            stix_output = {}
            if isinstance(bundle, Bundle):
                stix_output = bundle.model_dump()

            decision = "Suspicious"
            for obj in bundle.objects:
                if hasattr(obj, "type") and obj.type == "malware":
                    decision = "Malware"
                    break

            # Build validation summary for RunSummary (re-run is cheap)
            ttp_validation_summary = None
            if attck_validator and hasattr(attck_validator, "validate_isr_reports") and isr_reports:
                try:
                    ttp_validation_summary = attck_validator.validate_isr_reports(isr_reports)
                except Exception:
                    pass

            # Phase Observability: build RunSummary
            run_summary_dict = None
            try:
                from maljan.analysis.run_summary import RunSummaryBuilder

                _max_iters = container.config.negotiation.max_iterations
                summary = (
                    RunSummaryBuilder(start_time=_start_time)
                    .set_sample(state.get("file_hash", ""), state.get("file_name"))
                    .set_verdict(decision, len(bundle.objects) if isinstance(bundle, Bundle) else 0)
                    .set_negotiation({**state, "_max_iterations": _max_iters})
                    .set_isr_stats(isr_reports)
                    .set_validation_summary(ttp_validation_summary)
                    .set_cascade_summary(cascade_summary)
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

            # Phase 5: persist this result to long-term memory for future retrievals.
            # Infer malware category from schema_pruner (already runs in judge.give_verdict;
            # re-run here is cheap — keyword scoring only, no LLM call).
            if memory_store is not None and isr_reports:
                try:
                    from maljan.analysis.schema_pruner import infer_malware_category
                    from maljan.memory.long_term_memory import build_stored_case

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
                    )
                    memory_store.store(case)
                    logger.info(
                        "LTM: stored case '%s' (category=%s, techniques=%d).",
                        case.sample_id,
                        case.malware_category,
                        len(case.technique_ids),
                    )
                except Exception as e:
                    logger.warning("LTM store failed (%s). Analysis result is unaffected.", e)

            return {
                "final_decision": decision,
                "judge_report": "Analyzed negotiation history and expert reports.",
                "stix_output": stix_output,
                "run_summary": run_summary_dict,
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
