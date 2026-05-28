"""Dynamic graph builder that constructs the workflow from registered agents.

Instead of hardcoding which agents exist, the builder reads the AgentRegistry
and creates nodes and edges automatically. Adding a new agent to the registry
means the graph automatically includes it.

Topology (Wave 7, 2026-05-28, THROUGHPUT-01):
  * When ``config.llm.parallel_analysts == True``: analysts fan out from
    START and fan in to negotiation. This is the right call for hosted
    APIs (OpenAI / Anthropic / Gemini) where each request gets its own
    server-side slot — total wall clock = O(slowest analyst).
  * When ``config.llm.parallel_analysts == False`` (the default for
    local single-slot llama-server deployments): analysts run in a
    deterministic sequential chain so each one gets the LLM slot to
    itself for its full per-agent timeout budget. With a single
    physical slot, "parallel" execution just produced N×N queue
    contention — every analyst spent its budget waiting for the slot
    instead of actually decoding. The chain is built in registry order;
    ``negotiation`` still consumes a merged state from every analyst.

The parallel topology is preserved verbatim so this is a pure runtime
toggle — no agent-side changes, no LangGraph reducer behaviour change.
"""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from maljan.core.container import ServiceContainer
from maljan.pipeline.nodes import (
    make_analyst_node,
    make_judge_node,
    make_negotiation_node,
    make_report_node,
    make_revision_node,
)
from maljan.pipeline.routing import ConsensusRouter
from maljan.pipeline.state import AnalysisState


def build_graph(container: ServiceContainer) -> CompiledStateGraph:
    """Builds and compiles the analysis workflow dynamically.

    Flow (parallel mode — hosted multi-slot LLM):
        START -> [agent_1 || agent_2 || ... || agent_N]  <- parallel fan-out
        [all agents complete] -> negotiation             <- fan-in
        negotiation --(consensus or max iter)--> judge -> END
        negotiation --(no consensus)--> revision -> negotiation (loop)

    Flow (sequential mode — local single-slot llama-server):
        START -> agent_1 -> agent_2 -> ... -> agent_N -> negotiation
        ... (same downstream)

    Args:
        container: The ServiceContainer providing registries and factories.

    Returns:
        A compiled LangGraph StateGraph ready for invocation.
    """
    builder = StateGraph(AnalysisState)

    # 1. Discover all registered expert agents
    agent_names = container.agent_registry.list_agents()

    if not agent_names:
        raise RuntimeError("No agents registered. Cannot build pipeline.")

    # 2. Create and add analyst nodes dynamically
    for name in agent_names:
        builder.add_node(f"{name}_analyst", make_analyst_node(name, container))

    # 3. Add negotiation, revision, judge, and report nodes. The report
    #    node only runs when ``config.reporting.enabled`` — the node itself
    #    short-circuits when disabled, so the topology stays unchanged.
    builder.add_node("negotiation", make_negotiation_node(container))
    builder.add_node("revision", make_revision_node(container))
    builder.add_node("judge", make_judge_node(container))

    reporting_enabled = True
    try:
        reporting_enabled = bool(container.config.reporting.enabled)
    except AttributeError:
        reporting_enabled = True
    if reporting_enabled:
        builder.add_node("report", make_report_node(container))

    # 4 + 5. Analyst topology — parallel fan-out (hosted) or sequential
    # chain (local single-slot). Default to sequential because the only
    # deployments where parallel is actually useful are hosted APIs;
    # local llama-server runs hit queue contention.
    parallel_analysts = True
    try:
        parallel_analysts = bool(container.config.llm.parallel_analysts)
    except AttributeError:
        parallel_analysts = True

    if parallel_analysts:
        # Fan-out: START -> all analysts in parallel
        # LangGraph starts every analyst node simultaneously.
        for name in agent_names:
            builder.add_edge(START, f"{name}_analyst")
        # Fan-in: each analyst -> negotiation
        # LangGraph waits for ALL analyst nodes to finish before entering
        # negotiation.
        for name in agent_names:
            builder.add_edge(f"{name}_analyst", "negotiation")
    else:
        # Sequential chain — each analyst gets the LLM slot to itself.
        builder.add_edge(START, f"{agent_names[0]}_analyst")
        for prev, nxt in zip(agent_names, agent_names[1:], strict=False):
            builder.add_edge(f"{prev}_analyst", f"{nxt}_analyst")
        builder.add_edge(f"{agent_names[-1]}_analyst", "negotiation")

    # 6. Conditional routing after negotiation
    router = ConsensusRouter(container.config)
    builder.add_conditional_edges(
        source="negotiation",
        path=router.should_continue,
        path_map={
            "revision": "revision",
            "judge": "judge",
        },
    )

    # 7. Revision loops back to negotiation
    builder.add_edge("revision", "negotiation")

    # 8. Judge -> report -> END (or Judge -> END when reporting is disabled).
    if reporting_enabled:
        builder.add_edge("judge", "report")
        builder.add_edge("report", END)
    else:
        builder.add_edge("judge", END)

    return builder.compile()
