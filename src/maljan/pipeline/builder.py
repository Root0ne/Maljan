"""Dynamic graph builder that constructs the workflow from registered agents.

Instead of hardcoding which agents exist, the builder reads the AgentRegistry
and creates nodes and edges automatically. Adding a new agent to the registry
means the graph automatically includes it.

Parallelism: all analyst nodes start simultaneously from START (fan-out).
LangGraph waits for all analysts to complete before entering the negotiation
node (fan-in), reducing total wall-clock time from O(n) to O(1) in agent count.
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

    Flow:
        START -> [agent_1 || agent_2 || ... || agent_N]  <- parallel fan-out
        [all agents complete] -> negotiation             <- fan-in
        negotiation --(consensus or max iter)--> judge -> END
        negotiation --(no consensus)--> revision -> negotiation (loop)

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

    # 4. Fan-out: START -> all analysts in parallel
    #    LangGraph will start every analyst node simultaneously.
    for name in agent_names:
        builder.add_edge(START, f"{name}_analyst")

    # 5. Fan-in: each analyst -> negotiation
    #    LangGraph waits for ALL analyst nodes to finish before entering negotiation.
    for name in agent_names:
        builder.add_edge(f"{name}_analyst", "negotiation")

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
