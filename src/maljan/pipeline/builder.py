"""Dynamic graph builder that constructs the workflow from registered agents.

Instead of hardcoding which agents exist, the builder reads the AgentRegistry
and creates nodes and edges automatically. Adding a new agent to the registry
means the graph automatically includes it.
"""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from maljan.core.container import ServiceContainer
from maljan.pipeline.nodes import (
    make_analyst_node,
    make_judge_node,
    make_negotiation_node,
    make_revision_node,
)
from maljan.pipeline.routing import ConsensusRouter
from maljan.pipeline.state import AnalysisState


def build_graph(container: ServiceContainer) -> CompiledStateGraph:
    """Builds and compiles the analysis workflow dynamically.

    Flow:
        START -> agent_1 -> agent_2 -> ... -> agent_N -> negotiation
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

    # 3. Add negotiation, revision, and judge nodes
    builder.add_node("negotiation", make_negotiation_node(container))
    builder.add_node("revision", make_revision_node(container))
    builder.add_node("judge", make_judge_node(container))

    # 4. Wire the sequential analyst chain: START -> agent1 -> agent2 -> ... -> negotiation
    builder.add_edge(START, f"{agent_names[0]}_analyst")
    for i in range(len(agent_names) - 1):
        builder.add_edge(f"{agent_names[i]}_analyst", f"{agent_names[i + 1]}_analyst")
    builder.add_edge(f"{agent_names[-1]}_analyst", "negotiation")

    # 5. Conditional routing after negotiation
    router = ConsensusRouter(container.config)
    builder.add_conditional_edges(
        source="negotiation",
        path=router.should_continue,
        path_map={
            "revision": "revision",
            "judge": "judge",
        },
    )

    # 6. Revision loops back to negotiation
    builder.add_edge("revision", "negotiation")

    # 7. Judge -> END
    builder.add_edge("judge", END)

    return builder.compile()
