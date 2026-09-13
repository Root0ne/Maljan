"""The graph builder: a profile's stages, turned into a LangGraph workflow.

A team is an ordered list of dependent stages — triage, static, dynamic,
reversing, network and threat intel, correlation, report — and this is where
that list becomes nodes and edges. Nothing is hardcoded: the analysts, the
debate, the verdict and the report are all stages, and a profile that arranges
them differently builds a different graph without a line of code changing.

Two properties are load-bearing.

**The default profile builds the graph it always built.** Its four stages are
the pipeline that exists today, and ``pipeline.topology`` names their nodes
``static_analyst`` / ``negotiation`` / ``revision`` / ``judge`` / ``report`` so
every transcript, stored run and console view keeps working. The graph is
pinned by ``tests/fixtures/golden/graph_default.json`` in both analyst modes.

**The topology is a property of the configuration, never of the sample.** A
stage carries a ``when`` condition, but the condition is evaluated inside the
stage's nodes at run time, not here: a stage that declines to run is still in
the graph and still records a ``StageResult`` saying it was skipped and why.
Building a different graph per sample would mean a run's shape could not be
predicted, compared or drawn before the sample arrived.

Analyst mode is per analysis stage now. ``parallel`` fans the stage's agents
out and lets LangGraph wait for all of them, which is right for a hosted
multi-slot API; ``sequential`` chains them so each gets the single local
llama-server slot to itself for its whole timeout budget. The global
``llm.parallel_analysts`` still decides the mode of a profile that is stored as
a plain analyst list and has never been opened as stages.
"""

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from maljan.core.config import ProfileDefinition
from maljan.core.container import ServiceContainer
from maljan.core.memprobe import instrument_node
from maljan.pipeline.nodes import (
    make_join_node,
    make_judge_node,
    make_negotiation_node,
    make_report_node,
    make_revision_node,
    make_stage_agent_node,
)
from maljan.pipeline.routing import ConsensusRouter
from maljan.pipeline.state import AnalysisState
from maljan.pipeline.topology import (
    JOIN_SUFFIX,
    JUDGE_NODE,
    REPORT_NODE,
    StageNodes,
    analyst_node,
    debate_nodes,
    dependents,
    plan,
)


def build_graph(container: ServiceContainer) -> CompiledStateGraph:
    """Build and compile the active profile's workflow.

    Args:
        container: The ServiceContainer providing registries and factories.

    Returns:
        A compiled LangGraph StateGraph ready for invocation.
    """
    profile = container.active_profile()
    reporting_enabled = True
    try:
        reporting_enabled = bool(container.config.reporting.enabled)
    except AttributeError:
        reporting_enabled = True

    staged = plan(profile, reporting_enabled=reporting_enabled)
    if not staged:
        # Unreachable through a validated ``Settings``: ``ProfileDefinition``
        # refuses a profile with no stages and demands exactly one verdict
        # stage, and the API refuses one before it is ever stored. Kept as the
        # backstop it is — a graph with no nodes compiles cleanly and then
        # produces a verdict out of nothing, which is far worse to debug.
        raise RuntimeError(
            f"Profile {container.config.agents.profile!r} has no stages. Cannot build pipeline."
        )

    builder = StateGraph(AnalysisState)
    by_key: dict[str, StageNodes] = {entry.stage.key: entry for entry in staged}

    # 1. Nodes, and the edges that live inside one stage. Every node is wrapped
    #    in ``instrument_node`` so resident memory is reported on each side of
    #    it — node boundaries are the finest phase granularity that exists
    #    here, since the worker's ``phase_change`` events treat everything from
    #    the first analyst to the judge as one ``analyzing`` phase. See
    #    ``core/memprobe`` for why this exists.
    for entry in staged:
        _add_stage(builder, container, profile, entry, by_key)

    # 2. Edges between stages. A stage with no live dependency starts at START;
    #    a stage nothing live depends on ends at END. A debate stage's way out
    #    is the router's conditional edge, wired with the stage itself, which
    #    is why its ``exit`` is empty.
    for entry in staged:
        stage = entry.stage
        upstream = [by_key[key] for key in stage.depends_on if key in by_key]
        if not upstream:
            for node in entry.entry:
                builder.add_edge(START, node)
        for source in upstream:
            for tail in source.exit:
                for head in entry.entry:
                    builder.add_edge(tail, head)
        live_dependents = [d for d in dependents(profile, stage.key) if d.key in by_key]
        if entry.exit and not live_dependents:
            for tail in entry.exit:
                builder.add_edge(tail, END)

    return builder.compile()


def _add_stage(
    builder: StateGraph,
    container: ServiceContainer,
    profile: ProfileDefinition,
    entry: StageNodes,
    by_key: dict[str, StageNodes],
) -> None:
    """Add one stage's nodes and every edge that lives inside it."""
    stage = entry.stage
    if stage.kind == "analysis":
        _add_analysis_stage(builder, container, entry)
    elif stage.kind == "debate":
        _add_debate_stage(builder, container, profile, entry, by_key)
    elif stage.kind == "verdict":
        builder.add_node(
            JUDGE_NODE, instrument_node(JUDGE_NODE, make_judge_node(container, stage=stage))
        )
    else:
        builder.add_node(
            REPORT_NODE, instrument_node(REPORT_NODE, make_report_node(container, stage=stage))
        )


def _add_analysis_stage(
    builder: StateGraph, container: ServiceContainer, entry: StageNodes
) -> None:
    stage = entry.stage
    for agent in stage.agents:
        name = analyst_node(agent)
        builder.add_node(
            name, instrument_node(name, make_stage_agent_node(stage, agent, container))
        )
    if stage.mode != "parallel":
        for previous, following in zip(stage.agents, stage.agents[1:], strict=False):
            builder.add_edge(analyst_node(previous), analyst_node(following))
        return
    barriers = [node for node in entry.nodes if node.endswith(JOIN_SUFFIX)]
    for barrier in barriers:
        builder.add_node(barrier, instrument_node(barrier, make_join_node(stage)))
        for agent in stage.agents:
            builder.add_edge(analyst_node(agent), barrier)


def _add_debate_stage(
    builder: StateGraph,
    container: ServiceContainer,
    profile: ProfileDefinition,
    entry: StageNodes,
    by_key: dict[str, StageNodes],
) -> None:
    """The negotiation/revision pair, and the router that decides between them.

    The router's ``judge`` branch does not go to the judge by name: it goes to
    whatever this debate stage feeds, which in the default profile is the
    verdict stage's ``judge`` node and in a longer pipeline may be the next
    analysis stage. A conditional edge has one destination per branch, so a
    debate that feeds two stages is refused here rather than silently routed to
    whichever one came first.
    """
    stage = entry.stage
    negotiation, revision = debate_nodes(profile, stage)
    builder.add_node(
        negotiation,
        instrument_node(negotiation, make_negotiation_node(container, stage=stage)),
    )
    builder.add_node(
        revision, instrument_node(revision, make_revision_node(container, stage=stage))
    )

    heads: list[str] = []
    for dependent in dependents(profile, stage.key):
        downstream = by_key.get(dependent.key)
        if downstream is not None:
            heads.extend(downstream.entry)
    if len(heads) > 1:
        raise RuntimeError(
            f"stage {stage.key!r} is a debate that feeds {len(heads)} nodes; "
            "a debate hands over to exactly one stage"
        )
    onward = heads[0] if heads else END

    router = ConsensusRouter(container.config, stage=stage)
    builder.add_conditional_edges(
        source=negotiation,
        path=router.should_continue,
        path_map={"revision": revision, "judge": onward},
    )
    builder.add_edge(revision, negotiation)
