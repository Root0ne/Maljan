"""What each stage of a profile is called once it becomes graph nodes.

Node names are not an implementation detail here. They are in every transcript
row, every ``agent_progress`` event, every stored run's phase log and the
console's pipeline panel, so the names the default profile produces have to be
the names it produced before it was written as stages — ``static_analyst``,
``negotiation``, ``revision``, ``judge``, ``report``.

The rules are therefore written once, in one module, and read by both the
builder (which creates the nodes) and the nodes themselves (which have to know
which stage they belong to). Putting them in the builder would have made the
nodes import the builder that imports them.

  * An analysis stage contributes one node per agent, ``<agent>_analyst``. No
    stage prefix: a profile may not put the same agent in two stages, so the
    agent key is already unique across the graph.
  * A parallel analysis stage contributes a barrier ``<stage>__join`` when its
    dependents start at more than one node, and when nothing depends on it at
    all. With a single downstream entry the barrier node is redundant: the
    builder enters a node with several upstream tails through one list edge,
    which waits for all of them, and adding the node would have renamed the
    fan-in of the default profile. LangGraph does not wait on its own —
    separate single-source edges into one node are separate triggers, and the
    node runs once per trigger — which is why the builder always groups the
    tails. With no downstream at all there is nowhere the stage could be
    closed from, and each of its agents would announce the stage finished from
    its own half of the merged result.
  * A debate stage contributes ``negotiation`` and ``revision``, prefixed
    ``<stage>__`` when a profile holds more than one debate, and a barrier
    ``<stage>__join`` when nothing depends on it — the router's way out has to
    lead somewhere that sees the finished debate — or when the stage after it
    also depends on another stage: the router's edge is conditional and a
    list edge cannot wait on it, so the debate's barrier is the tail the next
    stage joins. One debate is the overwhelmingly common case and the one the
    console was written against.
  * The verdict stage is ``judge`` and the report stage is ``report``. A
    profile has exactly one of the first and at most one of the second, so
    neither can collide.
  * A triage stage is one node named after the stage itself. It has no agent
    to be named after, and a stage key is unique in its profile.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — types only
    from maljan.core.config import ProfileDefinition, StageDefinition

JOIN_SUFFIX = "__join"
NEGOTIATION_NODE = "negotiation"
REVISION_NODE = "revision"
JUDGE_NODE = "judge"
REPORT_NODE = "report"


def analyst_node(agent: str) -> str:
    """The node an analysis-stage agent runs as."""
    return f"{agent}_analyst"


def join_node(stage: StageDefinition) -> str:
    return f"{stage.key}{JOIN_SUFFIX}"


def debate_nodes(profile: ProfileDefinition, stage: StageDefinition) -> tuple[str, str]:
    """``(negotiation, revision)`` for one debate stage."""
    debates = [s.key for s in profile.stages if s.kind == "debate"]
    if len(debates) <= 1:
        return NEGOTIATION_NODE, REVISION_NODE
    return f"{stage.key}__{NEGOTIATION_NODE}", f"{stage.key}__{REVISION_NODE}"


@dataclass(frozen=True)
class StageNodes:
    """One stage's nodes, and which of them the graph attaches edges to.

    ``entry`` is what a dependency's exit points at; ``exit`` is what points at
    the next stage. A debate stage's outgoing edge is conditional and the
    builder wires it itself, which is why ``exit`` is empty there — an empty
    exit means "this stage arranges its own way out". A terminal debate is the
    exception: it leaves through a barrier of its own, so that the stage has
    one node that runs after everything in it is done.

    ``starter`` is the one node that announces the stage began, so a stage of
    three analysts announces itself once rather than three times.
    ``finisher`` is the one node that announces it ended, filled in by ``plan``
    once every stage's entry points are known — see ``_finisher`` for why it is
    sometimes a node belonging to the *next* stage.
    """

    stage: StageDefinition
    nodes: tuple[str, ...]
    entry: tuple[str, ...]
    exit: tuple[str, ...]
    starter: str = ""
    finisher: tuple[str, ...] = ()


def dependents(profile: ProfileDefinition, key: str) -> list[StageDefinition]:
    """The stages that declare ``key`` among their dependencies."""
    return [s for s in profile.stages if key in s.depends_on]


def adopted_roots(stages: list[StageDefinition]) -> tuple[str | None, list[str]]:
    """The triage stage that stands in for START, and the roots it adopts.

    A stage with no dependency among ``stages`` is a root and would start at
    START. When the first such root is a triage stage, every other root starts
    after it instead: the facts it writes come before anything that reads
    them. Returned as stage keys, so the builder that wires the edges and the
    team preview that draws them read the one rule.
    """
    keys = {stage.key for stage in stages}
    roots = [stage for stage in stages if not any(k in keys for k in stage.depends_on)]
    first = next((stage for stage in roots if stage.kind == "triage"), None)
    if first is None:
        return None, []
    return first.key, [stage.key for stage in roots if stage is not first]


def plan(profile: ProfileDefinition, *, reporting_enabled: bool = True) -> list[StageNodes]:
    """Every stage of ``profile`` as the nodes it becomes, in declaration order.

    ``reporting_enabled=False`` drops the report stage entirely, which is what
    ``reporting.enabled`` has always done: the graph ends at the judge and the
    downstream consumers fall back to the judge's own bundle.
    """
    live = [s for s in profile.stages if reporting_enabled or s.kind != "report"]
    live_keys = {s.key for s in live}
    entries: dict[str, tuple[str, ...]] = {}
    out: list[StageNodes] = []

    # Two passes: the join decision needs the downstream stages' entry nodes,
    # and a stage's dependents are always declared after it, so the entry
    # points are collected first and the joins decided second.
    for stage in live:
        entries[stage.key] = _entry_nodes(profile, stage)

    for stage in live:
        out.append(_stage_nodes(profile, stage, entries, live_keys))

    by_key = {planned.stage.key: planned for planned in out}
    return [
        replace(planned, starter=planned.entry[0], finisher=_finisher(profile, planned, by_key))
        for planned in out
    ]


def _finisher(
    profile: ProfileDefinition, planned: StageNodes, by_key: dict[str, StageNodes]
) -> tuple[str, ...]:
    """The node(s) that announce ``planned`` finished, and when.

    A stage with a single terminal node of its own — a sequential chain, a
    barrier, the judge, the report — announces its own end from it. Two shapes
    have no such node: a parallel analysis stage without a barrier, whose
    agents all end at once, and a debate, which loops and leaves through a
    conditional edge. Both of them already have exactly one node downstream
    that runs after they are done and sees their merged state, and that node is
    what announces them. It is the barrier they did not need.

    The remaining case is a stage nothing depends on and that has no single
    exit: each of its own nodes announces it, because there is nothing after it
    that could.
    """
    if len(planned.exit) == 1:
        return (planned.exit[0],)
    downstream: list[str] = []
    for dependent in profile.stages:
        if planned.stage.key not in dependent.depends_on:
            continue
        following = by_key.get(dependent.key)
        if following is not None:
            downstream.extend(following.entry)
    if len(downstream) == 1:
        return (downstream[0],)
    return tuple(planned.exit) or tuple(planned.nodes)


def triage_node(stage: StageDefinition) -> str:
    """The node a triage stage runs as."""
    return stage.key


def _entry_nodes(profile: ProfileDefinition, stage: StageDefinition) -> tuple[str, ...]:
    if stage.kind == "triage":
        return (triage_node(stage),)
    if stage.kind == "analysis":
        if stage.mode == "parallel":
            return tuple(analyst_node(a) for a in stage.agents)
        return (analyst_node(stage.agents[0]),)
    if stage.kind == "debate":
        return (debate_nodes(profile, stage)[0],)
    if stage.kind == "verdict":
        return (JUDGE_NODE,)
    return (REPORT_NODE,)


def _stage_nodes(
    profile: ProfileDefinition,
    stage: StageDefinition,
    entries: dict[str, tuple[str, ...]],
    live_keys: set[str],
) -> StageNodes:
    entry = entries[stage.key]
    if stage.kind == "triage":
        node = triage_node(stage)
        return StageNodes(stage, (node,), entry, (node,))
    if stage.kind == "analysis":
        agents = tuple(analyst_node(a) for a in stage.agents)
        if stage.mode != "parallel":
            return StageNodes(stage, agents, entry, (agents[-1],))
        downstream = {
            node
            for dependent in dependents(profile, stage.key)
            if dependent.key in live_keys
            for node in entries[dependent.key]
        }
        if len(downstream) > 1 or (not downstream and len(agents) > 1):
            barrier = join_node(stage)
            return StageNodes(stage, (*agents, barrier), entry, (barrier,))
        return StageNodes(stage, agents, entry, agents)
    if stage.kind == "debate":
        negotiation, revision = debate_nodes(profile, stage)
        following = [d for d in dependents(profile, stage.key) if d.key in live_keys]
        # The router's way out is a conditional edge, which a barrier cannot
        # wait on. A debate hands over straight to the next stage only when
        # that stage waits for nothing else; otherwise it leaves through a
        # barrier of its own, and that barrier is one of the tails the next
        # stage joins.
        joins_others = any(
            key != stage.key and key in live_keys
            for dependent in following
            for key in dependent.depends_on
        )
        if following and not joins_others:
            return StageNodes(stage, (negotiation, revision), entry, ())
        barrier = join_node(stage)
        return StageNodes(stage, (negotiation, revision, barrier), entry, (barrier,))
    if stage.kind == "verdict":
        return StageNodes(stage, (JUDGE_NODE,), entry, (JUDGE_NODE,))
    return StageNodes(stage, (REPORT_NODE,), entry, (REPORT_NODE,))
