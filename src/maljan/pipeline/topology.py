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
    dependents start at more than one node. With a single downstream entry the
    barrier is redundant — LangGraph already waits for every predecessor of a
    node — and adding it would have renamed the fan-in of the default profile.
  * A debate stage contributes ``negotiation`` and ``revision``, prefixed
    ``<stage>__`` when a profile holds more than one debate. One debate is the
    overwhelmingly common case and the one the console was written against.
  * The verdict stage is ``judge`` and the report stage is ``report``. A
    profile has exactly one of the first and at most one of the second, so
    neither can collide.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    exit means "this stage arranges its own way out".
    """

    stage: StageDefinition
    nodes: tuple[str, ...]
    entry: tuple[str, ...]
    exit: tuple[str, ...]


def dependents(profile: ProfileDefinition, key: str) -> list[StageDefinition]:
    """The stages that declare ``key`` among their dependencies."""
    return [s for s in profile.stages if key in s.depends_on]


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
    return out


def _entry_nodes(profile: ProfileDefinition, stage: StageDefinition) -> tuple[str, ...]:
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
        if len(downstream) > 1:
            barrier = join_node(stage)
            return StageNodes(stage, (*agents, barrier), entry, (barrier,))
        return StageNodes(stage, agents, entry, agents)
    if stage.kind == "debate":
        negotiation, revision = debate_nodes(profile, stage)
        return StageNodes(stage, (negotiation, revision), entry, ())
    if stage.kind == "verdict":
        return StageNodes(stage, (JUDGE_NODE,), entry, (JUDGE_NODE,))
    return StageNodes(stage, (REPORT_NODE,), entry, (REPORT_NODE,))
