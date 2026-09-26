"""Where each stage of a team sits when the team is drawn.

One layout, read by both pictures of a team: the SVGs on the architecture page
(``scripts/goldens/render_team_graphs.py``) and the live preview beside the
team editor in the console. A team is drawn top to bottom in run order, a
stage one row below the lowest stage it runs after, and stages that share a
row side by side in the order they are written. A team that is one chain —
every seeded team is — is therefore the single column the architecture page
has always shown.

Edges are ``depends_on`` as written, plus the ones the builder adds on its
own: a root stage that the triage pack adopts runs after it without saying so
(``pipeline.topology.adopted_roots``), and the picture shows that edge marked
as implicit rather than leaving the stage floating beside the pack. An edge to
a stage declared later is drawn and marked illegal — it is what save refuses —
and does not move anything, so a team with a loop in it still has a layout.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maljan.core.config import StageDefinition
from maljan.pipeline.topology import adopted_roots

__all__ = ["TeamEdge", "TeamLayout", "TeamNode", "layout_team"]


@dataclass(frozen=True)
class TeamNode:
    key: str
    label: str
    kind: str
    agents: tuple[str, ...]
    when: str
    reads: str
    mode: str
    row: int
    column: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "kind": self.kind,
            "agents": list(self.agents),
            "when": self.when,
            "reads": self.reads,
            "mode": self.mode,
            "row": self.row,
            "column": self.column,
        }


@dataclass(frozen=True)
class TeamEdge:
    source: str
    target: str
    implicit: bool = False
    legal: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "implicit": self.implicit,
            "legal": self.legal,
        }


@dataclass(frozen=True)
class TeamLayout:
    nodes: tuple[TeamNode, ...]
    edges: tuple[TeamEdge, ...]
    rows: int
    columns: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "rows": self.rows,
            "columns": self.columns,
        }

    def outgoing(self, key: str) -> list[TeamEdge]:
        return [edge for edge in self.edges if edge.source == key]

    def node(self, key: str) -> TeamNode | None:
        return next((node for node in self.nodes if node.key == key), None)


def layout_team(stages: list[StageDefinition]) -> TeamLayout:
    """Every stage's row and column, and every edge between stages.

    A stage whose key repeats an earlier one is drawn once, at the first; the
    repeat is a save refusal the lint reports on it by name.

    Rows are longest paths over the legal and implicit edges, found by Kahn's
    method — each stage placed once its last predecessor is — so any team costs
    its stages plus its edges. Those edges cannot form a loop: a legal edge
    points at an earlier stage, and an implicit one leads from the triage root
    to a root with no other dependency.
    """
    first, adopted = adopted_roots(stages)
    adopted_set = set(adopted)
    ordered: list[StageDefinition] = []
    position: dict[str, int] = {}
    for stage in stages:
        if stage.key not in position:
            position[stage.key] = len(ordered)
            ordered.append(stage)

    edges: list[TeamEdge] = []
    predecessors: dict[str, list[str]] = {stage.key: [] for stage in ordered}
    later: list[TeamEdge] = []
    for stage in ordered:
        for dependency in dict.fromkeys(stage.depends_on):
            if dependency == stage.key or dependency not in position:
                continue
            if position[dependency] < position[stage.key]:
                edges.append(TeamEdge(dependency, stage.key))
                predecessors[stage.key].append(dependency)
            else:
                # Drawn and marked, and left out of the rows so a loop cannot
                # stop a stage from ever being placed.
                later.append(TeamEdge(dependency, stage.key, legal=False))
        if first is not None and stage.key in adopted_set and first in position:
            edges.append(TeamEdge(first, stage.key, implicit=True))
            predecessors[stage.key].append(first)
    edges.extend(later)

    successors: dict[str, list[str]] = {stage.key: [] for stage in ordered}
    waiting = {key: len(before) for key, before in predecessors.items()}
    for key, before in predecessors.items():
        for predecessor in before:
            successors[predecessor].append(key)
    row_of: dict[str, int] = {}
    ready = [stage.key for stage in ordered if waiting[stage.key] == 0]
    for key in ready:
        row_of[key] = 0
    while ready:
        key = ready.pop()
        for successor in successors[key]:
            row_of[successor] = max(row_of.get(successor, 0), row_of[key] + 1)
            waiting[successor] -= 1
            if waiting[successor] == 0:
                ready.append(successor)

    column_of: dict[str, int] = {}
    filled: dict[int, int] = {}
    for stage in ordered:
        row = row_of[stage.key]
        column_of[stage.key] = filled.get(row, 0)
        filled[row] = column_of[stage.key] + 1

    nodes = tuple(
        TeamNode(
            key=stage.key,
            label=stage.label,
            kind=stage.kind,
            agents=tuple(stage.agents),
            when=stage.when,
            reads=stage.inject_upstream,
            # An unset mode follows the job's resolved analyst mode; the
            # drawing names it ``auto``.
            mode=stage.mode or "auto",
            row=row_of[stage.key],
            column=column_of[stage.key],
        )
        for stage in ordered
    )
    return TeamLayout(
        nodes=nodes,
        edges=tuple(edges),
        rows=(max(row_of.values()) + 1) if row_of else 0,
        columns=max(filled.values(), default=0),
    )
