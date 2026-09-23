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
    """
    first, adopted = adopted_roots(stages)
    adopted_set = set(adopted)
    row_of: dict[str, int] = {}
    edges: list[TeamEdge] = []
    ordered: list[StageDefinition] = []

    for stage in stages:
        if stage.key in row_of:
            continue
        rows = [row_of[d] for d in stage.depends_on if d in row_of and d != stage.key]
        for dependency in stage.depends_on:
            if dependency == stage.key:
                continue
            if dependency in row_of:
                edges.append(TeamEdge(dependency, stage.key))
        if first is not None and stage.key in adopted_set and first in row_of:
            rows.append(row_of[first])
            edges.append(TeamEdge(first, stage.key, implicit=True))
        row_of[stage.key] = (max(rows) + 1) if rows else 0
        ordered.append(stage)

    # Dependencies on a stage written further down: drawn, marked, and left
    # out of the rows above so a loop cannot make the layout recurse.
    for stage in ordered:
        seen_before = {s.key for s in ordered[: ordered.index(stage)]}
        for dependency in stage.depends_on:
            if dependency in row_of and dependency not in seen_before and dependency != stage.key:
                edges.append(TeamEdge(dependency, stage.key, legal=False))

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
            mode=stage.mode,
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
