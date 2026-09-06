"""Pin the compiled graph of the default profile, before the profile exists.

Sub-project C replaces ``AgentRegistry.list_agents()`` as the builder's
topology source. The replacement is only free if the graph it produces is the
graph it produced before, so the node names, the edge set, the conditional
edge's path map and the analyst order are captured here from a live
``build_graph`` — for both values of ``llm.parallel_analysts``, because the
two topologies are different graphs and only one of them is the default.

Run: ``uv run python scripts/capture_graph_golden.py``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "graph_default.json"


def graph_shape(parallel: bool) -> dict[str, Any]:
    """The node set, edge set, conditional path map and analyst order."""
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer
    from maljan.pipeline.builder import build_graph

    cfg = Settings(_env_file=None)
    cfg.llm.parallel_analysts = parallel
    container = ServiceContainer(cfg, mock=True)
    compiled = build_graph(container)
    drawn = compiled.get_graph()
    conditional: dict[str, dict[str, str]] = {}
    for source, branches in compiled.builder.branches.items():
        for spec in branches.values():
            conditional[source] = dict(spec.ends or {})
    analysts = [node[: -len("_analyst")] for node in drawn.nodes if node.endswith("_analyst")]
    return {
        # The analyst order is the sequential chain order, which is the order
        # the builder received; recovered from the edges rather than from the
        # node dict so the parallel capture records the same list.
        "analysts": _analyst_order(drawn, analysts, parallel),
        "nodes": sorted(drawn.nodes),
        "edges": sorted(f"{e.source}->{e.target}" for e in drawn.edges),
        "conditional": conditional,
    }


def _analyst_order(drawn: Any, analysts: list[str], parallel: bool) -> list[str]:
    """Analyst order: the chain in sequential mode, the node order in parallel."""
    if parallel:
        # Every analyst hangs off START, so the graph carries no order; the
        # builder's own iteration order is what the node dict preserves.
        return [n[: -len("_analyst")] for n in drawn.nodes if n.endswith("_analyst")]
    nxt = {e.source: e.target for e in drawn.edges if not e.conditional}
    node = nxt.get("__start__", "")
    order: list[str] = []
    while node.endswith("_analyst"):
        order.append(node[: -len("_analyst")])
        node = nxt.get(node, "")
    assert len(order) == len(analysts), f"chain {order} misses one of {analysts}"
    return order


def main() -> None:
    payload = {
        "sequential": graph_shape(parallel=False),
        "parallel": graph_shape(parallel=True),
    }
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
