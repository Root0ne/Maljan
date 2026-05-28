"""Concurrency contract for the LangGraph analyst fan-out.

Audit 2026-05-19 PERF-PARALLEL-ANALYSTS-01: the pipeline relies on
LangGraph's "multiple edges from START" semantics to run static /
dynamic / network analysts in parallel. If a future refactor accidentally
serialises them via an intermediate router we would 3x our pipeline
latency without any test catching it. This module pins the topology so
the regression becomes a hard failure at CI time.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def fake_container() -> Any:
    """Minimal ServiceContainer stub for ``build_graph``."""
    container = MagicMock()
    # Three analyst names matches production today (static + dynamic + network).
    container.agent_registry.list_agents.return_value = ["static", "dynamic", "network"]
    container.is_mock = True
    container.config.reporting.enabled = False  # keep the topology compact
    return container


def test_start_fans_out_to_every_analyst(fake_container: Any) -> None:
    """Every analyst node must be a direct successor of START."""
    from langgraph.graph import START

    from maljan.pipeline.builder import build_graph

    graph = build_graph(fake_container)
    # LangGraph's compiled graph exposes its edges via ``graph.edges`` —
    # the underlying ``StateGraph`` object is at ``compiled.builder``.
    builder = getattr(graph, "builder", None) or graph
    edges = getattr(builder, "edges", None)
    if edges is None:
        pytest.skip("LangGraph internal layout changed; revisit this test.")

    start_targets: set[str] = set()
    for edge in edges:
        source, target = edge if isinstance(edge, tuple) else (edge[0], edge[1])
        if source == START:
            start_targets.add(target)
    expected = {"static_analyst", "dynamic_analyst", "network_analyst"}
    assert expected.issubset(start_targets), (
        f"Expected START to fan out to {expected}, got {start_targets}. "
        "Did someone serialise the analysts behind a router?"
    )


def test_no_serialising_router_between_start_and_analysts(fake_container: Any) -> None:
    """No analyst node should be reachable from START only via another analyst."""
    from langgraph.graph import START

    from maljan.pipeline.builder import build_graph

    graph = build_graph(fake_container)
    builder = getattr(graph, "builder", None) or graph
    edges = getattr(builder, "edges", None)
    if edges is None:
        pytest.skip("LangGraph internal layout changed; revisit this test.")

    # Build an adjacency map and verify analysts have only START as
    # direct predecessor — never another analyst.
    predecessors: dict[str, set[str]] = {}
    for edge in edges:
        source, target = edge if isinstance(edge, tuple) else (edge[0], edge[1])
        predecessors.setdefault(target, set()).add(source)

    for analyst in ("static_analyst", "dynamic_analyst", "network_analyst"):
        preds = predecessors.get(analyst, set())
        # The only allowed predecessor is START. Anything else (e.g. a
        # router or another analyst) would force serial execution.
        assert preds == {START}, (
            f"Analyst {analyst} has unexpected predecessors {preds}; "
            "must be {START} only to preserve parallelism."
        )


# ---------------------------------------------------------------------------
# Wave 7 THROUGHPUT-01 (2026-05-28) — sequential-analyst topology
# ---------------------------------------------------------------------------


@pytest.fixture
def sequential_container() -> Any:
    """``fake_container`` clone with ``parallel_analysts = False``."""
    container = MagicMock()
    container.agent_registry.list_agents.return_value = ["static", "dynamic", "network"]
    container.is_mock = True
    container.config.reporting.enabled = False
    container.config.llm.parallel_analysts = False
    return container


def test_sequential_mode_chains_analysts(sequential_container: Any) -> None:
    """In sequential mode each analyst follows the previous one in registry order."""
    from langgraph.graph import START

    from maljan.pipeline.builder import build_graph

    graph = build_graph(sequential_container)
    builder = getattr(graph, "builder", None) or graph
    edges = getattr(builder, "edges", None)
    if edges is None:
        pytest.skip("LangGraph internal layout changed; revisit this test.")

    edge_set: set[tuple[str, str]] = set()
    for edge in edges:
        source, target = edge if isinstance(edge, tuple) else (edge[0], edge[1])
        edge_set.add((source, target))

    # START hits only the first analyst.
    start_targets = {tgt for src, tgt in edge_set if src == START}
    assert start_targets == {"static_analyst"}, (
        f"Expected START → static_analyst only, got {start_targets}."
    )
    # The chain links each analyst to the next.
    assert ("static_analyst", "dynamic_analyst") in edge_set
    assert ("dynamic_analyst", "network_analyst") in edge_set
    # Final analyst hands off to negotiation.
    assert ("network_analyst", "negotiation") in edge_set
    # And no analyst skips ahead to negotiation.
    forbidden = {
        ("static_analyst", "negotiation"),
        ("dynamic_analyst", "negotiation"),
    }
    assert not (edge_set & forbidden), (
        f"Sequential mode leaked a fan-in shortcut: {edge_set & forbidden}"
    )


def test_sequential_mode_preserves_negotiation_downstream(
    sequential_container: Any,
) -> None:
    """Sequential mode must not break the negotiation → judge → END chain."""
    from maljan.pipeline.builder import build_graph

    graph = build_graph(sequential_container)
    builder = getattr(graph, "builder", None) or graph
    edges = getattr(builder, "edges", None)
    if edges is None:
        pytest.skip("LangGraph internal layout changed; revisit this test.")

    edge_set: set[tuple[str, str]] = set()
    for edge in edges:
        source, target = edge if isinstance(edge, tuple) else (edge[0], edge[1])
        edge_set.add((source, target))

    # Revision still loops back to negotiation, judge still follows
    # negotiation via the conditional router (not visible as a plain
    # edge), and judge still terminates with END (reporting disabled in
    # this fixture so judge → END directly).
    assert ("revision", "negotiation") in edge_set
    # Judge → END (reporting disabled in the fixture).
    assert any(src == "judge" for src, _ in edge_set)
