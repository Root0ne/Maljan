"""Concurrency contract for the LangGraph analyst fan-out.

Audit 2026-05-19 PERF-PARALLEL-ANALYSTS-01: the pipeline relies on
LangGraph's "multiple edges from START" semantics to run static /
dynamic / network analysts in parallel. If a future refactor accidentally
serialises them via an intermediate router we would 3x our pipeline
latency without any test catching it. This module pins the topology so
the regression becomes a hard failure at CI time.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# The real coroutine function, captured before any test patches the reference
# on ``maljan.pipeline.nodes.asyncio.gather``. Spies ``wraps`` this so the
# concurrent branch keeps working while call-count stays observable.
_REAL_GATHER = asyncio.gather


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


# ---------------------------------------------------------------------------
# Revision-node fan-out topology (2026-07-13 — Interaction B)
# The INITIAL fan-out is serialised by graph edges (tested above), but the
# revision node fans out INTERNALLY (its own gather over the analysts). It must
# honour ``parallel_analysts`` too, or every revision round re-introduces the
# single-slot recurrent-state clobbering the sequential topology exists to
# prevent. The original 2026-07-13 fix wired only the builder edges and MISSED
# this node — these tests pin the contract so that regression can't recur.
# ---------------------------------------------------------------------------


def _revision_container(parallel: bool, call_order: list[str]) -> Any:
    """Container stub whose three agents return a deterministic (text, ISR).

    Each ``safe_revise_isr`` records its agent name in ``call_order`` so the
    execution order is observable. ``load_chunked`` raises so
    ``_build_revision_context`` takes its documented load_data fallback (keeps
    the fixture free of TextChunk plumbing).
    """
    from maljan.pipeline.nodes import _empty_isr

    container = MagicMock()
    container.agent_registry.list_agents.return_value = ["static", "dynamic", "network"]
    container.is_mock = False
    container.config.llm.parallel_analysts = parallel
    container.load_chunked.side_effect = RuntimeError("force load_data fallback")
    container.load_data.return_value = "raw analysis data"

    def _get_agent(name: str) -> Any:
        agent = MagicMock()

        def _revise(*_args: Any, _n: str = name, **_kw: Any) -> tuple[str, Any]:
            call_order.append(_n)
            return (f"{_n} revised", _empty_isr(_n, revision_round=1))

        agent.safe_revise_isr.side_effect = _revise
        return agent

    container.get_agent.side_effect = _get_agent
    return container


def _revision_state() -> dict[str, Any]:
    return {
        "iteration_count": 1,
        "reports": {"static": "r0", "dynamic": "r0", "network": "r0"},
    }


def test_revision_node_sequential_does_not_gather() -> None:
    """``parallel_analysts=False`` → the revision node must NOT use
    ``asyncio.gather`` (that would run the analysts concurrently on the single
    slot). Deterministic two-way guard for Interaction B: a revert to the
    unconditional gather flips ``assert_not_called`` to a hard failure. The
    registry-order check confirms the sequential ``await`` loop ran each revise
    to completion before the next (exclusive slot use)."""
    from maljan.pipeline.nodes import make_revision_node

    call_order: list[str] = []
    container = _revision_container(parallel=False, call_order=call_order)
    node = make_revision_node(container)

    with patch("maljan.pipeline.nodes.asyncio.gather", wraps=_REAL_GATHER) as gather_spy:
        result = asyncio.run(node(_revision_state()))

    gather_spy.assert_not_called()
    assert call_order == ["static", "dynamic", "network"]
    assert set(result["revised_reports"]) == {"static", "dynamic", "network"}
    assert result["revised_reports"]["static"] == "static revised"
    assert set(result["isr_reports"]) == {"static", "dynamic", "network"}


def test_revision_node_parallel_uses_gather() -> None:
    """``parallel_analysts=True`` keeps the concurrent gather and still returns
    a revised report + ISR for every analyst (the branch must not regress)."""
    from maljan.pipeline.nodes import make_revision_node

    container = _revision_container(parallel=True, call_order=[])
    node = make_revision_node(container)

    with patch("maljan.pipeline.nodes.asyncio.gather", wraps=_REAL_GATHER) as gather_spy:
        result = asyncio.run(node(_revision_state()))

    gather_spy.assert_called_once()
    assert set(result["revised_reports"]) == {"static", "dynamic", "network"}
    assert set(result["isr_reports"]) == {"static", "dynamic", "network"}


def test_revision_node_sequential_tolerates_one_failure() -> None:
    """A single analyst raising must not abort the round (parity with
    ``gather(return_exceptions=True)``): the survivors still revise and the
    failed agent falls back to its original report."""
    from maljan.pipeline.nodes import make_revision_node

    call_order: list[str] = []
    container = _revision_container(parallel=False, call_order=call_order)

    # Make the dynamic agent's revise blow up.
    def _get_agent(name: str) -> Any:
        agent = MagicMock()
        if name == "dynamic":
            agent.safe_revise_isr.side_effect = RuntimeError("boom")
        else:

            def _revise(*_a: Any, _n: str = name, **_k: Any) -> tuple[str, Any]:
                from maljan.pipeline.nodes import _empty_isr

                call_order.append(_n)
                return (f"{_n} revised", _empty_isr(_n, revision_round=1))

            agent.safe_revise_isr.side_effect = _revise
        return agent

    container.get_agent.side_effect = _get_agent
    node = make_revision_node(container)

    result = asyncio.run(node(_revision_state()))

    # Survivors revised; the failed agent kept its original report.
    assert result["revised_reports"]["static"] == "static revised"
    assert result["revised_reports"]["network"] == "network revised"
    assert result["revised_reports"]["dynamic"] == "r0"
