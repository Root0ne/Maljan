"""A report the report node built survives a later step of the graph failing.

The graph has no checkpointer, and an ``ainvoke`` that raises returns nothing:
a run that failed after its report was built used to lose the report with
everything else. ``MaljanApp`` runs the graph as a stream now, keeps what the
report node returned the moment it returns, and says where the graph failed.
On a run that completes, the final state is the one ``ainvoke`` returns.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langgraph.errors import InvalidUpdateError
from langgraph.graph import END, START, StateGraph

from maljan.app import MaljanApp
from maljan.pipeline.builder import _node
from maljan.pipeline.state import AnalysisState

REPORT = {"verdict": "Malware", "degradation_reasons": []}


async def _judge(state: Any) -> dict[str, Any]:
    return {
        "final_decision": "Malware",
        "evidence_ledger": [{"id": "E1"}],
        "run_summary": {"written_by": "judge"},
    }


async def _report(state: Any) -> dict[str, Any]:
    return {
        "malware_report": dict(REPORT),
        "malware_report_markdown": "# report",
        "evidence_ledger": [{"id": "E2"}],
        "run_summary": {**(state.get("run_summary") or {}), "written_by": "report"},
    }


async def _fails(state: Any) -> dict[str, Any]:
    raise RuntimeError("after the report")


async def _quiet(state: Any) -> dict[str, Any]:
    return {}


def _app(graph: Any) -> MaljanApp:
    app = MaljanApp.__new__(MaljanApp)
    app.graph = graph
    app.built_report = None
    app.failed_step = None
    return app


def _chain(after: Any) -> Any:
    """judge -> report -> after -> END, each node wrapped as the builder wraps it."""
    builder = StateGraph(AnalysisState)
    for name, fn in (("judge", _judge), ("report", _report), ("after", after)):
        builder.add_node(name, _node(name, fn))
    builder.add_edge(START, "judge")
    builder.add_edge("judge", "report")
    builder.add_edge("report", "after")
    builder.add_edge("after", END)
    return builder.compile()


INITIAL: dict[str, Any] = {"file_hash": "a" * 64, "evidence_ledger": [], "run_summary": None}


def test_a_node_after_the_report_raises_and_the_report_is_kept() -> None:
    app = _app(_chain(_fails))
    with pytest.raises(RuntimeError, match="after the report"):
        asyncio.run(app._stream_the_graph(dict(INITIAL)))  # type: ignore[arg-type]
    kept = app.built_report
    assert kept is not None
    assert kept["malware_report"] == REPORT
    assert kept["malware_report_markdown"] == "# report"
    assert kept["final_decision"] == "Malware"
    # Merged through the graph's reducer, not overwritten by the report's own
    # entries: the ledger is append-only.
    assert kept["evidence_ledger"] == [{"id": "E1"}, {"id": "E2"}]
    assert kept["run_summary"] == {"written_by": "report"}
    assert app.failed_step == "node after"


def test_the_writes_of_the_reports_own_step_are_refused_and_the_report_is_kept() -> None:
    """A second judge in the report's step: LangGraph refuses both writes at once."""
    builder = StateGraph(AnalysisState)
    builder.add_node("judge", _node("judge", _judge))
    builder.add_node("report", _node("report", _report))
    builder.add_node("second_judge", _node("second_judge", _judge))
    builder.add_edge(START, "judge")
    builder.add_edge("judge", "report")
    builder.add_edge("judge", "second_judge")
    builder.add_edge("report", END)
    builder.add_edge("second_judge", END)
    app = _app(builder.compile())
    with pytest.raises(InvalidUpdateError):
        asyncio.run(app._stream_the_graph(dict(INITIAL)))  # type: ignore[arg-type]
    assert app.built_report is not None
    assert app.built_report["malware_report"] == REPORT
    assert app.failed_step is not None
    assert app.failed_step.startswith("the graph step of nodes ")
    assert set(app.failed_step.removeprefix("the graph step of nodes ").split(", ")) == {
        "report",
        "second_judge",
    }


def test_only_the_reports_own_update_joins_the_state_it_was_built_from() -> None:
    """A node finishing beside the report did not feed it, and is not merged.

    Staged teams cannot put a node beside the report: the report stage waits
    for every stage it depends on. A hand-built graph can, and what the kept
    report carries is still the state it read plus what it wrote.
    """

    async def _beside(state: Any) -> dict[str, Any]:
        return {"judge_report": "written beside the report", "evidence_ledger": [{"id": "E9"}]}

    builder = StateGraph(AnalysisState)
    builder.add_node("judge", _node("judge", _judge))
    builder.add_node("report", _node("report", _report))
    builder.add_node("beside", _node("beside", _beside))
    builder.add_node("after", _node("after", _fails))
    builder.add_edge(START, "judge")
    builder.add_edge("judge", "report")
    builder.add_edge("judge", "beside")
    builder.add_edge(["report", "beside"], "after")
    builder.add_edge("after", END)
    app = _app(builder.compile())
    with pytest.raises(RuntimeError):
        asyncio.run(app._stream_the_graph(dict(INITIAL)))  # type: ignore[arg-type]
    kept = app.built_report
    assert kept is not None
    assert "judge_report" not in kept
    assert kept["evidence_ledger"] == [{"id": "E1"}, {"id": "E2"}]
    assert app.failed_step == "node after"


def test_a_graph_that_fails_before_the_report_keeps_nothing() -> None:
    builder = StateGraph(AnalysisState)
    builder.add_node("judge", _node("judge", _fails))
    builder.add_edge(START, "judge")
    builder.add_edge("judge", END)
    app = _app(builder.compile())
    with pytest.raises(RuntimeError):
        asyncio.run(app._stream_the_graph(dict(INITIAL)))  # type: ignore[arg-type]
    assert app.built_report is None
    assert app.failed_step == "node judge"


def test_a_run_that_completes_ends_in_the_state_ainvoke_returns() -> None:
    graph = _chain(_quiet)
    app = _app(graph)
    streamed = asyncio.run(app._stream_the_graph(dict(INITIAL)))  # type: ignore[arg-type]
    invoked = asyncio.run(graph.ainvoke(dict(INITIAL)))
    assert streamed == invoked
    assert app.failed_step is None
    assert app.built_report is not None
