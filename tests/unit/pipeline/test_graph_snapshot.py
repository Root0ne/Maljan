"""The compiled graph of the default profile is the graph on ``dev``.

Sub-project C moves the builder's topology source from the class registry to
the active profile. Node names, the edge set, the conditional edge's path map
and the analyst order are what "the same graph" means, and they are compared
here against a fixture captured before the move
(``scripts/capture_graph_golden.py``). Both values of
``llm.parallel_analysts`` are covered: they are two different graphs and only
one of them is the default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.builder import build_graph

GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "graph_default.json"


def compiled_shape(container: ServiceContainer) -> dict[str, Any]:
    """The node set, edge set and conditional path map of a built graph."""
    compiled = build_graph(container)
    drawn = compiled.get_graph()
    conditional: dict[str, dict[str, str]] = {}
    for source, branches in compiled.builder.branches.items():
        for spec in branches.values():
            conditional[source] = dict(spec.ends or {})
    nxt = {e.source: e.target for e in drawn.edges if not e.conditional}
    order: list[str] = []
    node = nxt.get("__start__", "")
    while node.endswith("_analyst"):
        order.append(node[: -len("_analyst")])
        node = nxt.get(node, "")
    return {
        "analysts": order,
        "nodes": sorted(drawn.nodes),
        "edges": sorted(f"{e.source}->{e.target}" for e in drawn.edges),
        "conditional": conditional,
    }


def _container(parallel: bool) -> ServiceContainer:
    cfg = Settings(_env_file=None)
    cfg.llm.parallel_analysts = parallel
    return ServiceContainer(cfg, mock=True)


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_the_sequential_graph_is_unchanged(golden):
    shape = compiled_shape(_container(parallel=False))
    expected = golden["sequential"]
    assert shape["nodes"] == expected["nodes"]
    assert shape["edges"] == expected["edges"]
    assert shape["conditional"] == expected["conditional"]
    assert shape["analysts"] == expected["analysts"]


def test_the_parallel_graph_is_unchanged(golden):
    shape = compiled_shape(_container(parallel=True))
    expected = golden["parallel"]
    assert shape["nodes"] == expected["nodes"]
    assert shape["edges"] == expected["edges"]
    assert shape["conditional"] == expected["conditional"]


def test_the_default_analyst_order_is_the_paper_triple(golden):
    """The order is a property of the system, not an accident of the fixture."""
    assert golden["sequential"]["analysts"] == ["static", "dynamic", "network"]


def test_the_negotiation_branch_still_has_exactly_two_destinations(golden):
    assert golden["sequential"]["conditional"] == {
        "negotiation": {"revision": "revision", "judge": "judge"}
    }


def test_a_custom_profile_produces_its_own_nodes_and_chain():
    """Four analysts, one of them generic, in the order the profile lists them."""
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {
                "static_r2": {"role": "static", "static_provider": "r2"},
                "strings": {"role": "generic", "prompt": "read strings"},
            },
            "profiles": {"wide": {"analysts": ["static", "static_r2", "network", "strings"]}},
            "profile": "wide",
        },
    )
    cfg.llm.parallel_analysts = False
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert shape["analysts"] == ["static", "static_r2", "network", "strings"]
    assert shape["nodes"] == sorted(
        [
            "__start__",
            "__end__",
            "static_analyst",
            "static_r2_analyst",
            "network_analyst",
            "strings_analyst",
            "negotiation",
            "revision",
            "judge",
            "report",
        ]
    )
    assert "static_r2_analyst->network_analyst" in shape["edges"]
    assert "strings_analyst->negotiation" in shape["edges"]
    assert shape["conditional"] == {"negotiation": {"revision": "revision", "judge": "judge"}}


def test_a_custom_profile_fans_out_from_start_in_parallel_mode():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"lean": {"analysts": ["network", "static"]}}, "profile": "lean"},
    )
    cfg.llm.parallel_analysts = True
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert "__start__->network_analyst" in shape["edges"]
    assert "__start__->static_analyst" in shape["edges"]
    assert "network_analyst->negotiation" in shape["edges"]
    assert "dynamic_analyst" not in " ".join(shape["nodes"])


def test_a_profile_of_one_analyst_still_reaches_negotiation():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"solo": {"analysts": ["network"]}}, "profile": "solo"},
    )
    cfg.llm.parallel_analysts = False
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert shape["analysts"] == ["network"]
    assert "__start__->network_analyst" in shape["edges"]
    assert "network_analyst->negotiation" in shape["edges"]
