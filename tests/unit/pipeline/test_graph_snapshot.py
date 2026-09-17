"""The compiled graph of the default profile is the graph on ``dev``.

Sub-project C moves the builder's topology source from the class registry to
the active profile. Node names, the edge set, the conditional edge's path map
and the analyst order are what "the same graph" means, and they are compared
here against a fixture captured before the move
(``scripts/goldens/capture_graph_golden.py``). Both values of
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
    while node and not node.endswith("_analyst"):
        node = nxt.get(node, "")
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
    # Set at construction, not after it: a profile stored as a plain analyst
    # list becomes stages while the settings are validated, and the analyst
    # mode is one of the two global keys that conversion reads. Assigning the
    # flag afterwards would leave a stage list that already said "sequential".
    cfg = Settings(_env_file=None, llm={"parallel_analysts": parallel})
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
            "triage_pack",
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
    assert "__start__->triage_pack" in shape["edges"]
    assert "triage_pack->static_analyst" in shape["edges"]
    assert "static_r2_analyst->network_analyst" in shape["edges"]
    assert "strings_analyst->negotiation" in shape["edges"]
    assert shape["conditional"] == {"negotiation": {"revision": "revision", "judge": "judge"}}


def test_a_custom_profile_fans_out_from_start_in_parallel_mode():
    cfg = Settings(
        _env_file=None,
        llm={"parallel_analysts": True},
        agents={"profiles": {"lean": {"analysts": ["network", "static"]}}, "profile": "lean"},
    )
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert "__start__->triage_pack" in shape["edges"]
    assert "triage_pack->network_analyst" in shape["edges"]
    assert "triage_pack->static_analyst" in shape["edges"]
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
    assert "triage_pack->network_analyst" in shape["edges"]
    assert "network_analyst->negotiation" in shape["edges"]


def test_a_profile_written_as_stages_without_the_pack_starts_at_its_first_stage():
    """A team may omit the pack; then nothing stands between START and it."""
    cfg = Settings(
        _env_file=None,
        agents={
            "profiles": {
                "bare": {
                    "stages": [
                        {"key": "one", "kind": "analysis", "agents": ["static"]},
                        {
                            "key": "verdict",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["one"],
                        },
                    ]
                }
            },
            "profile": "bare",
        },
    )
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert "triage_pack" not in shape["nodes"]
    assert "__start__->static_analyst" in shape["edges"]


def test_a_pack_placed_after_a_dependency_is_an_ordinary_stage():
    """Only a triage stage with no dependency stands in for START."""
    cfg = Settings(
        _env_file=None,
        agents={
            "profiles": {
                "late": {
                    "stages": [
                        {"key": "one", "kind": "analysis", "agents": ["static"]},
                        {"key": "facts", "kind": "triage", "depends_on": ["one"]},
                        {
                            "key": "two",
                            "kind": "analysis",
                            "agents": ["network"],
                            "depends_on": ["facts"],
                        },
                        {
                            "key": "verdict",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["two"],
                        },
                    ]
                }
            },
            "profile": "late",
        },
    )
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert "__start__->static_analyst" in shape["edges"]
    assert "static_analyst->facts" in shape["edges"]
    assert "facts->network_analyst" in shape["edges"]


TEAM_LEAD_GOLDEN = GOLDEN.with_name("graph_team_lead.json")


def test_the_team_lead_graph_is_the_one_pinned():
    """One analyst node; the specialists are its tools, not stages."""
    expected = json.loads(TEAM_LEAD_GOLDEN.read_text(encoding="utf-8"))
    for parallel, key in ((False, "sequential"), (True, "parallel")):
        cfg = Settings(_env_file=None, llm={"parallel_analysts": parallel})
        cfg.agents.profile = "team_lead"
        shape = compiled_shape(ServiceContainer(cfg, mock=True))
        assert shape["nodes"] == expected[key]["nodes"]
        assert shape["edges"] == expected[key]["edges"]
        assert shape["conditional"] == expected[key]["conditional"]
        assert shape["analysts"] == ["lead"]
    assert "static_analyst" not in expected["sequential"]["nodes"]
