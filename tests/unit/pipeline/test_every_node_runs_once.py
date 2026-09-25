"""A node runs once per pass, after every stage it depends on has finished.

The shape tests in ``test_staged_graph`` say which edges exist; these run the
compiled graph and count. LangGraph treats separate single-source edges into
one node as separate triggers: the node runs in the superstep after *any* of
them finishes. A stage that depends on two stages of unequal depth therefore
ran once per upstream stage, everything after it ran again, and two judges
that finished in different supersteps let the report share a superstep with
the second judge — both write ``run_summary``, which has no reducer, and the
run ended in ``InvalidUpdateError`` after the report was built.

Every node here is a stub that counts its own runs: the real ``build_graph``,
the real profiles, and nothing a model or a tool server would answer.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.pipeline import builder as graph_builder
from maljan.pipeline.topology import JUDGE_NODE, REPORT_NODE, REVISION_NODE

ALL_TOOLS = (
    Path(__file__).resolve().parents[3] / "docs" / "examples" / "profiles" / "all-tools.json"
)


class _Container:
    """What ``build_graph`` reads of a container: the settings and the active profile."""

    def __init__(self, settings: Settings) -> None:
        self.config = settings

    def active_profile(self) -> Any:
        from maljan.agents.composition import active_profile

        return active_profile(self.config)


class _Router:
    """Answers ``revision`` for the first ``loops`` rounds of each debate, then ``judge``."""

    loops = 0

    def __init__(self, config: Any, *, stage: Any) -> None:
        self._asked = 0

    def should_continue(self, state: Any) -> str:
        self._asked += 1
        return "revision" if self._asked <= self.loops else "judge"


def _run(settings: Settings, monkeypatch: pytest.MonkeyPatch, *, loops: int = 0) -> Counter:
    runs: Counter = Counter()

    def stub(name: str, _fn: Any) -> Any:
        async def node(state: Any) -> dict[str, Any]:
            runs[name] += 1
            if name in (JUDGE_NODE, REPORT_NODE):
                # The two writers of the one key the report and the judge
                # share. A second judge in the report's superstep is the
                # failure this file exists for.
                return {"run_summary": {"written_by": name}}
            return {}

        return node

    for factory in (
        "make_join_node",
        "make_judge_node",
        "make_negotiation_node",
        "make_report_node",
        "make_revision_node",
        "make_stage_agent_node",
        "make_triage_node",
    ):
        monkeypatch.setattr(graph_builder, factory, lambda *a, **k: None)
    monkeypatch.setattr(graph_builder, "_node", stub)
    router = type("Router", (_Router,), {"loops": loops})
    monkeypatch.setattr(graph_builder, "ConsensusRouter", router)

    compiled = graph_builder.build_graph(_Container(settings))  # type: ignore[arg-type]
    asyncio.run(compiled.ainvoke({"job_id": "job-under-test"}))
    return runs


def _team(stages: list[dict], **definitions: dict) -> Settings:
    return Settings(
        _env_file=None,
        agents={
            "definitions": definitions,
            "profiles": {"team": {"label": "Team", "stages": stages}},
            "profile": "team",
        },
    )


def _all_tools() -> Settings:
    values = json.loads(ALL_TOOLS.read_text(encoding="utf-8"))["values"]
    return Settings(
        _env_file=None,
        # The one server the team names that is not seeded; never started here.
        mcp={
            "servers": {
                "qu1cksc0pe": {"enabled": True, "transport": "stdio", "command": "qu1cksc0pe-mcp"}
            }
        },
        agents={
            "definitions": values["core.agents.definitions"],
            "profiles": values["core.agents.profiles"],
            "profile": "all_tools",
        },
    )


def _assert_once_each(runs: Counter, settings: Settings) -> None:
    compiled_nodes = set(
        graph_builder.build_graph(_Container(settings)).get_graph().nodes  # type: ignore[arg-type]
    ) - {"__start__", "__end__"}
    # With the router answering ``judge`` at once, a revision node is the one
    # node of the graph that has no reason to run.
    revisions = {name for name in compiled_nodes if name.endswith(REVISION_NODE)}
    assert set(runs) == compiled_nodes - revisions
    assert {name: count for name, count in runs.items() if count != 1} == {}


GENERIC = {"role": "generic", "prompt": "look"}
REPORT = {"key": "report", "kind": "report", "agents": ["reporter"], "depends_on": ["verdict"]}


class TestANodeRunsOnceAfterEveryStageItDependsOn:
    def test_a_diamond_of_unequal_depth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """a → b, c ← {a, b}: c waits for b, which finishes a superstep after a."""
        settings = _team(
            [
                {"key": "a", "kind": "analysis", "agents": ["static"]},
                {"key": "b", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["a"]},
                {
                    "key": "c",
                    "kind": "analysis",
                    "agents": ["network"],
                    "depends_on": ["a", "b"],
                },
                {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["c"]},
                REPORT,
            ]
        )
        runs = _run(settings, monkeypatch)
        _assert_once_each(runs, settings)

    def test_a_parallel_stage_of_unequal_branches_joins_before_its_dependent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One branch is two stages deep, the other one; the judge waits for both."""
        settings = _team(
            [
                {"key": "a", "kind": "analysis", "agents": ["static"]},
                {"key": "b", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["a"]},
                {"key": "c", "kind": "analysis", "agents": ["strings"]},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["b", "c"],
                },
                REPORT,
            ],
            strings=GENERIC,
        )
        runs = _run(settings, monkeypatch)
        _assert_once_each(runs, settings)

    def test_a_debate_and_a_deeper_stage_feeding_one_stage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A debate hands over through its router; the next stage waits for the other branch too."""
        settings = _team(
            [
                {"key": "a", "kind": "analysis", "agents": ["static"]},
                {"key": "argue", "kind": "debate", "depends_on": ["a"]},
                {"key": "b", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["a"]},
                {"key": "c", "kind": "analysis", "agents": ["network"], "depends_on": ["b"]},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["argue", "c"],
                },
                REPORT,
            ]
        )
        for loops in (0, 1, 3):
            runs = _run(settings, monkeypatch, loops=loops)
            assert runs[JUDGE_NODE] == 1, loops
            assert runs[REPORT_NODE] == 1, loops
            assert runs[REVISION_NODE] == loops
            assert runs["negotiation"] == loops + 1
            assert runs["network_analyst"] == 1

    def test_the_all_tools_team(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _all_tools()
        runs = _run(settings, monkeypatch)
        _assert_once_each(runs, settings)
        assert runs[REPORT_NODE] == 1

    def test_the_all_tools_team_with_the_revision_loop_taken_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runs = _run(_all_tools(), monkeypatch, loops=1)
        assert runs[REVISION_NODE] == 1
        assert runs["negotiation"] == 2
        others = {
            name: count
            for name, count in runs.items()
            if name not in ("negotiation", REVISION_NODE) and count != 1
        }
        assert others == {}
        assert runs[JUDGE_NODE] == 1
        assert runs[REPORT_NODE] == 1

    @pytest.mark.parametrize(
        "profile", ["default", "measurement", "mobile", "deep_static", "team_lead"]
    )
    @pytest.mark.parametrize("parallel", [False, True])
    def test_every_seeded_team(
        self, profile: str, parallel: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None, llm={"parallel_analysts": parallel})
        settings.agents.profile = profile
        assert profile in settings.agents.profiles
        runs = _run(settings, monkeypatch)
        _assert_once_each(runs, settings)

    @pytest.mark.parametrize("profile", ["default", "mobile", "deep_static"])
    def test_every_seeded_team_with_the_revision_loop_taken_once(
        self, profile: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(_env_file=None)
        settings.agents.profile = profile
        runs = _run(settings, monkeypatch, loops=1)
        assert runs[REVISION_NODE] == 1
        assert runs["negotiation"] == 2
        assert runs[JUDGE_NODE] == 1
        assert runs[REPORT_NODE] == 1
