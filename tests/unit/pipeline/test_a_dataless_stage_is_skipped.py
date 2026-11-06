"""A stage none of whose analysts holds any of the data they read is skipped, and says why.

Observed on a team with a stage of its own for the dynamic analyst: on a job no
sandbox ran for, the stage was announced as started, the analyst was built and
its tool servers attached, and the stage was recorded as having run, with the
analyst's own no-data line the only sign that nothing was read. The decision
is now taken before any analyst of the stage is built, from what each one
declares it reads (``pipeline.data_needs``): no model is called, the stage is
recorded as not run with the reason, ``stage_skipped`` carries the reason to
the console, and each analyst leaves the skip line and empty ISR the no-data
guard always left, so the judge and the report read it as they read a skipped
analyst.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from malspark.core.config import AgentDefinition, StageDefinition, ToolRef
from malspark.pipeline.data_needs import SANDBOX_REPORT, STORED
from malspark.pipeline.nodes import (
    DATALESS_STAGE_KEY,
    NO_AGENT_DATA_REASON,
    SYNTHETIC_SANDBOX_REASON,
    _agents_that_ran,
    dataless_stage_reason,
    dataless_stages,
    make_judge_node,
    make_stage_agent_node,
)
from malspark.pipeline.state import _merge_stage_results

_DEFINITIONS = {
    "static": AgentDefinition(role="static", tools=[ToolRef(kind="mcp", server="knowledge")]),
    "dynamic": AgentDefinition(
        role="dynamic",
        tools=[ToolRef(kind="sandbox"), ToolRef(kind="mcp", server="knowledge")],
    ),
    "dynamic_two": AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox")]),
    "network": AgentDefinition(
        role="network",
        tools=[
            ToolRef(kind="mcp", server="network"),
            ToolRef(kind="mcp", server="knowledge"),
            ToolRef(kind="capability", capability="reputation"),
        ],
    ),
}
_SERVER_ROLES = {
    "knowledge": ("reference",),
    "network": ("capture",),
    "threatintel": ("reputation",),
}
# The servers a capability resolves to, as ``composition.capability_servers`` reads them.
_CAPABILITIES = {"reputation": ("threatintel",)}

_STATIC = StageDefinition(key="static", kind="analysis", agents=["static"])


def _stage(agents: list[str], *, inject: str = "findings", key: str = "dynamic") -> StageDefinition:
    return StageDefinition(
        key=key,
        kind="analysis",
        agents=agents,
        depends_on=["static"],
        inject_upstream=inject,  # type: ignore[arg-type]
    )


@pytest.fixture(autouse=True)
def _declared_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    """The servers' declared roles, as the live declarations read them for a double's settings."""
    import malspark.core.declared_reading as declared_reading

    real = declared_reading.declarations

    def source(ref: str) -> Any:
        roles = _SERVER_ROLES.get(ref.partition(":")[2])
        return None if roles is None else SimpleNamespace(roles=roles)

    def declarations(settings: Any = None) -> Any:
        if isinstance(settings, MagicMock):
            return SimpleNamespace(source=source)
        return real(settings)

    monkeypatch.setattr(declared_reading, "declarations", declarations)

    import malspark.agents.composition as composition

    bound = composition.servers_bound_to

    def servers_bound_to(settings: Any, key: str) -> set[str]:
        if not isinstance(settings, MagicMock):
            return bound(settings, key)
        out: set[str] = set()
        for ref in settings.agents.definitions[key].tools:
            if ref.kind == "mcp":
                out.add(str(ref.server))
            elif ref.kind == "capability":
                out.update(_CAPABILITIES.get(str(ref.capability), ()))
        return out

    monkeypatch.setattr(composition, "servers_bound_to", servers_bound_to)


class _Built(Exception):
    """Raised by the double the moment an analyst is built."""


def _container(stage: StageDefinition, *, mock: bool = False) -> tuple[Any, list[Any]]:
    events: list[tuple[str, dict[str, Any]]] = []
    container = MagicMock()
    container.is_mock = mock
    container.event_sink = lambda kind, data: events.append((kind, data))
    container.config.agents.definitions = dict(_DEFINITIONS)
    container.agent_role.side_effect = lambda name: str(_DEFINITIONS[name].role)
    container.holds_stored_data.return_value = False
    container.get_agent.side_effect = _Built("the analyst was built")
    # The two stages under test; a profile's verdict and report stages play no part.
    container.active_profile.return_value = SimpleNamespace(stages=[_STATIC, stage])
    return container, events


def _state(**extra: Any) -> dict[str, Any]:
    return {"file_hash": "abc123", "sample_path": "/s/abc123.exe", **extra}


def _call(node: Any, state: dict[str, Any]) -> Any:
    """What the node returns, or ``None`` where it went on to build its analyst."""
    try:
        return node(state)
    except _Built:
        return None


def _run(stage: StageDefinition, agent: str, state: dict[str, Any], **kw: Any) -> Any:
    container, events = _container(stage, **kw)
    node = make_stage_agent_node(stage, agent, container)
    return container, events, _call(node, state)


class TestTheDatalessStageIsSkipped:
    def test_no_analyst_is_built_and_the_reason_is_recorded(self) -> None:
        stage = _stage(["dynamic"])
        container, events, out = _run(stage, "dynamic", _state())

        container.get_agent.assert_not_called()
        record = out["stage_results"]["dynamic"]
        assert record["ran"] is False
        assert record[DATALESS_STAGE_KEY] is True
        assert SANDBOX_REPORT in record["reason"] and STORED in record["reason"]
        # The analyst's own reason is the no-data guard's; the kinds are the stage's.
        assert record["agent_reasons"] == {"dynamic": NO_AGENT_DATA_REASON}

    def test_the_console_is_told_the_stage_was_skipped_and_why(self) -> None:
        stage = _stage(["dynamic"])
        _container_, events, out = _run(stage, "dynamic", _state())

        kinds = [kind for kind, _data in events]
        assert "stage_started" not in kinds
        skipped = [data for kind, data in events if kind == "stage_skipped"]
        assert skipped == [
            {
                "stage": "dynamic",
                "kind": "analysis",
                "reason": out["stage_results"]["dynamic"]["reason"],
            }
        ]
        statuses = [data.get("status") for kind, data in events if kind == "agent_message"]
        assert statuses == ["no_data"]

    def test_the_analyst_leaves_a_skip_line_and_an_empty_isr(self) -> None:
        stage = _stage(["dynamic"])
        _c, _e, out = _run(stage, "dynamic", _state())

        assert out["reports"]["dynamic"] == (
            "[WARN] dynamic: no dynamic data available for this sample — analyst skipped."
        )
        assert out["isr_reports"]["dynamic"].claims == []

    def test_every_analyst_of_a_parallel_stage_is_skipped_and_the_records_merge(self) -> None:
        stage = _stage(["dynamic", "dynamic_two"])
        merged: dict[str, Any] = {}
        for agent in stage.agents:
            _c, _e, out = _run(stage, agent, _state())
            merged = _merge_stage_results(merged, out["stage_results"])

        record = merged["dynamic"]
        assert record["ran"] is False and record[DATALESS_STAGE_KEY] is True
        assert set(record["agent_reasons"]) == {"dynamic", "dynamic_two"}
        assert dataless_stages({"stage_results": merged}) == [
            ("dynamic", record["reason"], ["dynamic", "dynamic_two"])
        ]

    def test_its_analysts_are_not_among_those_that_ran(self) -> None:
        stage = _stage(["dynamic"])
        container, _e, out = _run(stage, "dynamic", _state())
        results = {"static": {"ran": True, "claim_count": 0}, **out["stage_results"]}

        assert _agents_that_ran(container, {"stage_results": results}) == ["static"]  # type: ignore[arg-type]


class TestAStageWithAnyDataRuns:
    def _runs(self, stage: StageDefinition, agent: str, state: dict[str, Any]) -> None:
        container, events, out = _run(stage, agent, state)
        container.get_agent.assert_called_once_with(agent)
        assert out is None
        assert "stage_skipped" not in [kind for kind, _data in events]
        assert "stage_started" in [kind for kind, _data in events]

    def test_a_sandbox_report_is_data(self) -> None:
        report = {"target": {"sha256": "abc123"}, "behavior": {"processes": []}}
        self._runs(_stage(["dynamic"]), "dynamic", _state(sandbox_report=report))

    def test_a_synthetic_sandbox_report_is_not(self) -> None:
        report = {"target": {"sha256": "abc123"}, "synthetic": True}
        stage = _stage(["dynamic"])
        container, _e, out = _run(stage, "dynamic", _state(sandbox_report=report))
        container.get_agent.assert_not_called()
        record = out["stage_results"]["dynamic"]
        assert record[DATALESS_STAGE_KEY] is True
        assert record["agent_reasons"] == {"dynamic": SYNTHETIC_SANDBOX_REASON}
        assert SYNTHETIC_SANDBOX_REASON in out["reports"]["dynamic"]

    def test_stored_data_for_the_sample_is_data(self) -> None:
        stage = _stage(["dynamic"])
        container, _events = _container(stage)
        container.holds_stored_data.return_value = True
        node = make_stage_agent_node(stage, "dynamic", container)
        assert _call(node, _state()) is None
        container.get_agent.assert_called_once_with("dynamic")

    def test_one_analyst_with_data_runs_the_whole_stage(self) -> None:
        stage = _stage(["dynamic", "static"])
        self._runs(stage, "dynamic", _state())
        self._runs(stage, "static", _state())

    def test_an_analyst_holding_a_tool_over_the_sample_runs(self) -> None:
        """The network analyst's reputation lookup reads the sample's hash."""
        report = {"target": {"sha256": "abc123"}, "network": {"dns": []}}
        self._runs(_stage(["network"], key="network"), "network", _state(sandbox_report=report))

    def test_an_undeclared_agent_runs(self) -> None:
        stage = _stage(["undeclared"])
        container, events = _container(stage)
        container.agent_role.side_effect = None
        node = make_stage_agent_node(stage, "undeclared", container)
        assert _call(node, _state()) is None
        container.get_agent.assert_called_once_with("undeclared")


class TestDependsOn:
    def test_findings_injected_from_a_stage_that_found_something_are_data(self) -> None:
        stage = _stage(["dynamic"])
        results = {"static": {"ran": True, "claim_count": 3}}
        container, _e, _out = _run(stage, "dynamic", _state(stage_results=results))
        container.get_agent.assert_called_once_with("dynamic")

    def test_an_upstream_stage_that_found_nothing_is_no_data(self) -> None:
        stage = _stage(["dynamic"])
        results = {"static": {"ran": True, "claim_count": 0}}
        container, _e, _out = _run(stage, "dynamic", _state(stage_results=results))
        container.get_agent.assert_not_called()

    def test_a_stage_that_injects_nothing_reads_nothing_from_upstream(self) -> None:
        stage = _stage(["dynamic"], inject="none")
        results = {"static": {"ran": True, "claim_count": 3}}
        container, _e, _out = _run(stage, "dynamic", _state(stage_results=results))
        container.get_agent.assert_not_called()

    def test_a_dataless_upstream_stage_does_not_skip_one_with_data(self) -> None:
        upstream = _stage(["dynamic"], key="dynamic")
        downstream = StageDefinition(
            key="static_late", kind="analysis", agents=["static"], depends_on=["dynamic"]
        )
        _c, _e, out = _run(upstream, "dynamic", _state())
        container, _events = _container(downstream)
        node = make_stage_agent_node(downstream, "static", container)
        assert _call(node, _state(stage_results=out["stage_results"])) is None
        container.get_agent.assert_called_once_with("static")


class TestWhatIsLeftAsItWas:
    def test_the_mock_pipeline_is_not_skipped(self) -> None:
        stage = _stage(["dynamic"])
        _c, events, out = _run(stage, "dynamic", _state(), mock=True)
        assert out["reports"]["dynamic"].startswith("MOCK:")
        assert "stage_started" in [kind for kind, _data in events]

    def test_a_stage_with_no_agents_reads_no_decision(self) -> None:
        container, _events = _container(_stage([]))
        assert dataless_stage_reason(_stage([]), _state(), container) == ""  # type: ignore[arg-type]

    def test_a_decision_that_cannot_be_read_runs_the_stage(self) -> None:
        stage = _stage(["dynamic"])
        container, _events = _container(stage)
        container.holds_stored_data.side_effect = RuntimeError("unreadable")
        assert dataless_stage_reason(stage, _state(), container) == ""  # type: ignore[arg-type]


class TestTheVerdictSaysTheAnalystWasSkipped:
    """The degradation reasons name a dataless stage's analysts as skipped, in team order.

    The same run with the dynamic analyst skipped by its own guard inside a
    stage that ran (the shape before the stage was skipped) gives the same
    sentence: the analysts are placed where their stages stand in the team.
    """

    def _reasons(self, *, dataless_stage: bool) -> list[str]:
        import asyncio
        from unittest.mock import AsyncMock

        from malspark.agents.judge_agent import JudgeVerdict
        from malspark.core.config import ProfileDefinition, stages_from_analysts
        from malspark.schemas.evidence import EvidenceCounter
        from malspark.schemas.isr_models import AgentISR
        from malspark.schemas.stix_models import Bundle
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import (
            _state as judge_state,
        )
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import (
            _TeamContainer,
        )

        stages = stages_from_analysts(["static"])
        at = next(i for i, s in enumerate(stages) if s.key == "analysis") + 1
        stages[at:at] = [
            StageDefinition(key="dynamic", kind="analysis", agents=["dynamic"]),
            StageDefinition(key="network", kind="analysis", agents=["network"]),
        ]
        team = ["static", "dynamic", "network"]
        profile = ProfileDefinition(label="t", stages=stages, analysts=team)

        class _Container(_TeamContainer):
            def analyst_keys(self) -> list[str]:
                return team

            def active_profile(self) -> Any:
                return profile

        state = judge_state([])
        empty = {name: AgentISR(agent_id=name, domain=name, claims=[]) for name in team[1:]}
        state["isr_reports"] = {**state["isr_reports"], **empty}
        state["reports"] = {
            **state["reports"],
            "dynamic": f"[WARN] dynamic: {SYNTHETIC_SANDBOX_REASON} — analyst skipped.",
            "network": f"[WARN] network: {SYNTHETIC_SANDBOX_REASON} — analyst skipped.",
        }
        # The mock sandbox's stand-in for a detonation that never ran.
        state["sandbox_report"] = {"synthetic": True, "signatures": []}
        own_guard = {"ran": True, "agent_reasons": {"network": SYNTHETIC_SANDBOX_REASON}}
        dynamic: dict[str, Any] = {
            "ran": True,
            "agents": ["dynamic"],
            "agent_reasons": {"dynamic": SYNTHETIC_SANDBOX_REASON},
        }
        if dataless_stage:
            dynamic = {
                **dynamic,
                "ran": False,
                "reason": "the job holds none of the data its analysts read (a sandbox report)",
                DATALESS_STAGE_KEY: True,
            }
        state["stage_results"] = {
            "analysis": {"ran": True, "claim_count": 1, "agents": ["static"]},
            "dynamic": dynamic,
            "network": {**own_guard, "agents": ["network"]},
        }
        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        return list(asyncio.run(make_judge_node(container)(state))["degradation_reasons"])

    def test_the_analysts_are_named_skipped_for_no_sandbox_data_in_team_order(self) -> None:
        reasons = self._reasons(dataless_stage=True)
        assert "analysts skipped (no sandbox data): dynamic, network" in reasons
        assert not any(r.startswith("analysts produced no claims:") for r in reasons)

    def test_the_reasons_are_those_of_the_analyst_skipped_by_its_own_guard(self) -> None:
        assert self._reasons(dataless_stage=True) == self._reasons(dataless_stage=False)
