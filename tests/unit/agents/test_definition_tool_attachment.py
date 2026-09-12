"""The tools a built-in agent actually receives, not the ones resolution reports.

``StaticAnalyst``, ``DynamicAnalyst``, ``NetworkAnalyst`` and ``JudgeAgent``
build their own tool lists in ``_initialize_mcp_client``; none of them reads
``ResolvedAgent.tools``. So every assertion made through ``resolve_agent`` —
which is what ``test_composition`` does — can be true while the agents run with
nothing, and that is precisely the failure the reference half was added to
prevent: ``analysis`` and ``knowledge`` carry ``agents=[]`` and reach an agent
only through the ``ToolRef``s in its definition.

These tests go through the attachment entry point instead. Delete the reference
loop in ``BaseAnalyst._attach_registry_tools`` or the judge's equivalent and
they fail; nothing else in the suite does.

A fake registry throughout — no sidecar is launched, and the tool names are
stand-ins, so what is being asserted is which *binding* delivered a tool.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.core.config import Settings
from tests.unit.agents.tool_attachment_stubs import (
    FakeRegistry,
    StubProvider,
    StubSandboxProvider,
)

# The tool the ``knowledge`` server contributes in these stubs. It is the one
# server every built-in definition references and no built-in binds by role, so
# seeing it is proof the reference half ran.
KNOWLEDGE_TOOL = "attck_lookup"


def _container(profile: str = "default", registry: FakeRegistry | None = None) -> Any:
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    cfg.agents.profile = profile
    container = ServiceContainer(config=cfg, mock=True)
    container._server_registry_instance = registry or FakeRegistry()
    container.get_server_registry = lambda: container._server_registry_instance  # type: ignore[method-assign]
    container.sandbox_report = {"behavior": {"processes": [{"pid": 1, "process_name": "x.exe"}]}}
    return container


def _analyst(container: Any, key: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A built-in analyst wired to this container, with its provider stubbed out.

    ``container.get_agent`` needs a real model and refuses in mock mode. The
    providers are stubbed to offer nothing so that every tool the analyst ends
    up with came from the registry, which is what these tests are about.
    """
    agent = container.agent_registry.create(key, MagicMock())
    agent._container = container
    if key == "static":
        monkeypatch.setattr(type(agent), "_provider", lambda self: StubProvider())
    if key == "dynamic":
        monkeypatch.setattr(type(agent), "_sandbox_provider", lambda self: StubSandboxProvider())
    return agent


ANALYSTS = ["static", "dynamic", "network"]


class TestTheDefaultProfileDeliversTheReferencedServers:
    @pytest.mark.parametrize("key", ANALYSTS)
    def test_the_analyst_receives_the_knowledge_tools_its_definition_names(
        self, key: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _container()
        agent = _analyst(container, key, monkeypatch)

        agent._try_initialize_mcp()

        assert KNOWLEDGE_TOOL in [t.name for t in agent.tools], (
            f"{key} never received the knowledge tools its definition references"
        )

    def test_the_static_analyst_also_receives_its_analysis_reference(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _container()
        agent = _analyst(container, "static", monkeypatch)

        agent._try_initialize_mcp()

        assert sorted(t.name for t in agent.tools) == ["attck_lookup", "pe_info"]

    def test_the_network_analyst_gets_the_role_bound_half_as_well(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``network`` is bound by role and also referenced, so this is the
        case where both halves run and the collision rule has to hold."""
        registry = FakeRegistry(bound={"network": {"network": ["extract_dns"]}})
        container = _container(registry=registry)
        agent = _analyst(container, "network", monkeypatch)

        agent._try_initialize_mcp()

        names = [t.name for t in agent.tools]
        assert sorted(names) == ["attck_lookup", "extract_dns"]
        assert len(names) == len(set(names)), "a server bound and referenced yields one copy"

    def test_a_reference_the_registry_cannot_serve_is_a_degradation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry(by_server={"analysis": ["pe_info"]})
        container = _container(registry=registry)
        agent = _analyst(container, "static", monkeypatch)

        agent._try_initialize_mcp()

        assert [t.name for t in agent.tools] == ["pe_info"]
        assert any("knowledge" in reason for reason in agent.degradation_reasons)


class TestTheMeasurementProfileLeavesThemToolFree:
    @pytest.mark.parametrize("key", ANALYSTS)
    def test_the_analyst_attaches_nothing_at_all(
        self, key: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The baseline has to hold at *attachment* time. Asserting it only
        through ``resolve_agent`` would leave the agents free to attach tools
        the profile withheld."""
        container = _container(profile="measurement")
        agent = _analyst(container, key, monkeypatch)

        agent._try_initialize_mcp()

        assert agent.tools == []

    @pytest.mark.parametrize("key", ANALYSTS)
    def test_the_registry_is_never_asked_for_a_reference(
        self, key: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry()
        container = _container(profile="measurement", registry=registry)
        agent = _analyst(container, key, monkeypatch)

        agent._try_initialize_mcp()

        assert registry.asked_refs == []

    def test_an_operator_server_bound_by_role_is_withheld_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registry = FakeRegistry(bound={"static": {"operators_own": ["their_tool"]}})
        container = _container(profile="measurement", registry=registry)
        agent = _analyst(container, "static", monkeypatch)

        agent._try_initialize_mcp()

        assert agent.tools == []


class TestTheDynamicAnalystsSandboxReference:
    def test_the_in_process_sandbox_tools_reach_the_analyst(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``ToolRef(kind="sandbox")`` is the dynamic definition's first
        reference, and it resolves to closures over the job's report rather
        than to a server."""
        container = _container()
        agent = _analyst(container, "dynamic", monkeypatch)

        agent._try_initialize_mcp()

        names = [t.name for t in agent.tools]
        assert "sandbox_processes" in names
        assert "sandbox_network" in names
        assert KNOWLEDGE_TOOL in names

    def test_the_sandbox_half_is_withheld_by_the_measurement_profile(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _container(profile="measurement")
        agent = _analyst(container, "dynamic", monkeypatch)

        assert agent._definition_sandbox_tools() == []

    def test_a_definition_that_names_no_sandbox_reference_gets_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _container()
        definitions = container.config.agents.definitions
        definitions["dynamic"] = definitions["dynamic"].model_copy(update={"tools": []})
        agent = _analyst(container, "dynamic", monkeypatch)

        assert agent._definition_sandbox_tools() == []

    def test_the_tools_are_built_over_this_jobs_report(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        container = _container()
        agent = _analyst(container, "dynamic", monkeypatch)

        processes = next(
            t for t in agent._definition_sandbox_tools() if t.name == "sandbox_processes"
        )

        assert processes.invoke({})["total"] == 1


class TestTheJudge:
    @pytest.mark.asyncio
    async def test_the_judge_receives_the_knowledge_tools_it_references(self) -> None:
        """The judge attaches on its own loop rather than through
        ``BaseAnalyst``, so its reference half is a second implementation and
        needs its own proof."""
        from maljan.agents.judge_agent import JudgeAgent

        container = _container()
        judge = JudgeAgent(llm=MagicMock(), config=container.config)
        judge._container = container

        await judge._initialize_mcp_client()

        assert KNOWLEDGE_TOOL in [t.name for t in judge.tools]

    @pytest.mark.asyncio
    async def test_the_judge_still_gets_the_server_bound_to_its_role(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        registry = FakeRegistry(bound={"judge": {"threatintel": ["check_ip_reputation"]}})
        container = _container(registry=registry)
        judge = JudgeAgent(llm=MagicMock(), config=container.config)
        judge._container = container

        await judge._initialize_mcp_client()

        assert sorted(t.name for t in judge.tools) == ["attck_lookup", "check_ip_reputation"]

    @pytest.mark.asyncio
    async def test_the_measurement_profile_leaves_the_judge_tool_free(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        registry = FakeRegistry(bound={"judge": {"threatintel": ["check_ip_reputation"]}})
        container = _container(profile="measurement", registry=registry)
        judge = JudgeAgent(llm=MagicMock(), config=container.config)
        judge._container = container

        await judge._initialize_mcp_client()

        assert judge.tools == []
        assert registry.asked_refs == []


class TestAnAgentWithNoContainer:
    def test_the_reference_half_is_inert_rather_than_raising(self) -> None:
        """An analyst built bare — in a script, or in a test that wants no
        registry — must not acquire a container's worth of machinery to answer
        that it has no references."""
        from maljan.agents.network_analyst import NetworkAnalyst

        agent = NetworkAnalyst(llm=MagicMock(), name="network")

        assert agent._definition_tool_refs() == []
        assert agent._definition_sandbox_tools() == []
        assert agent._profile_excluded_servers() == ""
