"""The dataless-stage decision over the shipped settings, bindings and declarations.

Every server an agent reaches counts, however it is bound: a reference by
key, a capability, or the server's own ``agents`` list, which is how the
shipped map binds the network and threat-intel servers. Reading only the
definition's references skipped an agent its server map gave a reputation
lookup.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from maljan.core.config import AgentDefinition, Settings, StageDefinition, ToolRef
from maljan.pipeline.data_needs import CAPTURE, NETWORK
from maljan.pipeline.nodes import dataless_stage_reason

# A real sandbox report whose network block holds nothing.
_EMPTY_NETWORK = {
    "target": {"file": {"name": "x.exe"}},
    "behavior": {"processes": [{"pid": 1}]},
    "network": {"dns": [], "http": [], "hosts": []},
}


@pytest.fixture
def settings() -> Settings:
    held = Settings()
    held.agents.definitions["netlite"] = AgentDefinition(
        role="network",
        tools=[ToolRef(kind="mcp", server="network"), ToolRef(kind="mcp", server="knowledge")],
    )
    return held


def _reason(settings: Settings, agent: str) -> str:
    container: Any = SimpleNamespace(config=settings, holds_stored_data=lambda _h, _a: False)
    stage = StageDefinition(key="net", kind="analysis", agents=[agent])
    state: Any = {"file_hash": "a" * 64, "sandbox_report": _EMPTY_NETWORK}
    return dataless_stage_reason(stage, state, container)


def test_the_shipped_network_analyst_runs_on_an_empty_network_block(settings: Settings) -> None:
    """Its reputation servers read the sample's hash."""
    assert _reason(settings, "network") == ""


def test_a_capture_and_reference_only_agent_is_skipped(settings: Settings) -> None:
    reason = _reason(settings, "netlite")
    assert reason
    assert CAPTURE in reason and NETWORK in reason


def test_a_server_bound_by_its_own_agents_list_keeps_the_agent_running(
    settings: Settings,
) -> None:
    settings.mcp.servers["threatintel"].agents.append("netlite")
    assert _reason(settings, "netlite") == ""


def test_a_server_withheld_by_the_profile_does_not_count(settings: Settings) -> None:
    """``exclude_servers`` takes the reputation servers away; what is left reads no data."""
    from maljan.agents.composition import active_profile

    settings.mcp.servers["threatintel"].agents.append("netlite")
    active_profile(settings).exclude_servers.append("threatintel")
    assert _reason(settings, "netlite")
