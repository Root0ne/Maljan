"""The format fragment has to reach the message the analyst actually sends.

``composition.builtin_prompt`` assembles it, but for a long moment only
``ConfigurableAnalyst`` read ``ResolvedAgent.prompt``: the three built-in
analysts built their system turn from a module constant pinned to the neutral
fragment, so every real job — PE, APK, Mach-O alike — was told the sample's
format was not identified. These tests take the container path a job takes and
assert on the system turn each built-in analyst ends up sending.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.prompt_fragments import format_fragment
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer

ROLES = ("static", "dynamic", "network")


def _container(file_type: str, platform: str) -> ServiceContainer:
    """A mock container for one sample's format, with no tool server attached.

    The servers are switched off so building the network analyst does not
    launch an MCP subprocess; the prompt assembly under test does not involve
    them.
    """
    settings = Settings(_env_file=None)
    for server in settings.mcp.servers.values():
        server.enabled = False
    container = ServiceContainer(settings, mock=True)
    container.sample_format = (file_type, platform)
    return container


def _system_turn(agent: Any, method: str, *args: Any) -> str:
    """Run one analyst entry point and return the system turn it built."""
    captured: list[str] = []

    def _capture(messages: Any, *_a: Any, **_kw: Any) -> str:
        for role, text in messages:
            if role == "system":
                captured.append(text)
        return "CLAIM: none\nEVIDENCE: none\nCONFIDENCE: 0.1\n"

    with (
        patch.object(agent, "_initialize_mcp_client", return_value=None),
        patch.object(agent, "_try_initialize_mcp", return_value=False),
        patch.object(agent, "execute_tool_loop", side_effect=_capture),
    ):
        getattr(agent, method)(*args)
    assert captured, "the analyst sent no system message"
    return captured[0]


@pytest.mark.parametrize("role", ROLES)
class TestEveryBuiltInRoleResolvesTheJobsFormat:
    def test_a_windows_job_resolves_the_windows_artefacts(self, role: str) -> None:
        agent = _container("pe", "windows").get_agent(role)
        assert format_fragment("pe", "windows") in agent._resolved.prompt
        assert agent._system_prompt("NEUTRAL-FALLBACK") == agent._resolved.prompt

    def test_an_android_job_resolves_the_android_artefacts(self, role: str) -> None:
        agent = _container("apk", "android").get_agent(role)
        prompt = agent._resolved.prompt
        assert format_fragment("apk", "android") in prompt
        assert "DEX classes" in prompt
        assert format_fragment("unknown", "unknown") not in prompt


class TestTheSystemTurnTheAnalystSends:
    """The two roles whose entry points build their messages through the tool loop."""

    @pytest.mark.parametrize("role", ["static", "dynamic"])
    def test_a_pe_job_is_told_about_windows_artefacts(self, role: str) -> None:
        system = _system_turn(_container("pe", "windows").get_agent(role), "analyze", "data")
        assert format_fragment("pe", "windows") in system
        assert format_fragment("unknown", "unknown") not in system

    @pytest.mark.parametrize("role", ["static", "dynamic"])
    def test_an_apk_job_is_told_about_android_artefacts(self, role: str) -> None:
        system = _system_turn(_container("apk", "android").get_agent(role), "analyze", "data")
        assert format_fragment("apk", "android") in system
        assert "DEX classes" in system

    @pytest.mark.parametrize("role", ["static", "dynamic"])
    def test_the_isr_path_carries_the_same_fragment(self, role: str) -> None:
        system = _system_turn(_container("mach-o", "macos").get_agent(role), "analyze_isr", "data")
        assert format_fragment("mach-o", "macos") in system
        assert "launchd" in system

    def test_the_network_analyst_sends_its_resolved_prompt(self) -> None:
        """Its entry points build the chain themselves rather than through the loop."""
        from maljan.agents.network_analyst import _ISR_SYSTEM

        agent = _container("apk", "android").get_agent("network")
        sent = agent._system_prompt(_ISR_SYSTEM)
        assert format_fragment("apk", "android") in sent
        assert sent != _ISR_SYSTEM


def test_a_windows_dynamic_prompt_still_names_what_it_used_to() -> None:
    """The head lost its Windows nouns; the fragment has to put them back."""
    system = _system_turn(_container("pe", "windows").get_agent("dynamic"), "analyze", "data")
    for noun in ("registry", "services", "scheduled tasks", "DLL", "WinAPI"):
        assert noun.lower() in system.lower(), f"a Windows dynamic prompt lost {noun!r}"


def test_an_analyst_built_outside_a_container_falls_back_to_the_neutral_prompt() -> None:
    """A test, a script or the CLI has no job context; the neutral text is honest."""
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM, DynamicAnalyst

    agent = DynamicAnalyst(llm=MagicMock(), name="dynamic")
    assert agent._system_prompt(_ISR_SYSTEM) == _ISR_SYSTEM
    assert format_fragment("unknown", "unknown") in _ISR_SYSTEM
