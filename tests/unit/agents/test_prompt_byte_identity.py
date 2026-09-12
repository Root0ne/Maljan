"""The default profile's prompts are frozen.

Captured from `dev` by ``scripts/goldens/capture_provider_goldens.py`` before the
provider refactor. Any change to a byte of the static (ghidra) or dynamic
(cape2) system prompt is a behaviour change and fails here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
PROMPTS = FIXTURES / "prompts"


def _golden(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def test_static_ghidra_system_prompt_is_byte_identical():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")


def test_dynamic_cape2_system_prompt_is_byte_identical():
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("dynamic_system_cape2.txt")


def test_the_assembled_static_prompt_equals_the_golden():
    from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL
    from maljan.core.config import Settings
    from maljan.providers.static.ghidra import GhidraStaticProvider

    provider = GhidraStaticProvider.from_settings(Settings(_env_file=None))
    assembled = _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL
    assert assembled == _golden("static_isr_system_ghidra.txt")


def test_the_module_constant_is_still_the_assembled_prompt():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")


def test_the_assembled_dynamic_prompt_equals_the_golden():
    from maljan.agents.dynamic_analyst import _DYN_HEAD, _DYN_TAIL
    from maljan.core.config import Settings
    from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    assert _DYN_HEAD + provider.dynamic_prompt_fragment() + _DYN_TAIL == _golden(
        "dynamic_system_cape2.txt"
    )


@pytest.fixture(autouse=True)
def _no_real_tool_servers(monkeypatch):
    """Resolve prompts without spawning the built-in sidecars.

    ``resolve_agent`` attaches every server bound to the role, so resolving the
    judge or the network analyst against a real container used to start the
    network and threat-intel sidecars: two child processes a prompt test never
    reads, and nothing closed them. Dropping the container with those handles
    still open is what drove the agent loop into anyio's cancel-delivery spin
    for the rest of the test process (BUG 13). The stand-ins attach nothing
    real, and ``container`` closes whatever they did attach.
    """
    from unittest.mock import AsyncMock, MagicMock

    def factory(*args, **kwargs):
        toolkit = MagicMock()
        toolkit.initialize = AsyncMock(return_value=None)
        toolkit.get_tools = MagicMock(return_value=[])
        toolkit.cleanup = AsyncMock(return_value=None)
        return toolkit

    def run_async_stub(coro, label):
        coro.close()

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)
    monkeypatch.setattr("maljan.providers.servers._run_async", run_async_stub)


@pytest.fixture
def container():
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    built = ServiceContainer(Settings(_env_file=None), mock=True)
    yield built
    built.get_server_registry().close_all()


def test_the_resolved_static_prompt_is_the_golden(container):
    from maljan.agents.composition import resolve_agent

    assert resolve_agent("static", container).prompt == _golden("static_isr_system_ghidra.txt")


def test_the_resolved_dynamic_prompt_is_the_golden(container):
    """Pinned to CAPE2, exactly as ``dynamic_analyst._ISR_SYSTEM`` always was.

    The dynamic analyst has never assembled its prompt from the *configured*
    sandbox (that field defaults to ``mock``, whose fragment is empty); it
    sends this frozen constant on every run. Resolution says the same thing,
    or the default profile would change the day this landed.
    """
    from maljan.agents.composition import resolve_agent
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM

    assert resolve_agent("dynamic", container).prompt == _ISR_SYSTEM
    assert _ISR_SYSTEM == _golden("dynamic_system_cape2.txt")


def test_the_resolved_network_and_judge_prompts_are_their_constants(container):
    from maljan.agents.composition import resolve_agent
    from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM
    from maljan.agents.network_analyst import _ISR_SYSTEM as NETWORK_SYSTEM

    assert resolve_agent("network", container).prompt == NETWORK_SYSTEM
    assert resolve_agent("judge", container).prompt == JUDGE_VERDICT_SYSTEM


def test_the_resolved_static_tool_set_is_todays_registry_tool_set(container):
    """Under the default profile nothing is bound to ``static``, and that is the point.

    ``resolve_agent`` composes the *registry* half of an agent's tools; the
    provider half stays where it has always been, inside
    ``StaticAnalyst._initialize_mcp_client``, so the Ghidra attach is not
    pulled forward into resolution. Both halves are unchanged; this pins the
    half resolution owns.
    """
    from maljan.agents.composition import resolve_agent
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    expected, _ = ServerRegistry(Settings(_env_file=None)).tools_for("static", "job")
    assert [t.name for t in resolve_agent("static", container).tools] == [t.name for t in expected]
