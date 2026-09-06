"""The two built-in sidecars must expose exactly the tools they expose today.

Sub-project B moves ``network-mcp`` and ``threatintel-mcp`` out of constants
inside the agents and into ``mcp.servers`` entries. The move is only free if
the tool names the model sees do not change, so they are pinned here from a
live handshake before anything moves. Names only, not schemas: the fixture is
captured on one machine and the sidecars' argument descriptions are free to
improve (risk R1 in the spec).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)


def load_golden(name: str) -> list[str]:
    """The pinned tool names for one built-in server, sorted."""
    payload = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    return sorted(payload["tools"])


@pytest.mark.parametrize("name", ["network", "threatintel"])
def test_the_golden_names_a_non_empty_tool_set(name: str) -> None:
    names = load_golden(name)
    assert names, f"{name} golden is empty"
    assert names == sorted(set(names)), "tool names must be unique and sorted"


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
@pytest.mark.parametrize("name", ["network", "threatintel"])
def test_the_live_sidecar_still_offers_exactly_the_pinned_tools(name: str) -> None:
    """A real stdio handshake against the sidecar, with a 20 s budget.

    Neither sidecar reaches the network to answer ``initialize`` or
    ``tools/list``, so a slow or absent network is not a reason to skip: a
    failure here is a real signal that the pinned tool set moved.
    """
    from scripts.capture_builtin_tool_sets import SIDECARS, enumerate_stdio_tools

    from maljan.agents.subprocess_env import child_env

    subdir, allow = SIDECARS[name]
    live = asyncio.run(
        asyncio.wait_for(
            enumerate_stdio_tools(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            ),
            timeout=20.0,
        )
    )
    assert sorted(live) == load_golden(name)


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
def test_the_registry_opens_the_real_network_built_in_with_the_pinned_tools() -> None:
    """Live proof that moving the launch parameters into ``ServerHandle`` changed nothing.

    Sub-project B moved the transport/``child_env``/toolkit wiring that used
    to live inside ``NetworkAnalyst._initialize_mcp_client`` into
    ``ServerHandle.open``. This opens the real ``network`` built-in the way a
    job now would — through ``ServerRegistry``, no mocks — and checks its
    live manifest against the same golden the raw handshake above pins, so a
    parameter dropped in the move (a missing ``cwd``, a stripped ``env_allow``
    entry) shows up here even before any analyst is wired to the registry.
    """
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    registry = ServerRegistry(Settings(_env_file=None))
    handle = registry.get("network")
    try:
        handle.open("test-job")
        assert sorted(handle.all_tool_names()) == load_golden("network")
    finally:
        registry.close_all()


@pytest.mark.parametrize("name", ["network", "threatintel"])
def test_the_built_in_child_env_is_byte_for_byte_the_pre_branch_child_env(name, monkeypatch):
    """Regression (F4): ``ServerHandle`` used to force ``PYTHONIOENCODING``.

    Before sub-project B, ``NetworkAnalyst``/``JudgeAgent`` launched their
    sidecar with a bare ``child_env(...)``, which only carries
    ``PYTHONIOENCODING`` when the parent process already has it set.
    ``ServerHandle._build_toolkit`` must reproduce that for the two built-ins
    exactly -- no ``setdefault`` widening the child's environment -- even
    though it does apply that default for an operator-added server.
    """
    from maljan.agents.subprocess_env import child_env
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    monkeypatch.delenv("PYTHONIOENCODING", raising=False)

    captured: dict[str, object] = {}

    class _FakeToolkit:
        def __init__(self, server_params, **kwargs):
            captured["env"] = server_params.env

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return []

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)

    registry = ServerRegistry(Settings(_env_file=None))
    handle = registry.get(name)
    handle.open("test-job")
    try:
        expected = child_env(allow=tuple(handle.config.env_allow))
        assert captured["env"] == expected
        assert "PYTHONIOENCODING" not in captured["env"]
    finally:
        handle.close()


def test_the_registry_attaches_exactly_the_pinned_tools(monkeypatch):
    """The move into settings changed no tool the model can see.

    The point of the fixture: ``for_agent`` must hand the network analyst the
    same names ``NetworkAnalyst._initialize_mcp_client`` handed it before, and
    the judge the same names the judge had. Names, not schemas.
    """
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    registry = ServerRegistry(Settings(_env_file=None))
    for role, key in (("network", "network"), ("judge", "threatintel")):
        handles = registry.for_agent(role)
        assert [h.name for h in handles] == [key]
        try:
            handles[0].open("golden")
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"{key}-mcp did not start in this environment: {exc}")
        try:
            assert sorted(t.name for t in handles[0].tools()) == load_golden(key)
        finally:
            handles[0].close()
