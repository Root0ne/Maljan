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
