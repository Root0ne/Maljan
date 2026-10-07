"""A static analyst and a configurable agent on r2 have their provider open the mirror first.

r2mcp refuses every call but ``open_file`` until a file is open. The r2
provider opens its mirror (``R2StaticProvider.open_sample``); this pins that
both analyst classes ask it to, with the pinned mirror, before their loop.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.static_analyst import StaticAnalyst

MIRROR = "/srv/samples/r2-work/" + "cd" * 32 + ".exe"
HEAD_CHUNK = json.dumps({"analysis_file_path": MIRROR})


class _Stop(Exception):
    pass


class _Provider:
    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.opened: list[str | None] = []

    def open_sample(self, path: str | None = None) -> bool:
        self.opened.append(path)
        self.order.append("open")
        return True


def _loop(order: list[str]) -> Any:
    def run(_messages: Any) -> str:
        order.append("loop")
        raise _Stop

    return run


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda: "", name=name, description=name, infer_schema=True
    )


def test_the_static_analyst_opens_the_pinned_mirror_before_its_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    provider = _Provider(order)
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.logger = logging.getLogger("test.r2_open")
    analyst.name = "all_tools_static_r2"
    analyst.tools = []
    analyst._analysis_file_path = MIRROR
    analyst._host_sample_path = None
    monkeypatch.setattr(analyst, "_try_initialize_mcp", lambda: None)
    monkeypatch.setattr(analyst, "_provider", lambda: provider)
    monkeypatch.setattr(analyst, "_compute_sink_priority_hint", lambda _path: "")
    monkeypatch.setattr(analyst, "_compute_function_hash_hint", lambda *_a: "")
    monkeypatch.setattr(analyst, "_system_prompt", lambda *_a, **_k: "system")
    monkeypatch.setattr(analyst, "execute_tool_loop", _loop(order))

    with pytest.raises(_Stop):
        analyst.analyze_isr(HEAD_CHUNK)

    assert provider.opened == [MIRROR]
    assert order == ["open", "loop"]


def test_a_configurable_agent_on_r2_opens_the_pinned_mirror_before_its_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    provider = _Provider(order)
    resolved = ResolvedAgent(
        key="all_tools_static_r2",
        role="generic",
        prompt="read it with radare2",
        tools=stamp_source([_tool("decompile_function")], PROVIDER_FAMILY),
        static_provider_id="r2",
        llm=None,
    )
    analyst = ConfigurableAnalyst("all_tools_static_r2", resolved, llm=None)  # type: ignore[arg-type]
    analyst._analysis_file_path = MIRROR
    monkeypatch.setattr(analyst, "_own_static_provider", lambda: provider)
    monkeypatch.setattr(analyst, "execute_tool_loop", _loop(order))

    try:
        analyst.analyze_isr(HEAD_CHUNK)
    except _Stop:
        pass

    assert provider.opened == [MIRROR]
    assert order[:2] == ["open", "loop"]
