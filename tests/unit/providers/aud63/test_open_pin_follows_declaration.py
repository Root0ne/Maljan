"""PS-L6: the sample pin wraps the open tool the block declares, not a fixed name."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import create_model

from maljan.core.config import SampleOpenConfig
from maljan.providers.base import StaticJobContext
from maljan.providers.static.ghidra import GhidraStaticProvider


def test_the_declared_open_tool_and_argument_are_pinned():
    provider = GhidraStaticProvider.__new__(GhidraStaticProvider)
    provider._job = StaticJobContext(mirror_sample_path="/data/samples/x.exe")
    provider._cfg = SimpleNamespace(
        sample_open=SampleOpenConfig(open_tool="import_binary", path_argument="path"),
        transport="stdio",
        url="",
    )
    calls: list[dict[str, Any]] = []

    async def run(**kwargs: Any) -> str:
        calls.append(dict(kwargs))
        return "ok"

    tool = StructuredTool.from_function(
        func=None,
        coroutine=run,
        name="import_binary",
        description="d",
        args_schema=create_model("A", path=(str, ...)),
    )
    [wrapped] = provider._pin_load_program_path([tool])
    asyncio.run(wrapped.coroutine(path="/invented"))
    assert calls == [{"path": "/data/samples/x.exe"}]
