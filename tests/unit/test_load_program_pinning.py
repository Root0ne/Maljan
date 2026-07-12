"""Tests for load_program path pinning (Ghidra-path fix, 2026-07-12).

Job 60df48cb: on a fresh sample whose chunk lacked ``analysis_file_path``
the LLM hallucinated ``/home/user/data/bin.<sha>`` for ``load_program`` and
the static report claimed "file was not found on the server filesystem" even
though the mirror to ``/data/samples/`` had succeeded. The wrapper installed
by ``StaticAnalyst._pin_load_program_path`` deterministically overrides a
model-supplied ``file`` argument with the known container path.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import create_model

from maljan.agents.static_analyst import StaticAnalyst


def _agent(pinned: str | None) -> StaticAnalyst:
    agent = StaticAnalyst.__new__(StaticAnalyst)
    agent.logger = logging.getLogger("test.load_program_pinning")
    agent._analysis_file_path = pinned
    return agent


def _fake_load_program(calls: list[dict[str, Any]]) -> StructuredTool:
    async def arun_tool(**kwargs: Any) -> str:
        calls.append(dict(kwargs))
        return f"loaded {kwargs.get('file')}"

    return StructuredTool.from_function(
        func=None,
        coroutine=arun_tool,
        name="load_program",
        description="Load a program from the server filesystem.",
        args_schema=create_model("LoadProgramArgs", file=(str, ...)),
    )


class TestLoadProgramPinning:
    def test_overrides_hallucinated_path(self) -> None:
        calls: list[dict[str, Any]] = []
        agent = _agent("/data/samples/x.exe")
        [wrapped] = agent._pin_load_program_path([_fake_load_program(calls)])
        result = asyncio.run(wrapped.coroutine(file="/home/user/data/bin.x"))
        assert calls == [{"file": "/data/samples/x.exe"}]
        assert "/data/samples/x.exe" in result

    def test_passthrough_when_unpinned(self) -> None:
        calls: list[dict[str, Any]] = []
        agent = _agent(None)
        [wrapped] = agent._pin_load_program_path([_fake_load_program(calls)])
        asyncio.run(wrapped.coroutine(file="/model/choice.exe"))
        assert calls == [{"file": "/model/choice.exe"}]

    def test_passthrough_when_paths_match(self) -> None:
        calls: list[dict[str, Any]] = []
        agent = _agent("/data/samples/x.exe")
        [wrapped] = agent._pin_load_program_path([_fake_load_program(calls)])
        asyncio.run(wrapped.coroutine(file="/data/samples/x.exe"))
        assert calls == [{"file": "/data/samples/x.exe"}]

    def test_late_binding_reads_pin_at_call_time(self) -> None:
        # The agent is cached across samples: the pin set AFTER wrapping
        # must still win (nodes.py assigns per-run).
        calls: list[dict[str, Any]] = []
        agent = _agent(None)
        [wrapped] = agent._pin_load_program_path([_fake_load_program(calls)])
        agent._analysis_file_path = "/data/samples/late.exe"
        asyncio.run(wrapped.coroutine(file="/hallucinated.bin"))
        assert calls == [{"file": "/data/samples/late.exe"}]

    def test_preserves_tool_identity(self) -> None:
        agent = _agent("/data/samples/x.exe")
        original = _fake_load_program([])
        [wrapped] = agent._pin_load_program_path([original])
        assert wrapped is not original
        assert wrapped.name == original.name
        assert wrapped.description == original.description
        assert wrapped.args_schema is original.args_schema

    def test_non_load_program_tools_untouched(self) -> None:
        agent = _agent("/data/samples/x.exe")

        async def other(**kwargs: Any) -> str:
            return "ok"

        other_tool = StructuredTool.from_function(
            func=None,
            coroutine=other,
            name="list_imports",
            description="List imports.",
            args_schema=create_model("ListImportsArgs"),
        )
        out = agent._pin_load_program_path([other_tool])
        assert out[0] is other_tool

    def test_pin_survives_missing_coroutine(self) -> None:
        agent = _agent("/data/samples/x.exe")

        def sync_load(file: str) -> str:
            return f"loaded {file}"

        sync_tool = StructuredTool.from_function(
            func=sync_load,
            name="load_program",
            description="Sync variant.",
        )
        out = agent._pin_load_program_path([sync_tool])
        assert out[0] is sync_tool
