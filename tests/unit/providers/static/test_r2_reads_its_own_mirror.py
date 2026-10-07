"""The r2 analyst is handed the mirror radare2 can open, and its session opens it first.

An r2 analyst's chunk carried the worker's staging path beside the r2 mirror;
the model sent the staging path, radare2 refused it ("Failed to open file."),
and the remediation named neither path. A listing tool called before any open
was refused with r2mcp's open-first error and no remediation at all. Now:

* no chunk carries the worker's path, and a path argument that spells the
  worker's copy in full is replaced with the path the tool's server opens;
* the r2 provider opens its mirror in r2mcp's session before the loop, as the
  Ghidra provider loads its program;
* a failed open names the path it tried and the path radare2 can open, and an
  open-first refusal names the readable path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.tool_pinning import pin_paths
from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.pipeline.nodes import _augment_static_chunks_with_path
from maljan.providers.static import r2
from maljan.tools.errors import error_parts

SHA = "ab" * 32
MIRROR = f"/srv/samples/r2-work/{SHA}.exe"


class _OpenArgs(BaseModel):
    file_path: str = ""


def _open_tool(reply: Any, seen: list[str]) -> StructuredTool:
    async def _call(file_path: str = "") -> Any:
        seen.append(file_path)
        return reply(file_path) if callable(reply) else reply

    return StructuredTool.from_function(
        func=None,
        coroutine=_call,
        name="open_file",
        description="Open a file",
        args_schema=_OpenArgs,
        infer_schema=False,
        metadata={"maljan_server": "r2"},
    )


class TestTheChunk:
    def test_it_names_the_r2_mirror_and_never_the_worker_s_path(self) -> None:
        staged = f"/srv/samples/.tmp/{SHA}.exe"
        content = json.dumps({"sha256": SHA})
        chunk = TextChunk(
            index=0,
            total=1,
            strategy=ChunkStrategy.SLIDING_WINDOW,
            content=content,
            char_count=len(content),
            token_estimate=len(content) // 4,
            domain="static",
        )
        state = {"static_sample_paths": {"r2": MIRROR}, "sample_path": staged, "file_hash": SHA}

        head = _augment_static_chunks_with_path([chunk], state, provider_id="r2")[0].content  # type: ignore[arg-type]

        assert json.loads(head)["analysis_file_path"] == MIRROR
        assert staged not in head


class TestThePathArgument:
    def test_the_worker_s_copy_spelled_in_full_is_replaced_with_the_mirror(
        self, tmp_path: Path
    ) -> None:
        staged = tmp_path / ".tmp" / f"{SHA}.exe"
        staged.parent.mkdir()
        staged.write_bytes(b"MZ")
        seen: list[str] = []

        (tool,) = pin_paths(
            [_open_tool("File opened successfully.", seen)],
            default_path=MIRROR,
            agent_name="static_r2",
            staged_path=str(staged),
        )
        asyncio.run(tool.ainvoke({"file_path": str(staged)}))

        assert seen == [MIRROR]

    def test_another_existing_file_keeps_its_path(self, tmp_path: Path) -> None:
        other = tmp_path / "dropped.bin"
        other.write_bytes(b"MZ")
        seen: list[str] = []

        (tool,) = pin_paths(
            [_open_tool("File opened successfully.", seen)],
            default_path=MIRROR,
            staged_path=str(tmp_path / ".tmp" / f"{SHA}.exe"),
        )
        asyncio.run(tool.ainvoke({"file_path": str(other)}))

        assert seen == [str(other)]


class TestTheRemediation:
    def test_a_failed_open_names_the_path_tried_and_the_readable_one(self) -> None:
        tried = f"/srv/samples/.tmp/{SHA}.exe"
        wrapped = r2._reading_error_replies(_open_tool("Failed to open file.", []), lambda: MIRROR)

        reply = asyncio.run(wrapped.ainvoke({"file_path": tried}))
        code, message, remediation = error_parts(reply) or ("", "", "")

        assert message == "Failed to open file."
        assert remediation is not None
        assert tried in remediation and MIRROR in remediation

    def test_a_failed_open_of_the_readable_path_says_so(self) -> None:
        wrapped = r2._reading_error_replies(_open_tool("Failed to open file.", []), lambda: MIRROR)

        reply = asyncio.run(wrapped.ainvoke({"file_path": MIRROR}))
        _code, _message, remediation = error_parts(reply) or ("", "", "")

        assert remediation is not None and MIRROR in remediation
        assert "server log" in remediation

    def test_the_open_first_protocol_error_names_the_readable_path(self) -> None:
        marker = {
            "tool_error": "exception",
            "tool": "list_files",
            "type": "McpError",
            "detail": "Use the open_file method before calling any other method",
        }

        failure = r2.r2_error_reply("list_files", json.dumps(marker), readable=MIRROR)

        assert failure is not None
        assert failure["error"]["remediation"] == (
            f"call open_file with {MIRROR}, then call this tool again"
        )

    def test_without_a_readable_path_the_advice_is_as_before(self) -> None:
        failure = r2.r2_error_reply("list_strings", "No file is currently open.")

        assert failure is not None
        assert failure["error"]["remediation"] == r2._R2_OPEN_FILE_FIRST

    def test_another_marker_is_not_read_as_an_open_first_error(self) -> None:
        marker = {"tool_error": "exception", "detail": "connection reset"}

        assert r2.r2_error_reply("list_files", json.dumps(marker), readable=MIRROR) is None


class _Handle:
    def __init__(self, tools: list[Any]) -> None:
        self._tools = tools

    def tools(self) -> list[Any]:
        return list(self._tools)


def _provider(open_tool: StructuredTool) -> r2.R2StaticProvider:
    provider = r2.R2StaticProvider.__new__(r2.R2StaticProvider)
    provider._handle = _Handle([open_tool])  # type: ignore[assignment]
    provider._job = None
    return provider


class TestTheSessionOpensTheMirror:
    def test_the_pinned_mirror_is_opened_before_the_loop(self) -> None:
        seen: list[str] = []
        provider = _provider(_open_tool("File opened successfully.", seen))
        provider.pin_sample(MIRROR)

        assert provider.open_sample() is True
        assert seen == [MIRROR]

    def test_a_failed_open_is_reported_and_changes_nothing_else(self) -> None:
        seen: list[str] = []
        provider = _provider(_open_tool("Failed to open file.", seen))

        assert provider.open_sample(MIRROR) is False
        assert seen == [MIRROR]

    def test_no_path_opens_nothing(self) -> None:
        seen: list[str] = []
        provider = _provider(_open_tool("File opened successfully.", seen))

        assert provider.open_sample() is False
        assert seen == []
