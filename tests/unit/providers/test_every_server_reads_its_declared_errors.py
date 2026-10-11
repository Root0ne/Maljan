"""A server's declared error patterns are read from its answers by one function, for every server.

An invented server declared only as data, whose plain-text error sentence is
filed as a failure; a server that declares none keeps its tools untouched;
radare2's adapter reads the same function; the reading stays linear on a
hostile answer ten times the size.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.core.config import MCPServerConfig
from maljan.core.tool_declarations import ErrorPattern
from maljan.providers.declared_errors import declared_error, declared_failure, with_declared_errors
from maljan.providers.servers import ServerHandle
from maljan.tools.errors import BAD_ARGUMENT, error_parts

REFUSAL = "Unsupported query syntax near ']'"
LISTING = "0x401000 Unsupported query syntax near ']' is a string the sample holds\nand more"


class _Args(BaseModel):
    query: str = ""


def _tool(name: str, reply: Any) -> StructuredTool:
    async def _run(**_kwargs: Any) -> Any:
        return reply

    return StructuredTool.from_function(
        func=None, coroutine=_run, name=name, description="d", args_schema=_Args, infer_schema=False
    )


def _invented(patterns: list[dict[str, Any]]) -> MCPServerConfig:
    return MCPServerConfig.model_validate(
        {"command": "invented-search", "error_patterns": patterns, "tool_facts": {}}
    )


def _call(tool: Any) -> Any:
    return asyncio.run(tool.coroutine(query="x"))


PATTERN = {
    "match": r"Unsupported query syntax\b.*",
    "code": BAD_ARGUMENT,
    "remediation": "simplify",
}


def test_an_invented_servers_plain_text_error_is_filed_as_a_failure() -> None:
    handle = ServerHandle("invented", _invented([PATTERN]))
    handle._all_tools = [_tool("search", REFUSAL)]
    (tool,) = handle.tools()
    parts = error_parts(_call(tool))
    assert parts == (BAD_ARGUMENT, REFUSAL, "simplify")


def test_an_answer_the_patterns_do_not_hold_whole_is_kept_as_it_is() -> None:
    handle = ServerHandle("invented", _invented([PATTERN]))
    handle._all_tools = [_tool("search", LISTING)]
    (tool,) = handle.tools()
    assert _call(tool) == LISTING


def test_a_server_that_declares_no_pattern_keeps_its_tools() -> None:
    original = _tool("search", REFUSAL)
    handle = ServerHandle("plain", _invented([]))
    handle._all_tools = [original]
    assert handle.tools() == [original]
    assert handle.tools()[0] is original


def test_an_adapter_that_reads_its_own_errors_is_not_read_twice() -> None:
    original = _tool("search", REFUSAL)
    handle = ServerHandle("own", _invented([PATTERN]))
    handle.reads_own_errors = True
    handle._all_tools = [original]
    assert handle.tools()[0] is original


def test_a_pattern_scoped_to_one_tool_reads_only_that_tool() -> None:
    patterns = [ErrorPattern.model_validate({**PATTERN, "tools": ["search"]})]
    assert declared_failure(patterns, "search", REFUSAL) is not None
    assert declared_failure(patterns, "lookup", REFUSAL) is None


def test_a_remediation_names_the_path_the_server_can_open() -> None:
    pattern = ErrorPattern.model_validate(
        {
            "match": r"No file is open\..*",
            "remediation": "open the sample first",
            "remediation_with_path": "open {sample_path} first",
        }
    )
    tools = with_declared_errors([_tool("read", "No file is open.")], [pattern], lambda: "/m/s.exe")
    parts = error_parts(_call(tools[0]))
    assert parts is not None and parts[2] == "open /m/s.exe first"


def test_a_protocol_error_is_held_by_its_message() -> None:
    pattern = ErrorPattern.model_validate(
        {
            "match": r"(?:\w+: )?Open a file first\b.*",
            "applies_to": ["protocol_error"],
            "remediation": "open",
        }
    )
    marker = json.dumps(
        {"tool_error": "exception", "type": "McpError", "detail": "Open a file first please"}
    )
    found = declared_error([pattern], "any", marker)
    assert found is not None and found[2] == "protocol_error"
    assert declared_error([pattern], "any", "Open a file first please") is None


def test_radare2_reads_its_errors_by_the_same_function() -> None:
    from maljan.providers.static import r2

    for reply in (
        "Invalid regex used in filter parameter, try a simpler expression",
        "No file is currently open.",
        "<log>\n[ERROR] Cannot open file\n</log>",
        "a listing that is no error",
    ):
        mine = r2.r2_error_reply("list_strings", reply)
        held = declared_error(r2._R2_PATTERNS, "list_strings", reply)
        assert (mine is None) == (held is None), reply
        if mine is not None and held is not None:
            assert mine["error"]["message"] == held[1]
            assert mine["error"]["code"] == held[0].code


def test_the_reading_is_linear_on_a_hostile_answer() -> None:
    patterns = [ErrorPattern.model_validate(PATTERN)]

    def timed(n: int) -> float:
        text = "Unsupported query syntax " + "near ']' " * n + "\n" * (n // 10)
        start = time.perf_counter()
        for _ in range(5):
            declared_error(patterns, "search", text)
            declared_error(patterns, "search", text.replace("\n", " "))
        return time.perf_counter() - start

    small, large = timed(20_000), timed(200_000)
    assert large < max(small, 1e-3) * 40


def test_a_declared_open_tool_reads_its_errors_too() -> None:
    from maljan.core.config import SampleOpenConfig
    from maljan.providers.sample_open import SampleNotes

    spec = SampleOpenConfig(open_tool="search", path_argument="query")
    config = _invented([{"match": r"Failed to open .*", "code": "tool_failed"}])
    config = config.model_copy(update={"sample_open": spec})
    handle = ServerHandle("invented", config)
    handle._all_tools = [_tool("search", "Failed to open /s/a.bin")]
    handle.sample_notes = SampleNotes()
    (tool,) = handle.tools()
    said = asyncio.run(tool.ainvoke({"query": "/s/a.bin"}))
    parts = error_parts(said)
    assert parts is not None and parts[0] == "tool_failed"
    assert handle.sample_notes.get(handle.note_key, "/s/a.bin") is None
