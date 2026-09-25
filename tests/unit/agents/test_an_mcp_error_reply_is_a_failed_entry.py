"""Any MCP tool's error reply is a failed ledger entry.

The client handed a failed call on in a marker built with f-strings: an
``isError`` reply's content written as a Python repr, an exception message
written between quotes it might itself contain. Neither was JSON, so the
ledger's rule for a returned error read no failure and filed the call as ok.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

from mcp.types import CallToolResult, TextContent

from maljan.agents.mcp_client import MCPLangChainToolkit, tool_error_marker
from maljan.schemas.evidence import build_entry


def _entry(output: str) -> Any:
    return build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="network",
        tool="lookup",
        args={},
        server="threatintel",
        output=output,
    )


class _Session:
    def __init__(self, answer: Any) -> None:
        self._answer = answer

    async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


def _call(answer: Any) -> str:
    toolkit = MCPLangChainToolkit(None)
    toolkit.session = _Session(answer)  # type: ignore[assignment]
    return asyncio.run(toolkit._call("lookup", {}, ()))


def test_an_is_error_reply_is_a_failed_entry_with_the_server_s_words() -> None:
    reply = CallToolResult(
        content=[TextContent(type="text", text='quota exceeded for "lookup"')], isError=True
    )

    marker = _call(reply)
    entry = _entry(marker)

    assert json.loads(marker)["detail"] == 'quota exceeded for "lookup"'
    assert entry.ok is False
    assert 'quota exceeded for "lookup"' in str(entry.error)


def test_an_exception_with_a_quote_in_its_message_is_a_failed_entry() -> None:
    entry = _entry(_call(ValueError('bad "quoted" thing')))

    assert entry.ok is False
    assert 'bad "quoted" thing' in str(entry.error)


def test_the_marker_is_json_whatever_it_carries() -> None:
    marker = tool_error_marker("exception", "t", detail='a "b" \\ c\nd')

    assert json.loads(marker) == {"tool_error": "exception", "tool": "t", "detail": 'a "b" \\ c\nd'}


def test_an_answer_is_not_a_failure() -> None:
    reply = SimpleNamespace(content=[TextContent(type="text", text="ok")], isError=False)

    assert _entry(_call(reply)).ok is True
