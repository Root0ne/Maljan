"""An r2mcp error reply is a failed ledger entry, with r2mcp's own words.

r2mcp answers a call it refuses with an ordinary text result — "Invalid regex
used in filter parameter, try a simpler expression" — and the ledger used to
file that as a successful ``list_strings``. The provider reads its replies, and
the ledger's rule for a returned error then marks the entry failed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from pydantic import BaseModel

from maljan.providers.static import r2
from maljan.schemas.evidence import build_entry

REGEX_REFUSAL = "Invalid regex used in filter parameter, try a simpler expression"


class _Args(BaseModel):
    filter: str = ""


def _tool(reply: str) -> Any:
    from langchain_core.tools import StructuredTool

    async def _call(**_kwargs: Any) -> str:
        return reply

    return StructuredTool.from_function(
        func=None,
        coroutine=_call,
        name="list_strings",
        description="List strings",
        args_schema=_Args,
        infer_schema=False,
        metadata={"maljan_server": "r2"},
    )


def _entry(output: str) -> Any:
    return build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="static_r2",
        tool="list_strings",
        args={"filter": "(?i)(a|b"},
        server=None,
        output=output,
    )


def test_an_error_reply_becomes_a_failed_entry_with_r2mcp_s_message() -> None:
    wrapped = r2._reading_error_replies(_tool(REGEX_REFUSAL))

    reply = asyncio.run(wrapped.ainvoke({"filter": "(?i)(a|b"}))
    entry = _entry(reply)

    assert entry.ok is False
    assert entry.error == REGEX_REFUSAL
    assert json.loads(reply)["error"]["code"] == "bad_argument"


def test_an_answer_is_passed_on_exactly_as_r2mcp_gave_it() -> None:
    listing = "UpdaterTag.dll\nKERNEL32.dll\n"
    wrapped = r2._reading_error_replies(_tool(listing))

    reply = asyncio.run(wrapped.ainvoke({"filter": "dll"}))

    assert reply == listing
    assert _entry(reply).ok is True


def test_an_error_sentence_inside_a_listing_is_the_listing_and_not_a_failure() -> None:
    """A string the sample carries can read like anything; only the whole reply counts."""
    listing = f"first string\n{REGEX_REFUSAL}\n"

    assert r2.r2_error_reply("list_strings", listing) is None


def test_the_open_file_refusals_name_the_call_that_would_succeed() -> None:
    failure = r2.r2_error_reply(
        "list_functions",
        "No file is currently open. Call open_file first, then call list_functions again.",
    )

    assert failure is not None
    assert "open_file" in failure["error"]["remediation"]


def test_the_tool_keeps_its_name_schema_and_metadata() -> None:
    wrapped = r2._reading_error_replies(_tool("x"))

    assert wrapped.name == "list_strings"
    assert wrapped.args_schema is _Args
    assert wrapped.metadata == {"maljan_server": "r2"}
