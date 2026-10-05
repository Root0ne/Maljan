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
    original = _tool("x")
    wrapped = r2._reading_error_replies(original)

    assert wrapped.name == "list_strings"
    assert wrapped.args_schema is _Args
    assert wrapped.metadata == {"maljan_server": "r2"}
    # A copy: stamping the wrapped tool's source must not stamp the original.
    assert wrapped.metadata is not original.metadata


# radare2's own error, as r2mcp handed it back for ``decompile_function`` on an
# address inside no function: a log envelope with nothing beside it.
LOGGED_ERROR = "<log> [ERROR] Cannot find function in 0x00003ce4 </log>"


def test_a_log_envelope_of_an_error_is_a_failed_call_in_radare2_s_words() -> None:
    for reply in (
        LOGGED_ERROR,
        "<log>\n[ERROR] Cannot find function in 0x00003ce4\n</log>\n",
    ):
        wrapped = r2._reading_error_replies(_tool(reply))
        answered = asyncio.run(wrapped.ainvoke({"filter": ""}))
        entry = _entry(answered)

        assert entry.ok is False, reply
        assert entry.error == "[ERROR] Cannot find function in 0x00003ce4"
        assert json.loads(answered)["error"]["code"] == "tool_failed"


def test_a_fatal_or_mixed_failure_envelope_is_a_failed_call() -> None:
    for reply, words in (
        ("<log>\n[FATAL] Cannot open file\n</log>", "[FATAL] Cannot open file"),
        (
            "<log>\n[ERROR] Cannot seek\n[FATAL] Aborting\n</log>",
            "[ERROR] Cannot seek\n[FATAL] Aborting",
        ),
        (
            "<log>\n[WARN] Relocs not applied\n[FATAL] Aborting\n</log>",
            "[WARN] Relocs not applied\n[FATAL] Aborting",
        ),
    ):
        failure = r2.r2_error_reply("decompile_function", reply)
        assert failure is not None, reply
        assert failure["error"]["code"] == "tool_failed"
        assert failure["error"]["message"] == words


def test_an_envelope_of_warnings_alone_or_in_front_of_an_answer_is_no_failure() -> None:
    assert r2.r2_error_reply("list_strings", "<log>\n[WARN] Relocs not applied\n</log>") is None
    assert (
        r2.r2_error_reply(
            "decompile_function",
            "<log>\n[ERROR] Cannot find function in 0x10\n</log>\nint main(void) { return 0; }",
        )
        is None
    )
    # A line that is not a radare2 log line is something the envelope carried
    # beside the error, and the reply is not radare2 refusing.
    assert r2.r2_error_reply("list_strings", "<log>\n[ERROR] x\nplain text\n</log>") is None
