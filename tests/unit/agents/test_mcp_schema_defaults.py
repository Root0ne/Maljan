"""An unset optional argument must reach the server as *unset*, not as ``None``.

Found on the first live call to the CAPE MCP server (2026-08-10). Every one of
the 36 tools declares ``token`` as optional with ``"default": ""``, and every
single call failed the server's own validation::

    1 validation error for call[verify_auth]
    token
      Input should be a valid string [type=string_type, input_value=None, ...]

The toolkit built its argument model with ``... if required else None``, which
discards the schema's declared default and turns "the caller said nothing about
token" into "the caller explicitly passed null". Those are different statements,
and a server that types the field as ``str`` rejects the second one.

Nothing caught this earlier because the Ghidra server — the only MCP server the
pipeline had talked to — declares no optional parameter with a typed default,
so the same wrong argument dict happened to be acceptable. The bug is therefore
in the *client's* schema handling, not in either server, and it is fixed on both
sides of the same idea:

  * a declared default is honoured, so the model documents what the server does;
  * an optional argument left at ``None`` is dropped before the call, so the
    server applies its own default rather than parsing a null.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.agents.mcp_client import MCPLangChainToolkit


class _MCPTool:
    """The shape ``_create_langchain_tool`` consumes — an ``mcp.types.Tool``."""

    def __init__(self, name: str, schema: dict[str, Any], description: str = "d") -> None:
        self.name = name
        self.inputSchema = schema  # noqa: N815 — mirrors the MCP wire field
        self.description = description


class _Result:
    def __init__(self, text: str) -> None:
        self.isError = False
        self.content = [type("C", (), {"text": text})()]


class _Session:
    """Records the argument dict that would go over the wire."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _Result:
        self.calls.append((name, dict(arguments)))
        return _Result("ok")


# The real verify_auth schema, copied from the live server.
VERIFY_AUTH = {
    "additionalProperties": False,
    "properties": {"token": {"default": "", "type": "string"}},
    "type": "object",
}

# The real list_tasks schema: three optional params, three different types.
LIST_TASKS = {
    "additionalProperties": False,
    "properties": {
        "limit": {"default": 10, "type": "integer"},
        "offset": {"default": 0, "type": "integer"},
        "status": {"default": "", "type": "string"},
        "token": {"default": "", "type": "string"},
    },
    "type": "object",
}

# An optional parameter with no declared default — the case where the client has
# nothing to fall back on and must simply not mention the argument.
NO_DEFAULT = {
    "properties": {"hash_value": {"type": "string"}, "note": {"type": "string"}},
    "required": ["hash_value"],
    "type": "object",
}


def _toolkit() -> tuple[MCPLangChainToolkit, _Session]:
    tk = MCPLangChainToolkit(transport="streamable-http", http_url="http://x/mcp")
    session = _Session()
    tk.session = session  # type: ignore[assignment]
    return tk, session


class TestUnsetOptionalArguments:
    def test_a_null_is_never_sent_for_an_omitted_argument(self) -> None:
        """The exact failure the live server reported."""
        tk, session = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("verify_auth", VERIFY_AUTH))
        asyncio.run(tool.arun({}))
        _, args = session.calls[0]
        assert None not in args.values(), f"a null reached the wire: {args}"

    def test_a_declared_default_is_honoured_rather_than_discarded(self) -> None:
        tk, _ = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("list_tasks", LIST_TASKS))
        fields = tool.args_schema.model_fields
        assert fields["limit"].default == 10
        assert fields["offset"].default == 0
        assert fields["status"].default == ""
        assert fields["token"].default == ""

    def test_every_optional_type_survives_the_round_trip(self) -> None:
        """int, str and the mixture — the whole list_tasks call as it failed."""
        tk, session = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("list_tasks", LIST_TASKS))
        asyncio.run(tool.arun({"limit": 5}))
        _, args = session.calls[0]
        assert args["limit"] == 5
        assert None not in args.values(), f"a null reached the wire: {args}"

    def test_an_optional_argument_with_no_default_is_omitted_entirely(self) -> None:
        """Nothing to fall back on, so the argument must simply not appear —
        inventing an empty string would be the client asserting a value the
        caller never gave."""
        tk, session = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("search_task", NO_DEFAULT))
        asyncio.run(tool.arun({"hash_value": "abc"}))
        _, args = session.calls[0]
        assert args == {"hash_value": "abc"}

    def test_a_caller_supplied_value_still_wins(self) -> None:
        tk, session = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("verify_auth", VERIFY_AUTH))
        asyncio.run(tool.arun({"token": "real-token"}))
        assert session.calls[0][1] == {"token": "real-token"}

    def test_a_required_argument_is_still_required(self) -> None:
        """The fix must not quietly make required parameters optional."""
        tk, _ = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("search_task", NO_DEFAULT))
        assert tool.args_schema.model_fields["hash_value"].is_required()

    def test_an_explicit_none_from_the_caller_is_also_dropped(self) -> None:
        """A ReAct agent emitting ``{"token": null}`` is the same statement as
        omitting it, and must not be forwarded as a null either."""
        tk, session = _toolkit()
        tool = tk._create_langchain_tool(_MCPTool("verify_auth", VERIFY_AUTH))
        asyncio.run(tool.arun({"token": None}))
        assert session.calls[0][1] == {}
