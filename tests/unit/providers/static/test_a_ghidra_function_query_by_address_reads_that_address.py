"""A Ghidra query for a function by address reads that address.

The Ghidra tools that take a function by name or by address (callers, callees,
cross-references, jump targets, the call graph, variables) are sent only the
arguments a call set: a call with an address and no name queries the address,
one with a name queries the name. Ghidra's own answer is handed on as it came;
the ledger entry beside it holds the arguments the call sent, address included.

No Ghidra runs here: the tool schemas are the recorded definitions
(``tests/fixtures/tools/reverser_ghidra_tool_definitions.json``) in the shape
``/mcp/schema`` serves them, and each answer is a recorded one.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from maljan.agents.ghidra_http_client import GhidraHTTPClient

ADDRESS = "0x1360bc02200"
NAME_ARGUMENTS = ("name", "function_name")
DEFINITIONS = (
    Path(__file__).parents[3] / "fixtures" / "tools" / "reverser_ghidra_tool_definitions.json"
)


def _by_name_or_address() -> dict[str, list[str]]:
    """The recorded tools that take a function by name or by address, with their arguments."""
    out: dict[str, list[str]] = {}
    for tool in json.loads(DEFINITIONS.read_text(encoding="utf-8")):
        properties = list((tool.get("input_schema") or {}).get("properties") or {})
        if "address" in properties and any(n in properties for n in NAME_ARGUMENTS):
            required = (tool.get("input_schema") or {}).get("required") or []
            if not any(n in required for n in ("address", *NAME_ARGUMENTS)):
                out[tool["name"]] = properties
    return out


def _schema_entry(tool: str, arguments: list[str]) -> dict[str, Any]:
    return {
        "path": f"/{tool}",
        "method": "GET",
        "description": f"recorded {tool}",
        "params": [{"name": a, "type": "string", "source": "query"} for a in arguments],
    }


class _Ghidra:
    """Answers each path with a recorded answer and records every request."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text=self.answers.get(request.url.path, "{}"))


def _ask(tool: str, call: dict[str, Any], answer: str) -> tuple[str, _Ghidra]:
    ghidra = _Ghidra({f"/{tool}": answer})
    client = GhidraHTTPClient(base_url="http://ghidra.invalid")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(ghidra.handler))
    built = client._create_langchain_tool(_schema_entry(tool, _by_name_or_address()[tool]))
    return str(asyncio.run(built.ainvoke(call))), ghidra


class TestTheCallSendsWhatItWasGiven:
    def test_the_recorded_definitions_hold_the_tools_this_covers(self) -> None:
        tools = _by_name_or_address()
        for name in ("get_function_callees", "get_function_callers", "get_function_xrefs"):
            assert name in tools
        assert len(tools) >= 5

    def test_an_address_alone_queries_the_address(self) -> None:
        for tool in _by_name_or_address():
            _said, ghidra = _ask(tool, {"address": ADDRESS}, "x")
            (request,) = ghidra.requests
            assert dict(request.url.params) == {"address": ADDRESS}, tool

    def test_a_name_alone_queries_the_name(self) -> None:
        _said, ghidra = _ask("get_function_callers", {"name": "FUN_1360bc02118"}, "x")
        (request,) = ghidra.requests
        assert dict(request.url.params) == {"name": "FUN_1360bc02118"}

    def test_ghidra_s_answer_is_handed_on_as_it_came(self) -> None:
        said, _ = _ask(
            "get_function_callees", {"address": ADDRESS}, "No callees found for function: null"
        )
        assert said == "No callees found for function: null"
