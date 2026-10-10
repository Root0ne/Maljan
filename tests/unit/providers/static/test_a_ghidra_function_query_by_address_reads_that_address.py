"""A Ghidra query for a function by address reads that address, and an empty answer names it.

The Ghidra tools that take a function by name or by address (callers, callees,
cross-references, jump targets, the call graph, variables) are sent only the
arguments a call set: a call with an address and no name queries the address,
one with a name queries the name. Ghidra's one-line answers name the function
by the name argument, which it holds as nothing for a call made by address:
"No callees found for function: null". Such an answer ends with the address the
call gave.

The empty answer itself came from a program that was never analysed: every
``load_program`` imports the file afresh, in the place of any analysed program
of its name, and an import holds no call or code reference. So a job loads and
analyses its sample once: the first load of the held path is followed by the
switch and Ghidra's auto-analysis and noted, and every later load of it in the
job is a switch to the noted program, answered with the load's own answer.

No Ghidra runs here: the tool schemas are the recorded definitions
(``tests/fixtures/tools/reverser_ghidra_tool_definitions.json``) in the shape
``/mcp/schema`` serves them, and each answer is a recorded one.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx

from maljan.agents.ghidra_http_client import (
    FUNCTION_NAME_ARGUMENTS,
    GhidraHTTPClient,
    function_named_by_address,
)
from maljan.analysis.ghidra_program import ANALYSIS_PATH, SWITCH_PATH

ADDRESS = "0x1360bc02200"
DEFINITIONS = (
    Path(__file__).parents[3] / "fixtures" / "tools" / "reverser_ghidra_tool_definitions.json"
)


def _by_name_or_address() -> dict[str, list[str]]:
    """The recorded tools that take a function by name or by address, with their arguments."""
    out: dict[str, list[str]] = {}
    for tool in json.loads(DEFINITIONS.read_text(encoding="utf-8")):
        properties = list((tool.get("input_schema") or {}).get("properties") or {})
        if "address" in properties and any(n in properties for n in FUNCTION_NAME_ARGUMENTS):
            required = (tool.get("input_schema") or {}).get("required") or []
            if not any(n in required for n in ("address", *FUNCTION_NAME_ARGUMENTS)):
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


def _client(answers: dict[str, str]) -> tuple[GhidraHTTPClient, _Ghidra]:
    ghidra = _Ghidra(answers)
    client = GhidraHTTPClient(base_url="http://ghidra.invalid")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(ghidra.handler))
    return client, ghidra


def _ask(client: GhidraHTTPClient, tool: str, arguments: list[str], call: dict[str, Any]) -> str:
    built = client._create_langchain_tool(_schema_entry(tool, arguments))
    return str(asyncio.run(built.ainvoke(call)))


class TestTheCallSendsWhatItWasGiven:
    def test_the_recorded_definitions_hold_the_tools_this_covers(self) -> None:
        tools = _by_name_or_address()
        for name in ("get_function_callees", "get_function_callers", "get_function_xrefs"):
            assert name in tools
        assert len(tools) >= 5

    def test_an_address_alone_queries_the_address(self) -> None:
        arguments = _by_name_or_address()["get_function_callees"]
        client, ghidra = _client({"/get_function_callees": "FUN_a @ 1360bc0ae78"})
        _ask(client, "get_function_callees", arguments, {"address": ADDRESS})
        (request,) = ghidra.requests
        assert dict(request.url.params) == {"address": ADDRESS}

    def test_a_name_alone_queries_the_name(self) -> None:
        arguments = _by_name_or_address()["get_function_callers"]
        client, ghidra = _client({"/get_function_callers": "FUN_b @ 1360bc03cf4"})
        _ask(client, "get_function_callers", arguments, {"name": "FUN_1360bc02118"})
        (request,) = ghidra.requests
        assert dict(request.url.params) == {"name": "FUN_1360bc02118"}


class TestTheEmptyAnswerNamesTheAddress:
    def test_no_callees_names_the_address_asked(self) -> None:
        arguments = _by_name_or_address()["get_function_callees"]
        client, _ = _client({"/get_function_callees": "No callees found for function: null"})
        said = _ask(client, "get_function_callees", arguments, {"address": ADDRESS})
        assert said == f"No callees found for function at {ADDRESS}"

    def test_a_function_ghidra_cannot_resolve_says_so_with_the_address(self) -> None:
        arguments = _by_name_or_address()["get_function_callers"]
        client, _ = _client({"/get_function_callers": "Function not found: null"})
        said = _ask(client, "get_function_callers", arguments, {"address": ADDRESS})
        assert said == f"Function not found at {ADDRESS}"

    def test_every_tool_by_name_or_address_is_read_the_same_way(self) -> None:
        for tool, arguments in _by_name_or_address().items():
            client, _ = _client({f"/{tool}": "Function not found: null"})
            said = _ask(client, tool, arguments, {"address": ADDRESS})
            assert said == f"Function not found at {ADDRESS}", tool

    def test_no_references_says_both_things_ghidra_means_by_it(self) -> None:
        """Ghidra answers this for an address no function stands at as well."""
        arguments = _by_name_or_address()["get_function_xrefs"]
        client, _ = _client({"/get_function_xrefs": "No references found to function: null"})
        said = _ask(client, "get_function_xrefs", arguments, {"address": ADDRESS})
        assert said == f"No function at {ADDRESS}, or no references to the one there"

    def test_an_answer_to_a_call_by_name_is_kept_as_it_came(self) -> None:
        arguments = _by_name_or_address()["get_function_callees"]
        client, _ = _client({"/get_function_callees": "No callees found for function: FUN_x"})
        said = _ask(client, "get_function_callees", arguments, {"name": "FUN_x"})
        assert said == "No callees found for function: FUN_x"

    def test_a_list_of_callees_is_kept_as_it_came(self) -> None:
        listed = "FUN_1360bc06aa4 @ 1360bc06aa4\nFUN_1360bc0bc1c @ 1360bc0bc1c"
        assert function_named_by_address(listed, ["name", "address"], {"address": ADDRESS}) == (
            listed
        )

    def test_a_tool_that_takes_no_name_is_left_alone(self) -> None:
        said = "No references found to address: null"
        assert function_named_by_address(said, ["address"], {"address": ADDRESS}) == said

    def test_a_long_answer_is_read_in_linear_time(self) -> None:
        def seconds(n: int) -> float:
            text = "x" * n + ": null"
            began = time.perf_counter()
            for _ in range(5):
                function_named_by_address(text, ["name", "address"], {"address": ADDRESS})
            return time.perf_counter() - began

        seconds(100_000)
        low, high = seconds(1_000_000), seconds(10_000_000)
        assert high < low * 20 + 0.05


HELD = "/data/samples/.work/s.exe"
LOAD_SCHEMA = {
    "path": "/load_program",
    "method": "POST",
    "params": [{"name": "file", "type": "string", "required": True, "source": "body"}],
}


def _provider(client: GhidraHTTPClient) -> Any:
    from pydantic import SecretStr

    from maljan.providers.static.ghidra import GhidraStaticProvider

    class _G:
        enabled = True
        transport = "http"
        url = "http://ghidra.invalid"
        auth_token = SecretStr("")

    provider = GhidraStaticProvider(_G(), None, None)  # type: ignore[arg-type]
    provider._toolkit = client
    provider.pin_sample(HELD)
    return provider


class TestAJobLoadsAndAnalysesItsSampleOnce:
    LOADED = json.dumps({"success": True, "program": "s.exe"})
    SWITCHED = json.dumps({"success": True, "switched_to": "s.exe"})
    ANALYSED = json.dumps({"success": True, "total_functions": 150, "program": "s.exe"})

    def _answers(self, **over: str) -> dict[str, str]:
        answers = {
            "/load_program": self.LOADED,
            SWITCH_PATH: self.SWITCHED,
            ANALYSIS_PATH: self.ANALYSED,
        }
        answers.update({f"/{k}": v for k, v in over.items()})
        return answers

    def _loads(self, answers: dict[str, str], times: int) -> tuple[list[str], _Ghidra, Any]:
        client, ghidra = _client(answers)
        provider = _provider(client)
        (load,) = [
            t for t in provider._pin_load_program_path([client._create_langchain_tool(LOAD_SCHEMA)])
        ]

        async def go() -> list[str]:
            return [str(await load.ainvoke({"file": "/invented.exe"})) for _ in range(times)]

        return asyncio.run(go()), ghidra, provider

    def test_the_first_load_is_switched_to_and_analysed_and_noted(self) -> None:
        (said,), ghidra, provider = self._loads(self._answers(), 1)
        assert [r.url.path for r in ghidra.requests] == [
            "/load_program",
            SWITCH_PATH,
            ANALYSIS_PATH,
        ]
        analysis = ghidra.requests[2]
        assert dict(analysis.url.params) == {"program": "s.exe"}
        assert json.loads(analysis.content) == {"program": "s.exe"}
        assert json.loads(ghidra.requests[0].content) == {"file": HELD}
        assert said == self.LOADED
        assert provider.programs.get(HELD).name == "s.exe"

    def test_every_later_load_is_a_switch_answered_with_the_load_s_answer(self) -> None:
        said, ghidra, _provider_ = self._loads(self._answers(), 5)
        assert [r.url.path for r in ghidra.requests] == [
            "/load_program",
            SWITCH_PATH,
            ANALYSIS_PATH,
            *[SWITCH_PATH] * 4,
        ]
        assert said == [self.LOADED] * 5

    def test_a_switch_ghidra_refuses_loads_and_analyses_afresh(self) -> None:
        client, ghidra = _client(self._answers())
        provider = _provider(client)
        provider.programs.note(HELD, "s.exe", self.LOADED)
        ghidra.answers[SWITCH_PATH] = '{"error": "Program not found: s.exe"}'
        (load,) = provider._pin_load_program_path([client._create_langchain_tool(LOAD_SCHEMA)])
        asyncio.run(load.ainvoke({"file": HELD}))
        assert [r.url.path for r in ghidra.requests] == [
            SWITCH_PATH,
            "/load_program",
            SWITCH_PATH,
            ANALYSIS_PATH,
        ]

    def test_an_analysis_ghidra_did_not_confirm_is_not_noted(self) -> None:
        said, ghidra, provider = self._loads(
            self._answers(run_analysis='{"error": "Analysis failed: x"}'), 2
        )
        assert said == [self.LOADED] * 2
        assert [r.url.path for r in ghidra.requests].count("/load_program") == 2
        assert provider.programs.get(HELD) is None

    def test_a_failed_load_is_not_analysed(self) -> None:
        from maljan.core.exceptions import SampleNotOpened

        client, ghidra = _client({"/load_program": '{"error": "File not found: /x/s.exe"}'})
        provider = _provider(client)
        (load,) = provider._pin_load_program_path([client._create_langchain_tool(LOAD_SCHEMA)])
        try:
            asyncio.run(load.ainvoke({"file": HELD}))
        except SampleNotOpened:
            pass
        assert [r.url.path for r in ghidra.requests] == ["/load_program"]

    def test_the_client_alone_loads_and_switches_without_analysing(self) -> None:
        client, ghidra = _client(self._answers())
        asyncio.run(
            client._call_endpoint(
                "/load_program", "POST", [{"name": "file", "source": "body"}], {"file": HELD}
            )
        )
        assert [r.url.path for r in ghidra.requests] == ["/load_program", SWITCH_PATH]

    def test_the_triage_pass_s_analysed_program_is_noted_for_the_agents(self) -> None:
        from maljan.analysis.ghidra_passes import GhidraPasses
        from maljan.analysis.ghidra_program import JobPrograms
        from tests.unit.fake_ghidra import FakeGhidra

        fake = FakeGhidra()
        programs = JobPrograms()
        passes = GhidraPasses(
            base_url="http://ghidra.invalid",
            sample_path=HELD,
            transport=httpx.MockTransport(fake.handler),
            programs=programs,
        )
        passes.open()
        noted = programs.get(HELD)
        assert noted is not None and noted.name == "s.exe"
        assert json.loads(noted.answer) == {"success": True, "program": "s.exe"}
