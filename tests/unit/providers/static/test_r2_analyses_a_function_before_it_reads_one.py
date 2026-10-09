"""A function tool at an address radare2 has not analysed: the function is analysed, then read.

radare2 answers ``decompile_function`` / ``disassemble_function`` at an
address its analysis holds no function at with "Cannot find function in
0x…", though another tool decompiled a function there. Where the server offers
``run_command`` the adapter runs ``af`` at that address and calls the tool once
more; where it does not, the failure names the call that analyses it.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel

from maljan.providers.static import r2

NO_FUNCTION = "<log>\n[ERROR] Cannot find function in 0x401a20\n</log>\n"
NO_FUNCTION_AT = "<log>\n[ERROR] Cannot find function at 0x401a20\n</log>\n"
LISTING = "int fcn.00401a20 (int rcx) {\n    return rcx;\n}\n"


class _Address(BaseModel):
    address: str
    cursor: str | None = None
    page_size: int | None = None


class _Command(BaseModel):
    command: str


class _Server:
    """A stubbed r2mcp: functions exist only where ``af`` has run."""

    def __init__(self, *, af_defines: bool = True) -> None:
        self.analysed: set[str] = set()
        self.af_defines = af_defines
        self.commands: list[str] = []
        self.reads: list[dict[str, Any]] = []

    def tools(self, *, run_command: bool = True) -> list[Any]:
        from langchain_core.tools import StructuredTool

        def _reader(name: str, missing: str) -> Any:
            async def _read(**kwargs: Any) -> str:
                self.reads.append({"tool": name, **kwargs})
                return LISTING if "0x401a20" in self.analysed else missing

            return StructuredTool.from_function(
                func=None,
                coroutine=_read,
                name=name,
                description=name,
                args_schema=_Address,
                infer_schema=False,
            )

        async def _run(command: str) -> str:
            self.commands.append(command)
            if self.af_defines and command.startswith("af @ "):
                self.analysed.add(command.removeprefix("af @ "))
            return ""

        tools = [
            _reader("decompile_function", NO_FUNCTION),
            _reader("disassemble_function", NO_FUNCTION_AT),
        ]
        if run_command:
            tools.append(
                StructuredTool.from_function(
                    func=None,
                    coroutine=_run,
                    name="run_command",
                    description="run_command",
                    args_schema=_Command,
                    infer_schema=False,
                )
            )
        return tools


class _Provider(r2.R2StaticProvider):
    """The r2 adapter over the stubbed server's tool list."""

    def __init__(self, tools: list[Any]) -> None:
        self._handle = SimpleNamespace(tools=lambda: tools)

    def _held_path(self) -> str | None:
        return None


def _wrapped(server: _Server, name: str, *, run_command: bool = True) -> Any:
    provider = _Provider(server.tools(run_command=run_command))
    return next(t for t in provider.get_tools() if t.name == name)


def test_the_function_is_analysed_and_the_call_answered() -> None:
    for name in ("decompile_function", "disassemble_function"):
        server = _Server()
        tool = _wrapped(server, name)
        reply = asyncio.run(tool.ainvoke({"address": "0x401a20", "page_size": 200}))
        assert reply == LISTING
        assert server.commands == ["af @ 0x401a20"]
        assert [read["page_size"] for read in server.reads] == [200, 200]


def test_one_retry_and_then_the_failure_says_af_ran() -> None:
    server = _Server(af_defines=False)
    tool = _wrapped(server, "decompile_function")
    reply = json.loads(asyncio.run(tool.ainvoke({"address": "0x401a20"})))
    assert len(server.reads) == 2
    assert reply["error"]["message"] == "[ERROR] Cannot find function in 0x401a20"
    assert "even after `af @ 0x401a20`" in reply["error"]["remediation"]
    assert "`disassemble` with this address" in reply["error"]["remediation"]


def test_without_run_command_the_failure_names_the_call_that_analyses_it() -> None:
    server = _Server()
    tool = _wrapped(server, "decompile_function", run_command=False)
    reply = json.loads(asyncio.run(tool.ainvoke({"address": "0x401a20"})))
    assert len(server.reads) == 1
    assert server.commands == []
    remediation = reply["error"]["remediation"]
    assert "`af @ 0x401a20` runs through `run_command`" in remediation
    assert "Call `analyze` with a level above" in remediation
    assert "report it with the server log" not in remediation


def test_another_tool_s_failure_is_not_analysed() -> None:
    failure = r2.r2_error_reply("list_strings", NO_FUNCTION)
    assert failure is not None
    assert "af @" not in json.dumps(failure)


def test_an_answer_is_not_touched() -> None:
    server = _Server()
    server.analysed.add("0x401a20")
    tool = _wrapped(server, "decompile_function")
    assert asyncio.run(tool.ainvoke({"address": "0x401a20"})) == LISTING
    assert server.commands == []
