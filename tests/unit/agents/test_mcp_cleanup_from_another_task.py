"""A stdio MCP server closed from another task than the one that opened it is gone.

A registry closes a toolkit in a task of its own on the loop that opened it,
so anyio refuses to exit the transport's cancel scope from there ("Attempted to
exit cancel scope in a different task than it was entered in"). That refusal
is task-group bookkeeping: the stack's exits still run, the stdio transport
still closes the server's stdin, waits, and terminates a server that does not
exit, and nothing is left running. These open a stub stdio server, close it
from a different task, and look for its process; the log line says the same.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from mcp import StdioServerParameters

from maljan.agents import mcp_client
from maljan.agents.mcp_client import MCPLangChainToolkit

SERVER = """
import os, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
from mcp.server.fastmcp import FastMCP
app = FastMCP("stub")

@app.tool()
def ping() -> str:
    return "pong"

app.run()
if len(sys.argv) > 2:
    # A server that does not exit when its stdin closes.
    time.sleep(60)
"""


def _running(pid: int) -> bool:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("State:"):
                return "Z" not in line.split()[1]
    except FileNotFoundError:
        return False
    return False


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="reads the process table under /proc")
@pytest.mark.parametrize("stubborn", [False, True], ids=["exits_on_eof", "ignores_eof"])
def test_the_server_process_is_gone_after_a_close_from_another_task(
    tmp_path: Path, stubborn: bool
) -> None:
    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    pidfile = tmp_path / "pid"
    args = [str(script), str(pidfile), *(["stubborn"] if stubborn else [])]
    toolkit = MCPLangChainToolkit(StdioServerParameters(command=sys.executable, args=args))
    log = MagicMock()

    async def _run() -> tuple[int, bool, list[str]]:
        await asyncio.create_task(toolkit.initialize())
        pid = int(pidfile.read_text())
        before = _running(pid)
        with patch.object(mcp_client, "logger", log):
            await asyncio.create_task(toolkit.cleanup())
        left = [
            t.get_coro().__qualname__
            for t in asyncio.all_tasks()
            if t is not asyncio.current_task()
        ]
        return pid, before, left

    pid, before, left = asyncio.run(_run())
    try:
        assert [tool.name for tool in toolkit.get_tools()] == ["ping"]
        assert before is True
        assert _running(pid) is False
        assert left == []
        said = [call.args[0] % call.args[1:] for call in log.info.call_args_list]
        assert any(
            line.startswith(
                "MCP connection closed from a different task than the one that opened it; "
                "anyio reported 'Attempted to exit cancel scope in a different task"
            )
            and line.endswith("the transport's own shutdown still ran, so nothing is left open.")
            for line in said
        ), said
        log.warning.assert_not_called()
    finally:
        if _running(pid):
            os.kill(pid, 9)
