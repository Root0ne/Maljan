"""Freeze the tool names of the two built-in MCP sidecars as golden fixtures.

Run once, on the branch point, before the sidecars move into ``mcp.servers``:

    uv run python scripts/capture_builtin_tool_sets.py

It speaks raw stdio MCP to each server with exactly the launch parameters the
agents use today (``network_analyst.py:73-111``, ``judge_agent.py:131-158``)
and writes the tool names it is offered. Committed so a reviewer can re-run it
on ``dev`` and diff the result: the whole claim that moving the sidecars into
settings is behaviour-free rests on these names.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from maljan.agents.subprocess_env import child_env

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

# key -> (directory holding server.py and used as cwd, env names passed through)
SIDECARS: dict[str, tuple[str, tuple[str, ...]]] = {
    "network": ("network-mcp", ()),
    "threatintel": ("threatintel-mcp", ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")),
}


async def enumerate_stdio_tools(
    command: str, args: list[str], cwd: str, env: dict[str, str]
) -> list[str]:
    """Tool names a stdio MCP server offers, over one initialize + tools/list."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        response = await session.list_tools()
        return [tool.name for tool in response.tools]


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for key, (subdir, allow) in SIDECARS.items():
        names = asyncio.run(
            enumerate_stdio_tools(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            )
        )
        dest = GOLDEN / f"{key}.json"
        dest.write_text(
            json.dumps(
                {"server": key, "source": "live handshake", "tools": sorted(names)},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"{key}: {len(names)} tools -> {dest}")


if __name__ == "__main__":
    main()
