"""Freeze the tool manifests of the built-in MCP sidecars as golden fixtures.

Re-run whenever a sidecar's tool set changes on purpose:

    uv run python scripts/goldens/capture_builtin_tool_sets.py

It speaks raw stdio MCP to each server with exactly the launch parameters
``_builtin_servers()`` uses and writes what it is offered. The two older
sidecars are pinned by name alone: their fixtures were captured before the
servers moved into ``mcp.servers``, and the claim that the move was
behaviour-free rests on those names not shifting. The two tool sidecars are
pinned by name *and* argument names, because their arguments are the contract
an agent calls them by — an argument silently renamed is a tool that stops
working with no test to say so.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from maljan.agents.subprocess_env import child_env

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

# key -> (directory holding server.py and used as cwd, env names passed through)
SIDECARS: dict[str, tuple[str, tuple[str, ...]]] = {
    "analysis": ("services/analysis-mcp", ("MALJAN_STAGING_DIR",)),
    "knowledge": ("services/knowledge-mcp", ()),
    "network": ("services/network-mcp", ()),
    "threatintel": ("services/threatintel-mcp", ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")),
}

# The sidecars whose fixture carries argument names as well as tool names.
WITH_ARGUMENTS: frozenset[str] = frozenset({"analysis", "knowledge"})


async def enumerate_stdio_manifest(
    command: str, args: list[str], cwd: str, env: dict[str, str]
) -> dict[str, list[str]]:
    """``{tool name: sorted argument names}``, over one initialize + tools/list."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        response = await session.list_tools()
        return {
            tool.name: sorted((tool.inputSchema or {}).get("properties") or {})
            for tool in response.tools
        }


async def enumerate_stdio_tools(
    command: str, args: list[str], cwd: str, env: dict[str, str]
) -> list[str]:
    """Just the tool names, for the two sidecars pinned by name alone."""
    manifest = await enumerate_stdio_manifest(command, args, cwd, env)
    return list(manifest)


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for key, (subdir, allow) in SIDECARS.items():
        manifest = asyncio.run(
            enumerate_stdio_manifest(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            )
        )
        payload: dict[str, object] = {
            "server": key,
            "source": "live handshake",
            "tools": sorted(manifest),
        }
        if key in WITH_ARGUMENTS:
            payload["arguments"] = {name: manifest[name] for name in sorted(manifest)}
        dest = GOLDEN / f"{key}.json"
        dest.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"{key}: {len(manifest)} tools -> {dest}")


if __name__ == "__main__":
    main()
