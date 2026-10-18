"""Every Maljan sidecar's standard output carries JSON-RPC and nothing else.

A stdio MCP client parses each stdout line as JSON-RPC and logs a traceback for
one that is not; a ``maljan`` log line written to stdout cost 12 to 60 of them
per validation run. Each entrypoint routes logging to standard error before any
import that can log. The sidecar runs as a subprocess, the way a client starts
it, through the initialize handshake and one tool call.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]

# One tool call per sidecar. The knowledge call loads a cached ATT&CK bundle
# (it logs at INFO; the cache is a one-technique fixture in a temporary
# directory, never the user's); the others import the tool layer and answer a manifest.
CALLS: dict[str, tuple[str, dict[str, Any]]] = {
    "knowledge-mcp": ("resolve_technique", {"text": "process injection into explorer"}),
    "analysis-mcp": ("capabilities", {}),
    "network-mcp": ("capabilities", {}),
    "threatintel-mcp": ("capabilities", {}),
}


def _cache(directory: Path) -> dict[str, str]:
    """An environment whose ATT&CK cache holds a one-technique bundle per domain."""
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "Process Injection",
                "description": "Injects code into another process.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
                ],
                "x_mitre_platforms": ["Windows"],
            }
        ],
    }
    for domain in ("enterprise", "mobile", "ics"):
        (directory / f"{domain}-attack.json").write_text(json.dumps(bundle), encoding="utf-8")
    return {**os.environ, "MALJAN_ATTCK_CACHE": str(directory), "MALJAN_ATTCK_REFRESH_DAYS": "0"}


def _exchange(
    server: str, tool: str, arguments: dict[str, Any], env: dict[str, str] | None = None
) -> tuple[str, str]:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "guard", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    ]
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "services" / server / "server.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    timer = threading.Timer(240, proc.kill)
    timer.start()
    stdout_lines: list[str] = []
    try:
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in messages))
        proc.stdin.flush()
        # Keep the pipe open until the tool call is answered: closing it ends
        # the server, and a call still running would be cut off.
        for line in proc.stdout:
            stdout_lines.append(line)
            if line.strip() and json.loads(line).get("id") == 2:
                break
        proc.stdin.close()
        rest = proc.stdout.read()
        stdout_lines.extend(rest.splitlines(keepends=True))
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait(timeout=30)
    finally:
        timer.cancel()
        proc.kill()
    return "".join(stdout_lines), stderr


@pytest.mark.parametrize("server", sorted(CALLS))
def test_every_stdout_line_is_json_rpc(server: str, tmp_path: Path) -> None:
    stdout, stderr = _exchange(server, *CALLS[server], env=_cache(tmp_path))
    lines = [line for line in stdout.splitlines() if line.strip()]
    assert lines, stderr[-2000:]
    parsed = [json.loads(line) for line in lines]
    assert all(message.get("jsonrpc") == "2.0" for message in parsed), lines
    assert {m["id"] for m in parsed if "id" in m} >= {1, 2}


def test_the_knowledge_sidecar_logs_to_stderr(tmp_path: Path) -> None:
    stdout, stderr = _exchange("knowledge-mcp", *CALLS["knowledge-mcp"], env=_cache(tmp_path))
    assert "ATT&CK bundle" in stderr
    assert "ATT&CK bundle" not in stdout


def test_routing_is_one_handler_and_leaves_the_text_alone() -> None:
    code = (
        "import logging\n"
        "from maljan.core.stdio_safe import route_logging_to_stderr\n"
        "route_logging_to_stderr()\n"
        "from maljan.core.logger import logger\n"
        "logger.info('hello %s', 'x')\n"
        "print(len(logger.handlers), len(logging.getLogger().handlers))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=False
    )
    assert done.stdout.split() == ["0", "1"], done.stderr
    assert done.stderr.count("hello x") == 1
    assert " - maljan - INFO - hello x" in done.stderr
