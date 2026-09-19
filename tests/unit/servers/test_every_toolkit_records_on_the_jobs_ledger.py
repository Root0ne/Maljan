"""One ledger per job, and every toolkit of that job writes on it.

A run whose analysts met six shortened answers reported that it shortened
none. The guardrail is the toolkit's and the counters are the container's, and
every attach but the static provider's opened its toolkit with neither the
job's ledger nor the job's tool-output limit — so the counting happened on
``None`` and the cutting happened at the signature's own default.

The first test drives the real wiring end to end: a container resolves an
agent, the agent's tool answers with more than fits, and the run summary is
asked what the run cut. The second is the guard: whatever a caller passes,
every toolkit opened for this job holds this job's ledger.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest

from maljan.agents.composition import resolve_agent
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.container import ServiceContainer


class _McpTool:
    """One entry of an MCP server's manifest, as the toolkit reads it."""

    def __init__(self) -> None:
        self.name = "strings"
        self.description = "List printable runs."
        self.inputSchema = {  # noqa: N815 - the wire name the toolkit reads
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "limit": {"type": "integer", "default": 150},
                "offset": {"type": "integer", "default": 0},
                "pattern": {"type": "string"},
            },
        }


class _Content:
    def __init__(self, text: str) -> None:
        self.text = text


class _Result:
    def __init__(self, text: str) -> None:
        self.isError = False
        self.content = [_Content(text)]


class _Session:
    """A server that answers one large document, on every call."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _Result:
        rows = [{"offset": 100 + i, "enc": "ascii", "text": f"row number {i}"} for i in range(400)]
        return _Result(json.dumps({"read_path": "/staging/sample", "strings": rows}))


@pytest.fixture()
def attached(monkeypatch):
    """Attach every server without a subprocess, keeping the real toolkit."""

    async def _initialize(self: MCPLangChainToolkit) -> None:
        self.session = _Session()  # type: ignore[assignment]
        self._tools = [self._create_langchain_tool(_McpTool())]

    made: list[MCPLangChainToolkit] = []
    real_init = MCPLangChainToolkit.__init__

    def _record(self: MCPLangChainToolkit, *args: Any, **kwargs: Any) -> None:
        real_init(self, *args, **kwargs)
        made.append(self)

    monkeypatch.setattr(MCPLangChainToolkit, "__init__", _record)
    monkeypatch.setattr(MCPLangChainToolkit, "initialize", _initialize)
    monkeypatch.setattr(
        "maljan.providers.servers._run_async",
        lambda coro, label="": asyncio.run(coro),
    )
    return made


def _settings() -> Settings:
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["analysis"] = MCPServerConfig(
        enabled=True, command="mcp", agents=["static", "network"]
    )
    return cfg


def test_a_run_that_shortened_an_answer_says_so_in_its_run_summary(attached):
    container = ServiceContainer(_settings(), mock=True)
    resolved = resolve_agent("network", container, container.job_key())
    tool = next(t for t in resolved.tools if t.name == "strings")

    answer = asyncio.run(tool.ainvoke({"path": "/staging/sample"}))

    assert "shortened" in answer, "the answer itself was shortened"
    summary = (
        RunSummaryBuilder(time.monotonic())
        .set_truncation(container.get_truncation_ledger().snapshot())
        .build()
        .to_dict()
    )
    truncation = summary["truncation"]
    assert truncation["tool_output_calls"] == 1
    assert truncation["tool_output_over_limit"] == 1
    assert truncation["tool_output_shortened"] == 1
    assert truncation["tool_output_chars_dropped"] > 0
    assert truncation["any_bound_hit"] is True


def test_every_toolkit_of_the_job_holds_the_containers_own_ledger(attached):
    container = ServiceContainer(_settings(), mock=True)
    for key in ("static", "network"):
        resolve_agent(key, container, container.job_key())

    assert attached, "the resolution opened at least one toolkit"
    ledger = container.get_truncation_ledger()
    assert all(toolkit._truncation_ledger is ledger for toolkit in attached)
    assert all(
        toolkit._max_output_chars == container.config.preprocessing.max_tool_output_chars
        for toolkit in attached
    )


def test_a_toolkit_asked_for_another_ledger_still_records_on_the_jobs(attached):
    container = ServiceContainer(_settings(), mock=True)
    from maljan.core.truncation_ledger import TruncationLedger

    registry = container.get_server_registry()
    registry.tools_for("network", container.job_key(), truncation_ledger=TruncationLedger())

    assert attached
    assert all(
        toolkit._truncation_ledger is container.get_truncation_ledger() for toolkit in attached
    )
