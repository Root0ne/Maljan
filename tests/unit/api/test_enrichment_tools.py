"""A server source is asked through the server's own handle, only where it declares reputation."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from app.services.enrichment_tools import ServerToolCaller
from maljan.core.config import MCPServerConfig


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[dict[str, Any]] = []

    async def ainvoke(self, args: dict[str, Any]) -> str:
        self.calls.append(args)
        return '{"score": 70}'


class _Handle:
    made: list[_Handle] = []

    def __init__(self, name: str, config: Any) -> None:
        self.name, self.config = name, config
        self.tool = _Tool("lookup_address")
        self.opened: list[str] = []
        self.closed = False
        _Handle.made.append(self)

    async def aopen(self, job_id: str) -> None:
        self.opened.append(job_id)

    def tools(self) -> list[_Tool]:
        return [self.tool]

    async def aclose(self) -> None:
        self.closed = True


def _settings(**servers: MCPServerConfig) -> Any:
    return SimpleNamespace(mcp=SimpleNamespace(servers=servers))


def _server(**over: Any) -> MCPServerConfig:
    fields: dict[str, Any] = {
        "enabled": True,
        "command": "intel",
        "roles": ["reputation"],
        "tool_facts": {
            "lookup_address": {"kind": "indicator_reputation", "arguments": {"ip": "addr"}}
        },
    }
    fields.update(over)
    return MCPServerConfig.model_validate(fields)


@pytest.mark.asyncio
async def test_it_attaches_once_calls_the_named_tool_and_closes() -> None:
    _Handle.made = []
    caller = ServerToolCaller(_settings(intelsrv=_server()), job_key="enrich-1")
    assert caller.arguments("intelsrv", "lookup_address") == {"ip": "addr"}
    with patch("maljan.providers.servers.ServerHandle", _Handle):
        first = await caller("intelsrv", "lookup_address", {"addr": "8.8.4.4"})
        await caller("intelsrv", "lookup_address", {"addr": "8.8.8.8"})
        missing = await caller("intelsrv", "nothing_here", {})
        await caller.aclose()
    (handle,) = _Handle.made
    assert handle.opened == ["enrich-1"]
    assert handle.tool.calls == [{"addr": "8.8.4.4"}, {"addr": "8.8.8.8"}]
    assert first == '{"score": 70}' and missing is None
    assert handle.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("over", [{"roles": ["decompiler"]}, {"enabled": False}])
async def test_a_server_that_is_off_or_not_a_reputation_server_is_not_asked(
    over: dict[str, Any],
) -> None:
    _Handle.made = []
    caller = ServerToolCaller(_settings(intelsrv=_server(**over)), job_key="enrich-1")
    with patch("maljan.providers.servers.ServerHandle", _Handle):
        assert await caller("intelsrv", "lookup_address", {"addr": "8.8.4.4"}) is None
        assert await caller("absent", "lookup_address", {}) is None
    assert _Handle.made == []
