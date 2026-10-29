"""A tool server is asked about a report's indicators only with the operator's consent, and said.

Post-verdict enrichment sends every public domain and address of a report to
whatever it asks. A tool server is asked only through a source that names it,
or, with ``api.enrichment_reputation_servers`` on (off by default), through
every enabled server whose roles hold reputation; and wherever a server may be
asked, the run's disclosure names it before anything is sent.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.enrichment_sources import (
    REPUTATION_SERVERS_PATH,
    asks_a_server,
    enrichment_reach,
    ready_sources,
    reputation_server_sources,
)
from app.services.settings_catalog_api import API_DEFAULTS, catalog_index
from maljan.core.config import MCPServerConfig

LOOKUP = "-".join(["acme", "intel"])
HOST = ".".join(["intel", "acme-labs", "net"])


def _servers() -> dict[str, MCPServerConfig]:
    return {
        LOOKUP: MCPServerConfig(
            enabled=True,
            transport="streamable-http",
            url=f"https://{HOST}/mcp",
            roles=["reputation"],
            reputation_service={"name": "Acme Intel", "rank": 30},
        ),
        "off": MCPServerConfig(enabled=False, roles=["reputation"], command="x"),
        "tools": MCPServerConfig(enabled=True, command="x"),
    }


async def _no_secret(_key: str) -> str:
    return ""


def test_the_switch_is_off_until_the_operator_turns_it_on() -> None:
    assert API_DEFAULTS[REPUTATION_SERVERS_PATH] is False
    entry = catalog_index()[f"api.{REPUTATION_SERVERS_PATH}"]
    assert (entry.type, entry.group, entry.editable) == ("bool", "enrichment", True)
    # The setting says what leaves the host, and that the disclosure names it.
    assert "leave this host" in entry.description and "disclosure" in entry.description


@pytest.mark.asyncio
async def test_no_server_is_a_source_while_the_switch_is_off() -> None:
    sources = await ready_sources({}, _no_secret, _servers())
    assert not [s for s in sources if s.source.server]
    assert not asks_a_server({})
    rows = await enrichment_reach({}, _no_secret, _servers())
    assert not [row for row in rows if row["server"]]


@pytest.mark.asyncio
async def test_with_the_switch_on_every_enabled_reputation_server_is_a_source() -> None:
    sources = await ready_sources({}, _no_secret, _servers(), reputation_servers=True)
    asked = [s for s in sources if s.source.server]
    assert [(s.key, s.source.server, s.label, s.source.order) for s in asked] == [
        (f"mcp:{LOOKUP}", LOOKUP, "Acme Intel", 30)
    ]
    assert asked[0].configured and asked[0].source.kinds == ["domain", "ip"]
    assert asks_a_server({}, reputation_servers=True)


@pytest.mark.asyncio
async def test_the_disclosure_names_the_server_before_anything_is_asked() -> None:
    rows = await enrichment_reach({}, _no_secret, _servers(), reputation_servers=True)
    named = [row for row in rows if row["server"]]
    assert [(r["source"], r["server"], r["kinds"], r["hosts"]) for r in named] == [
        (f"mcp:{LOOKUP}", LOOKUP, ["domain", "ip"], [HOST])
    ]


def test_a_server_a_source_names_is_asked_only_as_that_source_declares() -> None:
    assert reputation_server_sources(_servers(), named=[LOOKUP]) == {}


@pytest.mark.asyncio
async def test_a_source_turned_off_keeps_its_server_from_being_asked() -> None:
    stored: dict[str, Any] = {"acme": {"kinds": ["ip"], "server": LOOKUP, "enabled": False}}
    sources = await ready_sources(stored, _no_secret, _servers(), reputation_servers=True)
    asked = [s for s in sources if s.source.server and s.configured]
    assert asked == []
