"""A section says which tool server it was built from, derived from the index.

The one server the cited entries agree on, else the name their source carries
(a provider-backed tool has no server), else none. A stored report has no
field and is derived on read.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.api.v1.reports import get_full_malware_report
from maljan.reporting.models import EvidenceIndexRow, EvidenceSection
from maljan.reporting.section_servers import index_of, source_server, with_source_servers
from maljan.reporting.section_tabs import section_tabs


def _rows() -> list[dict]:
    return [
        {"id": "ev_1", "server": "alpha", "source": "mcp:alpha"},
        {"id": "ev_2", "server": "alpha", "source": "mcp:alpha"},
        {"id": "ev_3", "server": None, "source": "provider:beta"},
        {"id": "ev_4", "server": None, "source": "sandbox"},
        {"id": "ev_5", "server": "gamma"},
    ]


def _section(key: str, ids: list[str]) -> dict:
    return {"key": key, "title": key, "kind": "text", "evidence_ids": ids, "source": "tool:x"}


def test_one_agreed_server_is_the_sections() -> None:
    assert source_server(_section("a", ["ev_1", "ev_2"]), index_of(_rows())) == "alpha"


def test_a_source_names_the_server_when_the_row_has_none() -> None:
    assert source_server(_section("a", ["ev_3"]), index_of(_rows())) == "beta"


def test_mixed_unindexed_or_unnamed_entries_say_none() -> None:
    index = index_of(_rows())
    assert source_server(_section("a", ["ev_1", "ev_5"]), index) is None
    assert source_server(_section("a", ["ev_1", "ev_9"]), index) is None
    assert source_server(_section("a", ["ev_4"]), index) is None
    assert source_server(_section("a", []), index) is None


def test_a_stored_report_is_derived_on_read_and_left_alone_otherwise() -> None:
    stored = {
        "evidence_index": _rows(),
        "sections": [_section("tool_a", ["ev_1"]), _section("mixed", ["ev_1", "ev_5"])],
    }
    served = with_source_servers(stored)
    assert served["sections"][0]["source_server"] == "alpha"
    assert "source_server" not in served["sections"][1]
    assert "source_server" not in stored["sections"][0]
    nothing = {"evidence_index": [], "sections": [_section("k", ["ev_1"])]}
    assert with_source_servers(nothing) is nothing
    assert with_source_servers(None) is None


def test_the_model_leaves_an_absent_server_out_of_the_dump() -> None:
    plain = EvidenceSection(key="k", title="t").model_dump(mode="json")
    assert "source_server" not in plain
    placed = EvidenceSection(key="k", title="t", source_server="alpha").model_dump(mode="json")
    assert placed["source_server"] == "alpha"
    assert EvidenceIndexRow(id="ev_1", server="alpha").server == "alpha"


def test_a_platform_server_section_follows_its_agents_declared_tab() -> None:
    # A server named like a fixed tab, answering a built-in analyst: the
    # section is the analyst's tab's, never a server's of its own.
    rows = [
        {"id": "ev_1", "server": "network", "source": "mcp:network", "agent_tab": "network"},
        {"id": "ev_2", "server": "network", "source": "mcp:network", "agent_tab": "network"},
    ]
    report = {
        "evidence_index": rows,
        "sections": [
            _section("tool_flows", ["ev_1", "ev_2"]),
            _section("pe_imports", ["ev_1"]),
            _section("tool_mixed", ["ev_1", "ev_3"]),
        ],
    }
    assert section_tabs(report) == {"tool_flows": "network"}
    mixed_roles = {
        "evidence_index": [
            {"id": "ev_1", "server": "x", "source": "mcp:x", "agent_tab": "static"},
            {"id": "ev_2", "server": "x", "source": "mcp:x"},
        ],
        "sections": [_section("tool_a", ["ev_1", "ev_2"])],
    }
    assert section_tabs(mixed_roles) == {}


def test_the_full_report_says_its_servers_too() -> None:
    stored = {"evidence_index": _rows(), "sections": [_section("tool_a", ["ev_1"])]}
    svc = SimpleNamespace(get_malware_report=AsyncMock(return_value=stored))
    served = asyncio.run(get_full_malware_report(uuid.uuid4(), SimpleNamespace(), svc))
    assert served["sections"][0]["source_server"] == "alpha"
    assert "source_server" not in stored["sections"][0]
