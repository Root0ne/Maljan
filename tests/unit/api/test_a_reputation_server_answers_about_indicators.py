"""A reputation server no code names is asked about indicators through what is read of its listing.

Nothing here is a service the platform knows: the server's key, host and tool
names are made up at run time, its tools declare nothing, and what each is
(an indicator report, a submission) is read from its listing
(``core.derived_declarations``). Post-verdict enrichment asks it through the
lookup read for each kind, reads the answer by its shape, and never asks a tool
that sends the sample or one its tools list leaves unticked.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from app.services.enrichment_sources import ready_sources, slowest_shipped_pace
from app.services.enrichment_tools import ServerToolCaller
from maljan.analysis.disclosure import EnrichmentAsks
from maljan.core.config import MCPServerConfig
from maljan.core.derived_declarations import derived_tool_facts
from maljan.core.served_declarations import register_served
from maljan.core.tool_declarations import launch_identity
from maljan.enrichment.builtin_sources import builtin_source_entries
from maljan.enrichment.orchestrator import enrich_malware_report

KEY = "-".join(["acme", "intel"])
HOST = ".".join(["intel", "acme-labs", "net"])
DOMAIN = ".".join(["c2", "badhost", "net"])
ADDRESS = ".".join(["8", "8", "4", "4"])
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False}


def _tool(name: str, properties: dict[str, Any], *, annotations: Any = READ_ONLY) -> dict[str, Any]:
    return {
        "name": name,
        "description": "Answers what the service holds.",
        "inputSchema": {"type": "object", "properties": properties, "required": list(properties)},
        **({"annotations": annotations} if annotations is not None else {}),
    }


LISTING = [
    # Not read-only: a write tool, which a reputation service's reading calls
    # a submission. It takes a domain too, and is never the enrichment's call.
    _tool("share_domain", {"domain": {"type": "string"}}, annotations=None),
    _tool("domain_verdict", {"hostname": {"type": "string"}}),
    _tool("address_verdict", {"addr": {"type": "string", "format": "ipv4"}}),
    # Sends the file: never asked, whatever else it takes.
    _tool("scan_upload", {"file_path": {"type": "string"}, "ip": {"type": "string"}}),
]
ANSWER = {
    "result": {
        "verdicts": {"malicious": 4, "suspicious": 1, "harmless": 50, "undetected": 10},
        "family": ["acme-family"],
        "first_seen": "2024-01-02T00:00:00Z",
        "permalink": f"https://{HOST}/r/1",
    }
}


class _Listed:
    def __init__(
        self, definition: dict[str, Any], calls: list[tuple[str, dict[str, Any]]], answer: Any
    ) -> None:
        self.name = definition["name"]
        self.args_schema = definition["inputSchema"]
        self._calls = calls
        self._answer = answer

    async def ainvoke(self, args: dict[str, Any]) -> Any:
        self._calls.append((self.name, args))
        return self._answer


class _Handle:
    def __init__(
        self,
        calls: list[tuple[str, dict[str, Any]]],
        listing: list[dict[str, Any]],
        answers: dict[str, Any],
    ) -> None:
        self._tools = [_Listed(t, calls, answers.get(t["name"], ANSWER)) for t in listing]

    def tools(self) -> list[_Listed]:
        return self._tools

    def withheld_reason(self, _tool: str) -> None:
        return None


def _server(listing: list[dict[str, Any]] = LISTING, **fields: Any) -> MCPServerConfig:
    cfg = MCPServerConfig(
        enabled=True,
        transport="streamable-http",
        url=f"https://{HOST}/mcp",
        roles=["reputation"],
        **fields,
    )
    register_served(f"mcp:{KEY}", {}, launch_identity(cfg), derived_tool_facts(listing))
    return cfg


async def _enrich(
    cfg: MCPServerConfig,
    listing: list[dict[str, Any]] = LISTING,
    answers: dict[str, Any] | None = None,
    slept: list[float] | None = None,
) -> tuple[dict[str, Any], list[Any], list[Any]]:
    servers = {KEY: cfg}
    caller = ServerToolCaller(SimpleNamespace(mcp=SimpleNamespace(servers=servers)), job_key="t")
    calls: list[tuple[str, dict[str, Any]]] = []
    asks = EnrichmentAsks()

    async def _handle(_server: str) -> _Handle:
        return _Handle(calls, listing, answers or {})

    async def _no_secret(_key: str) -> str:
        return ""

    async def _sleep(seconds: float) -> None:
        (slept if slept is not None else []).append(seconds)

    sources = await ready_sources({}, _no_secret, servers, reputation_servers=True)
    report = {
        "network": {
            "domains": [{"fqdn": DOMAIN, "source": "sandbox"}],
            "ips": [{"address": ADDRESS, "source": "sandbox", "asn": "x", "geo": "y"}],
        }
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as h:
        with (
            patch.object(caller, "_handle", _handle),
            patch("maljan.enrichment.declared.asyncio.sleep", _sleep),
        ):
            await enrich_malware_report(
                report,
                sources=[s for s in sources if s.key.startswith("mcp:")],
                http_client=h,
                tool_caller=caller,
                tool_arguments=caller.arguments,
                on_ask=asks,
            )
    return report, calls, asks.rows(servers)


@pytest.mark.asyncio
async def test_a_never_seen_service_is_asked_through_the_lookups_read_from_its_listing() -> None:
    report, calls, rows = await _enrich(_server())
    assert calls == [
        ("domain_verdict", {"hostname": DOMAIN}),
        ("address_verdict", {"addr": ADDRESS}),
    ]
    expected = {
        "source": KEY,
        "malicious": 4,
        "suspicious": 1,
        "total": 65,
        "labels": ["acme-family"],
        "first_seen": "2024-01-02T00:00:00Z",
        "link": f"https://{HOST}/r/1",
    }
    assert report["network"]["domains"][0]["reputation"] == expected
    assert report["network"]["ips"][0]["reputation"] == expected
    # Every question is told, under the source and the server it went through.
    assert [(r["source"], r["host"], r["kinds"]) for r in rows] == [
        (f"mcp:{KEY}", HOST, {"domain": 1, "ip": 1})
    ]


@pytest.mark.asyncio
async def test_a_lookup_its_tools_list_leaves_unticked_is_never_asked() -> None:
    report, calls, _rows = await _enrich(_server(tools=["address_verdict", "share_domain"]))
    assert calls == [("address_verdict", {"addr": ADDRESS})]
    assert report["network"]["domains"][0].get("reputation") is None


@pytest.mark.asyncio
async def test_neither_a_submission_nor_a_tool_that_sends_the_file_is_ever_asked() -> None:
    _report, calls, _rows = await _enrich(_server())
    assert not {"share_domain", "scan_upload"} & {name for name, _args in calls}


@pytest.mark.asyncio
async def test_a_source_that_names_the_server_and_no_tool_is_asked_the_same_way() -> None:
    cfg = _server()
    servers = {KEY: cfg}
    caller = ServerToolCaller(SimpleNamespace(mcp=SimpleNamespace(servers=servers)), job_key="t")
    calls: list[tuple[str, dict[str, Any]]] = []

    async def _handle(_server: str) -> _Handle:
        return _Handle(calls, LISTING, {})

    async def _no_secret(_key: str) -> str:
        return ""

    stored = {
        "acme": {
            "kinds": ["ip"],
            "server": KEY,
            "malicious_when": [{"field": "malicious", "at_least": 3}],
        }
    }
    # Named by a source, the server is asked only as that source declares.
    sources = await ready_sources(stored, _no_secret, servers, reputation_servers=True)
    assert [s.key for s in sources if s.source.server] == ["acme"]
    report = {"network": {"domains": [], "ips": [{"address": ADDRESS, "source": "sandbox"}]}}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as h:
        with (
            patch.object(caller, "_handle", _handle),
            patch("maljan.enrichment.orchestrator.WhoisClient") as whois,
        ):
            whois.return_value.asn_lookup = _nothing
            whois.return_value.geoip = lambda _a: None
            await enrich_malware_report(
                report,
                sources=[s for s in sources if s.key == "acme"],
                http_client=h,
                tool_caller=caller,
                tool_arguments=caller.arguments,
            )
    assert calls == [("address_verdict", {"addr": ADDRESS})]
    ip = report["network"]["ips"][0]
    assert ip["reputation"]["source"] == KEY
    assert ip["reputation"]["malicious_verdict"] is True
    assert ip["is_suspicious"] is True


async def _nothing(_address: str) -> None:
    return None


@pytest.mark.asyncio
async def test_a_server_is_paced_at_the_slowest_shipped_pace_unless_its_service_says() -> None:
    slept: list[float] = []
    await _enrich(_server(), slept=slept)
    # Never faster than any shipped source, whichever service the server relays.
    shipped = [
        float(entry.get("rate_limit_seconds") or 0) for entry in builtin_source_entries().values()
    ]
    assert slept == [slowest_shipped_pace()] * 2 and slowest_shipped_pace() == max(shipped)
    slept.clear()
    await _enrich(_server(reputation_service={"rate_limit_seconds": 0.5}), slept=slept)
    assert slept == [0.5, 0.5]


@pytest.mark.asyncio
async def test_a_server_s_thresholds_give_its_records_a_verdict_and_none_give_none() -> None:
    marked = _server(reputation_service={"malicious_when": [{"field": "malicious", "at_least": 3}]})
    report, _calls, _rows = await _enrich(marked)
    domain = report["network"]["domains"][0]
    assert domain["reputation"]["malicious_verdict"] is True and domain["is_suspicious"] is True
    report, _calls, _rows = await _enrich(_server())
    domain = report["network"]["domains"][0]
    assert "malicious_verdict" not in domain["reputation"] and "is_suspicious" not in domain


FALLBACK = [
    # Read as a report on a domain, but its listing requires a second argument
    # the indicator alone cannot fill.
    _tool("domain_by_case", {"domain": {"type": "string"}, "case_id": {"type": "string"}}),
    # Answers a structured failure: the next lookup is asked.
    _tool("domain_quick", {"domain": {"type": "string"}}),
    _tool("domain_full", {"fqdn": {"type": "string"}}),
]


@pytest.mark.asyncio
async def test_a_failed_lookup_falls_back_to_the_next_and_an_unaskable_one_is_skipped() -> None:
    failure = {"error": {"code": "rate_limited", "message": "slow down"}}
    report, calls, rows = await _enrich(
        _server(FALLBACK), FALLBACK, answers={"domain_quick": failure}
    )
    assert calls == [("domain_quick", {"domain": DOMAIN}), ("domain_full", {"fqdn": DOMAIN})]
    assert report["network"]["domains"][0]["reputation"]["malicious"] == 4
    # Each question is told, the failed one too.
    assert rows[0]["kinds"] == {"domain": 2}


@pytest.mark.asyncio
async def test_a_lookup_read_as_sending_the_sample_is_skipped_whatever_is_declared() -> None:
    listing = [
        _tool(
            "domain_scan",
            {
                "domain": {"type": "string"},
                "content": {"type": "string", "contentEncoding": "base64"},
            },
        ),
        _tool("domain_verdict", {"hostname": {"type": "string"}}),
    ]
    # The block declares the sending tool a plain report on a domain; what its
    # listing is read as still keeps it from being asked.
    declared = {
        "domain_scan": {
            "kind": "indicator_report",
            "arguments": {"domain": "domain"},
            "effects": {"third_party": "no"},
        }
    }
    _report, calls, _rows = await _enrich(_server(listing, tool_facts=declared), listing)
    assert [name for name, _args in calls] == ["domain_verdict"]
