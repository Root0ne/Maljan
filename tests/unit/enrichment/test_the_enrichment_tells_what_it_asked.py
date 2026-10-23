"""The enrichment tells its listener each question just before it is sent.

A REST source is named with the host its declaration fixes, a source asked
through a tool server with that server's key, and RDAP with its registry's
host. The listener's rows (``analysis.disclosure.EnrichmentAsks``) count the
questions per source and host, by indicator kind; a question through a server
is placed by the server's block, and one through a server on this machine or
at a local address names no host. A listener that fails never costs a lookup.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from maljan.analysis.disclosure import EnrichmentAsks
from maljan.enrichment.declared import ReadySource, effective_sources
from maljan.enrichment.orchestrator import enrich_malware_report
from maljan.enrichment.whois_client import RDAP_HOST, RDAP_SOURCE
from tests.credential_shapes import password

VT_HOST = "www.virustotal.com"


def _key(*parts: str) -> str:
    """A credential-shaped value built at run time."""
    return "-".join(parts)


def _shipped(key: str, credential: str = "") -> ReadySource:
    source = effective_sources({key: {"rate_limit_seconds": 0.0}})[key]
    return ReadySource(key=key, source=source, credential=credential)


def _report() -> dict[str, Any]:
    return {
        "network": {
            "domains": [{"fqdn": "evil.example.com"}],
            "ips": [{"address": "1.2.3.4"}],
        }
    }


def _client() -> httpx.AsyncClient:
    def _answer(request: httpx.Request) -> httpx.Response:
        if request.url.host == VT_HOST:
            stats = {"malicious": 0, "undetected": 70}
            return httpx.Response(
                200, json={"data": {"attributes": {"last_analysis_stats": stats}}}
            )
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(_answer))


@pytest.mark.asyncio
async def test_each_question_is_told_with_its_source_host_and_kind() -> None:
    asks = EnrichmentAsks()
    with patch("maljan.enrichment.whois_client._try_ipwhois", return_value=None):
        async with _client() as http:
            await enrich_malware_report(
                _report(),
                sources=[_shipped("virustotal", _key("vt", "k"))],
                http_client=http,
                on_ask=asks,
            )

    assert asks.rows() == [
        {"source": RDAP_SOURCE, "host": RDAP_HOST, "kinds": {"ip": 1}, "failed": 0, "why": ""},
        {
            "source": "virustotal",
            "host": VT_HOST,
            "kinds": {"domain": 1, "ip": 1},
            "failed": 0,
            "why": "",
        },
    ]


@pytest.mark.asyncio
async def test_a_listener_that_fails_never_costs_a_lookup() -> None:
    def _broken(*_args: str) -> None:
        raise RuntimeError("listener down")

    with patch("maljan.enrichment.whois_client._try_ipwhois", return_value=None):
        async with _client() as http:
            out = await enrich_malware_report(
                _report(),
                sources=[_shipped("virustotal", _key("vt", "k"))],
                http_client=http,
                on_ask=_broken,
            )

    assert out["network"]["domains"][0]["reputation"]["source"] == "virustotal"


def test_a_question_through_a_server_is_placed_by_the_servers_block() -> None:
    asks = EnrichmentAsks()
    for source, kind, server in [
        ("intel", "domain", "far"),
        ("intel", "domain", "far"),
        ("misp", "ip", "near"),
        ("local", "ip", "child"),
    ]:
        asks(source, "", kind, server)(True)
    servers = {
        "far": SimpleNamespace(
            transport="streamable-http", url=f"https://u:{password()}@intel.example.org/mcp"
        ),
        "near": SimpleNamespace(transport="http", url="http://10.0.0.5:8443/mcp"),
        "child": SimpleNamespace(transport="stdio", url=""),
    }

    rows = {row["source"]: row for row in asks.rows(servers)}

    assert rows["intel"] == {
        "source": "intel",
        "host": "intel.example.org",
        "kinds": {"domain": 2},
        "failed": 0,
        "why": "",
    }
    for local in ("misp", "local"):
        assert rows[local]["host"] == ""
        assert "a local tool server" in rows[local]["why"]


def test_a_server_the_settings_no_longer_hold_names_no_host() -> None:
    asks = EnrichmentAsks()
    asks("intel", "", "domain", "gone")

    (row,) = asks.rows({})

    assert row["host"] == "" and row["why"]


@pytest.mark.asyncio
async def test_the_rdap_fallback_reaches_the_bootstrap_alone_and_follows_no_referral() -> None:
    from maljan.enrichment.whois_client import WhoisClient

    reached: list[str] = []

    def _answer(request: httpx.Request) -> httpx.Response:
        reached.append(str(request.url.host))
        return httpx.Response(302, headers={"location": "https://rdap.db.ripe.net/ip/1.2.3.4"})

    asks = EnrichmentAsks()
    with patch("maljan.enrichment.whois_client.ipwhois_available", return_value=False):
        async with httpx.AsyncClient(transport=httpx.MockTransport(_answer)) as http:
            await WhoisClient(http, on_ask=asks).asn_lookup("1.2.3.4")

    assert reached == [RDAP_HOST]
    assert [(r["source"], r["host"]) for r in asks.rows()] == [(RDAP_SOURCE, RDAP_HOST)]


@pytest.mark.asyncio
async def test_ipwhois_s_own_lookups_are_their_own_rows_with_their_path() -> None:
    from maljan.analysis.disclosure import (
        disclosure_lines,
        registry_rows,
        with_enrichment,
        with_enrichment_asked,
    )
    from maljan.enrichment.whois_client import (
        IPWHOIS_ASN_HOST,
        IPWHOIS_ASN_SOURCE,
        IPWHOIS_RDAP_SOURCE,
        WhoisClient,
    )

    asks = EnrichmentAsks()
    with (
        patch("maljan.enrichment.whois_client.ipwhois_available", return_value=True),
        patch("maljan.enrichment.whois_client._try_ipwhois", return_value="AS15169 GOOGLE"),
    ):
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(500))
        ) as http:
            assert await WhoisClient(http, on_ask=asks).asn_lookup("8.8.8.8") == "AS15169 GOOGLE"
        planned = [(r["source"], r["hosts"]) for r in registry_rows()]

    rows = asks.rows()
    assert sorted((r["source"], r["host"], r["failed"]) for r in rows) == [
        (IPWHOIS_ASN_SOURCE, IPWHOIS_ASN_HOST, 0),
        (IPWHOIS_RDAP_SOURCE, RDAP_HOST, 0),
    ]
    assert planned == [
        (IPWHOIS_RDAP_SOURCE, [RDAP_HOST]),
        (IPWHOIS_ASN_SOURCE, [IPWHOIS_ASN_HOST]),
        (RDAP_SOURCE, [RDAP_HOST]),
    ]
    record = with_enrichment_asked(with_enrichment({"models": [], "addressed": []}, []), rows)
    (line,) = [line for line in disclosure_lines(record) if line.startswith("Enrichment")]
    assert "RDAP through ipwhois, from the ARIN bootstrap, which may refer to a regional" in line
    assert "ASN lookups through ipwhois, by DNS to the ASN service there" in line
