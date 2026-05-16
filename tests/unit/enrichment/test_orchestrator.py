"""Unit tests for :func:`enrich_malware_report`."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from maljan.enrichment.orchestrator import enrich_malware_report


def _mr(domains: list[dict] | None = None, ips: list[dict] | None = None) -> dict:
    return {
        "network": {
            "domains": domains or [],
            "ips": ips or [],
        }
    }


def _vt_mock(domain_rep: dict | None = None, ip_rep: dict | None = None) -> MagicMock:
    mock = MagicMock()
    mock.domain_reputation = AsyncMock(return_value=domain_rep)
    mock.ip_reputation = AsyncMock(return_value=ip_rep)
    return mock


def _abuse_mock(rep: dict | None = None) -> MagicMock:
    mock = MagicMock()
    mock.ip_check = AsyncMock(return_value=rep)
    return mock


def _whois_mock(asn: str | None = None, geo: str | None = None) -> MagicMock:
    mock = MagicMock()
    mock.asn_lookup = AsyncMock(return_value=asn)
    mock.geoip = MagicMock(return_value=geo)
    return mock


class TestNoNetwork:
    @pytest.mark.asyncio
    async def test_empty_report_skipped(self) -> None:
        mr = {"network": {}}
        out = await enrich_malware_report(mr, vt_api_key="x", abuseipdb_api_key="y")
        assert out == mr  # unchanged

    @pytest.mark.asyncio
    async def test_missing_network_key(self) -> None:
        mr: dict[str, Any] = {}
        out = await enrich_malware_report(mr, vt_api_key="x", abuseipdb_api_key="y")
        assert out is mr


class TestDomainEnrichment:
    @pytest.mark.asyncio
    async def test_vt_populates_reputation(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch(
                "maljan.enrichment.orchestrator.VirusTotalClient",
                return_value=_vt_mock(domain_rep={"source": "virustotal", "malicious": 7}),
            ):
                out = await enrich_malware_report(
                    mr,
                    vt_api_key="key",
                    abuseipdb_api_key=None,
                    http_client=http,
                )
        assert out["network"]["domains"][0]["reputation"]["malicious"] == 7

    @pytest.mark.asyncio
    async def test_skips_already_populated(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com", "reputation": {"source": "preset"}}])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            vt = _vt_mock(domain_rep={"source": "virustotal", "malicious": 99})
            with patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt):
                await enrich_malware_report(
                    mr,
                    vt_api_key="key",
                    abuseipdb_api_key=None,
                    http_client=http,
                )
        assert mr["network"]["domains"][0]["reputation"]["source"] == "preset"
        vt.domain_reputation.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_vt_key_leaves_reputation_null(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            out = await enrich_malware_report(
                mr,
                vt_api_key=None,
                abuseipdb_api_key=None,
                http_client=http,
            )
        assert out["network"]["domains"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_cap_limits_lookups(self) -> None:
        mr = _mr(domains=[{"fqdn": f"d{i}.com"} for i in range(50)])
        vt = _vt_mock(domain_rep={"source": "virustotal"})
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt):
                await enrich_malware_report(
                    mr,
                    vt_api_key="key",
                    abuseipdb_api_key=None,
                    http_client=http,
                    max_lookups_per_kind=5,
                )
        assert vt.domain_reputation.await_count == 5


class TestIPEnrichment:
    @pytest.mark.asyncio
    async def test_falls_back_to_abuse_when_vt_returns_none(self) -> None:
        mr = _mr(ips=[{"address": "1.2.3.4"}])
        vt = _vt_mock(ip_rep=None)
        abuse = _abuse_mock(rep={"source": "abuseipdb", "abuse_confidence": 65})
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with (
                patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt),
                patch("maljan.enrichment.orchestrator.AbuseIPDBClient", return_value=abuse),
                patch(
                    "maljan.enrichment.orchestrator.WhoisClient",
                    return_value=_whois_mock(),
                ),
            ):
                out = await enrich_malware_report(
                    mr,
                    vt_api_key="k1",
                    abuseipdb_api_key="k2",
                    http_client=http,
                )
        rep = out["network"]["ips"][0].get("reputation")
        assert rep is not None
        assert rep["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_asn_and_geo_populated(self) -> None:
        mr = _mr(ips=[{"address": "8.8.8.8"}])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch(
                "maljan.enrichment.orchestrator.WhoisClient",
                return_value=_whois_mock(asn="AS15169 GOOGLE", geo="US"),
            ):
                await enrich_malware_report(
                    mr,
                    vt_api_key=None,
                    abuseipdb_api_key=None,
                    http_client=http,
                )
        ip = mr["network"]["ips"][0]
        assert ip["asn"] == "AS15169 GOOGLE"
        assert ip["geo"] == "US"
