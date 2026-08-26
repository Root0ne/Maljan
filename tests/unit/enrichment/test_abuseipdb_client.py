"""Unit tests for :class:`maljan.enrichment.AbuseIPDBClient`."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from maljan.enrichment.abuseipdb_client import AbuseIPDBClient, _safe_ip


def _client(handler: Any) -> tuple[AbuseIPDBClient, httpx.AsyncClient]:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    abuse = AbuseIPDBClient(api_key="test-key", http=http)
    return abuse, http


class TestSafeIP:
    def test_valid_ipv4(self) -> None:
        assert _safe_ip("1.2.3.4")

    def test_valid_ipv6(self) -> None:
        assert _safe_ip("2001:db8::1")

    def test_rejects_garbage(self) -> None:
        assert not _safe_ip("not-an-ip")

    def test_rejects_empty(self) -> None:
        assert not _safe_ip("")


class TestAbuseIPDB:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Key"] == "test-key"
            assert "ipAddress=1.2.3.4" in str(request.url)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 88,
                        "countryCode": "RU",
                        "isp": "EvilNet",
                        "domain": "evilnet.example",
                        "totalReports": 42,
                    }
                },
            )

        abuse, http = _client(handler)
        try:
            result = await abuse.ip_check("1.2.3.4")
        finally:
            await http.aclose()
        assert result is not None
        assert result["abuse_confidence"] == 88
        assert result["country"] == "RU"
        assert result["total_reports"] == 42

    @pytest.mark.asyncio
    async def test_404_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        abuse, http = _client(handler)
        try:
            result = await abuse.ip_check("1.2.3.4")
        finally:
            await http.aclose()
        assert result is None

    @pytest.mark.asyncio
    async def test_rate_limited(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        abuse, http = _client(handler)
        try:
            result = await abuse.ip_check("1.2.3.4")
        finally:
            await http.aclose()
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_ip_short_circuits(self) -> None:
        called = {"flag": False}

        def handler(request: httpx.Request) -> httpx.Response:
            called["flag"] = True
            return httpx.Response(200, json={})

        abuse, http = _client(handler)
        try:
            assert await abuse.ip_check("not-an-ip") is None
            assert await abuse.ip_check("") is None
        finally:
            await http.aclose()
        assert not called["flag"]

    @pytest.mark.asyncio
    async def test_constructor_requires_key(self) -> None:
        with pytest.raises(ValueError):
            AbuseIPDBClient(api_key="", http=httpx.AsyncClient())

    @pytest.mark.asyncio
    async def test_malformed_payload_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json")

        abuse, http = _client(handler)
        try:
            result = await abuse.ip_check("1.2.3.4")
        finally:
            await http.aclose()
        assert result is None
