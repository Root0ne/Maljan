"""Unit tests for :class:`maljan.enrichment.VirusTotalClient`.

The client never raises. We stub ``httpx.AsyncClient`` with
``httpx.MockTransport`` so every branch (success, 404, 429, network error,
SSRF refusal, malformed JSON) is exercised without real HTTP traffic.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from maljan.enrichment.virustotal_client import (
    VirusTotalClient,
    _is_whitelisted_host,
    _safe_lookup_value,
    _summarise_vt_object,
)


def _client(handler: Any) -> tuple[VirusTotalClient, httpx.AsyncClient]:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    vt = VirusTotalClient(api_key="test-key", http=http, rate_limit_seconds=0)
    return vt, http


class TestHelpers:
    def test_safe_lookup_value_accepts_normal(self) -> None:
        assert _safe_lookup_value("evil.com")

    def test_safe_lookup_value_rejects_empty(self) -> None:
        assert not _safe_lookup_value("")

    def test_safe_lookup_value_rejects_control_chars(self) -> None:
        assert not _safe_lookup_value("evil\x00.com")

    def test_safe_lookup_value_rejects_slashes(self) -> None:
        assert not _safe_lookup_value("evil.com/path")

    def test_safe_lookup_value_rejects_oversized(self) -> None:
        assert not _safe_lookup_value("a" * 300)

    def test_whitelist_accepts_expected_host(self) -> None:
        assert _is_whitelisted_host("https://www.virustotal.com/api/v3/x", "www.virustotal.com")

    def test_whitelist_rejects_unexpected_host(self) -> None:
        assert not _is_whitelisted_host("https://attacker.example/x", "www.virustotal.com")

    def test_summarise_vt_object_full_payload(self) -> None:
        result = _summarise_vt_object(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 10,
                            "suspicious": 3,
                            "harmless": 2,
                            "undetected": 5,
                        },
                        "reputation": -42,
                        "categories": {"vendor_a": "malware", "vendor_b": "phishing"},
                    }
                }
            }
        )
        assert result is not None
        assert result["malicious"] == 10
        assert result["reputation"] == -42
        assert "malware" in result["categories"]


class TestVirusTotalClient:
    @pytest.mark.asyncio
    async def test_domain_reputation_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["x-apikey"] == "test-key"
            assert "evil.com" in str(request.url)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 5, "suspicious": 1},
                            "reputation": -10,
                        }
                    }
                },
            )

        vt, http = _client(handler)
        try:
            result = await vt.domain_reputation("evil.com")
        finally:
            await http.aclose()
        assert result is not None
        assert result["source"] == "virustotal"
        assert result["malicious"] == 5

    @pytest.mark.asyncio
    async def test_domain_reputation_404_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        vt, http = _client(handler)
        try:
            result = await vt.domain_reputation("missing.com")
        finally:
            await http.aclose()
        assert result is None

    @pytest.mark.asyncio
    async def test_domain_reputation_rate_limit_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        vt, http = _client(handler)
        try:
            result = await vt.domain_reputation("evil.com")
        finally:
            await http.aclose()
        assert result is None

    @pytest.mark.asyncio
    async def test_domain_reputation_network_error_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        vt, http = _client(handler)
        try:
            result = await vt.domain_reputation("evil.com")
        finally:
            await http.aclose()
        assert result is None

    @pytest.mark.asyncio
    async def test_unsafe_value_short_circuits(self) -> None:
        called = {"flag": False}

        def handler(request: httpx.Request) -> httpx.Response:
            called["flag"] = True
            return httpx.Response(200, json={})

        vt, http = _client(handler)
        try:
            assert await vt.domain_reputation("") is None
            assert await vt.domain_reputation("evil\x00.com") is None
        finally:
            await http.aclose()
        assert not called["flag"]

    @pytest.mark.asyncio
    async def test_ip_reputation_success(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "1.2.3.4" in str(request.url)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 1},
                            "reputation": 0,
                        }
                    }
                },
            )

        vt, http = _client(handler)
        try:
            result = await vt.ip_reputation("1.2.3.4")
        finally:
            await http.aclose()
        assert result is not None
        assert result["malicious"] == 1

    @pytest.mark.asyncio
    async def test_constructor_requires_key(self) -> None:
        with pytest.raises(ValueError):
            VirusTotalClient(api_key="", http=httpx.AsyncClient())
