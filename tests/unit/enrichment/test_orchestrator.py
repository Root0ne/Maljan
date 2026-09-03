"""Unit tests for :func:`enrich_malware_report`."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from maljan.enrichment.orchestrator import (
    _annotate_reputation_age,
    _has_successful_rep,
    _is_public_ip,
    _reputation_is_malicious,
    enrich_malware_report,
)


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


class TestReputationHelpers:
    def test_has_successful_rep(self) -> None:
        assert _has_successful_rep({"reputation": {"source": "virustotal"}}) is True
        assert _has_successful_rep({"reputation": {"malicious": 0}}) is False  # no source
        assert _has_successful_rep({"reputation": {}}) is False
        assert _has_successful_rep({}) is False

    def test_is_public_ip(self) -> None:
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("10.0.0.5") is False
        assert _is_public_ip("127.0.0.1") is False
        assert _is_public_ip("169.254.1.1") is False
        assert _is_public_ip("not-an-ip") is False

    def test_reputation_is_malicious(self) -> None:
        assert _reputation_is_malicious({"source": "virustotal", "malicious": 3}) is True
        assert _reputation_is_malicious({"source": "virustotal", "malicious": 0}) is False
        assert _reputation_is_malicious({"source": "abuseipdb", "abuse_confidence": 80}) is True
        assert _reputation_is_malicious({"source": "abuseipdb", "abuse_confidence": 10}) is False
        # Stale reputation never drives a verdict.
        assert (
            _reputation_is_malicious({"source": "virustotal", "malicious": 9, "stale": True})
            is False
        )

    def test_annotate_age_marks_stale(self) -> None:
        old = {"source": "virustotal", "last_analysis_date_unix": 1_000_000_000}  # 2001
        _annotate_reputation_age(old)
        assert old.get("stale") is True
        assert old["age_days"] > 90

        fresh = {"source": "virustotal", "last_analysis_date_unix": int(time.time()) - 100}
        _annotate_reputation_age(fresh)
        assert fresh.get("stale") is None
        assert fresh["age_days"] >= 0


class TestSignalQualityFeedback:
    @pytest.mark.asyncio
    async def test_private_ip_skipped_no_lookup(self) -> None:
        mr = _mr(ips=[{"address": "10.0.0.5"}])
        vt = _vt_mock(ip_rep={"source": "virustotal", "malicious": 5})
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with (
                patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt),
                patch("maljan.enrichment.orchestrator.WhoisClient", return_value=_whois_mock()),
            ):
                await enrich_malware_report(
                    mr, vt_api_key="k", abuseipdb_api_key=None, http_client=http
                )
        vt.ip_reputation.assert_not_awaited()
        assert mr["network"]["ips"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_private_fqdn_skipped_no_lookup(self) -> None:
        mr = _mr(domains=[{"fqdn": "build.corp.internal"}])
        vt = _vt_mock(domain_rep={"source": "virustotal", "malicious": 5})
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt):
                await enrich_malware_report(
                    mr, vt_api_key="k", abuseipdb_api_key=None, http_client=http
                )
        vt.domain_reputation.assert_not_awaited()
        assert mr["network"]["domains"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_malicious_reputation_sets_is_suspicious(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com", "is_suspicious": False}])
        vt = _vt_mock(domain_rep={"source": "virustotal", "malicious": 8})
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch("maljan.enrichment.orchestrator.VirusTotalClient", return_value=vt):
                await enrich_malware_report(
                    mr, vt_api_key="k", abuseipdb_api_key=None, http_client=http
                )
        assert mr["network"]["domains"][0]["is_suspicious"] is True


class _AttribStore:
    """Stub for the memory store used by populate_similar_samples."""

    def __init__(self, cases: list[Any]) -> None:
        self._cases = cases
        self.calls = 0

    def retrieve(self, query: str, top_k: int = 3) -> list[Any]:
        self.calls += 1
        return self._cases[:top_k]


class TestAttribution:
    @pytest.mark.asyncio
    async def test_memory_store_none_is_default_and_noop(self) -> None:
        """Backward-compat: callers that don't pass memory_store still work."""
        mr = _mr(ips=[{"address": "1.2.3.4"}])
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        ) as http:
            with patch(
                "maljan.enrichment.orchestrator.WhoisClient",
                return_value=_whois_mock(),
            ):
                out = await enrich_malware_report(
                    mr,
                    vt_api_key=None,
                    abuseipdb_api_key=None,
                    http_client=http,
                )
        # No attribution block injected when no store was provided.
        assert "attribution" not in out or not out.get("attribution", {}).get("similar_samples")

    @pytest.mark.asyncio
    async def test_memory_store_populates_similar_samples(self) -> None:
        from maljan.memory.long_term_memory import StoredCase

        store = _AttribStore(
            [
                StoredCase(
                    sample_id="b" * 64,
                    summary_text="similar",
                    technique_ids=["T1055"],
                    malware_category="RAT",
                ),
                StoredCase(
                    sample_id="c" * 64,
                    summary_text="another",
                    technique_ids=["T1071"],
                    malware_category="STEALER",
                ),
            ]
        )
        mr: dict[str, Any] = {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "malware_category": "RAT",
            "ttp_mappings": [{"technique_id": "T1055", "technique_name": "Process Injection"}],
            "network": {"domains": [], "ips": []},
        }
        out = await enrich_malware_report(
            mr,
            vt_api_key=None,
            abuseipdb_api_key=None,
            memory_store=store,  # type: ignore[arg-type]
            similar_top_k=2,
        )
        sims = out["attribution"]["similar_samples"]
        assert len(sims) == 2
        assert store.calls == 1
        assert sims[0]["source"] == "maljan-ltm"

    @pytest.mark.asyncio
    async def test_attribution_runs_even_without_network_iocs(self) -> None:
        from maljan.memory.long_term_memory import StoredCase

        store = _AttribStore(
            [
                StoredCase(
                    sample_id="b" * 64,
                    summary_text="ldr",
                    technique_ids=["T1547"],
                    malware_category="DROPPER",
                ),
            ]
        )
        mr: dict[str, Any] = {
            "identity": {"hashes": {"sha256": "z" * 64}},
            "malware_category": "DROPPER",
            "ttp_mappings": [
                {"technique_id": "T1547", "technique_name": "Boot or Logon Autostart"}
            ],
            # No network block → orchestrator short-circuits BEFORE reputation
            # lookups, but attribution must still run.
        }
        out = await enrich_malware_report(
            mr,
            vt_api_key=None,
            abuseipdb_api_key=None,
            memory_store=store,  # type: ignore[arg-type]
        )
        assert len(out["attribution"]["similar_samples"]) == 1
