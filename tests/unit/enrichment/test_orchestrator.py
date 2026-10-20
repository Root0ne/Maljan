"""Unit tests for :func:`enrich_malware_report`, driven by declared sources."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    Threshold,
    annotate_age,
    declared_verdict,
    effective_sources,
    is_malicious,
)
from maljan.enrichment.orchestrator import (
    _carry_seeded_context,
    _has_successful_rep,
    _is_public_ip,
    enrich_malware_report,
)


def _key(*parts: str) -> str:
    """A credential-shaped value built at run time."""
    return "-".join(parts)


def _mr(domains: list[dict] | None = None, ips: list[dict] | None = None) -> dict:
    return {"network": {"domains": domains or [], "ips": ips or []}}


def _whois_mock(asn: str | None = None, geo: str | None = None) -> MagicMock:
    mock = MagicMock()
    mock.asn_lookup = AsyncMock(return_value=asn)
    mock.geoip = MagicMock(return_value=geo)
    return mock


def _shipped(key: str, credential: str = "", **changes: Any) -> ReadySource:
    """A shipped source, unpaced so a test does not sleep, with ``credential``."""
    source = effective_sources({key: {"rate_limit_seconds": 0.0, **changes}})[key]
    return ReadySource(key=key, source=source, credential=credential)


def _vt_answer(malicious: int = 0, suspicious: int = 0, **attrs: Any) -> dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious},
                **attrs,
            }
        }
    }


class _Wire:
    """A mock transport that answers by host and records every request."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.get(request.url.host)
        if isinstance(answer, httpx.Response):
            return answer
        if answer is None:
            return httpx.Response(404)
        return httpx.Response(200, json=answer)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self))


VT_HOST = "www.virustotal.com"
ABUSE_HOST = "api.abuseipdb.com"


class TestNoNetwork:
    @pytest.mark.asyncio
    async def test_empty_report_skipped(self) -> None:
        mr = {"network": {}}
        out = await enrich_malware_report(mr, sources=[_shipped("virustotal", _key("k"))])
        assert out == mr  # unchanged

    @pytest.mark.asyncio
    async def test_missing_network_key(self) -> None:
        mr: dict[str, Any] = {}
        out = await enrich_malware_report(mr, sources=[_shipped("virustotal", _key("k"))])
        assert out is mr


class TestDomainEnrichment:
    @pytest.mark.asyncio
    async def test_a_source_populates_reputation(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=7)})
        async with wire.client() as http:
            out = await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("vt", "k"))], http_client=http
            )
        assert out["network"]["domains"][0]["reputation"]["malicious"] == 7

    @pytest.mark.asyncio
    async def test_skips_already_populated(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com", "reputation": {"source": "preset"}}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=99)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("vt", "k"))], http_client=http
            )
        assert mr["network"]["domains"][0]["reputation"]["source"] == "preset"
        assert wire.requests == []

    @pytest.mark.asyncio
    async def test_no_credential_leaves_reputation_null(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=7)})
        async with wire.client() as http:
            out = await enrich_malware_report(
                mr, sources=[_shipped("virustotal", "")], http_client=http
            )
        assert out["network"]["domains"][0].get("reputation") is None
        assert wire.requests == []

    @pytest.mark.asyncio
    async def test_a_disabled_source_is_not_asked(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=7)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr,
                sources=[_shipped("virustotal", _key("vt", "k"), enabled=False)],
                http_client=http,
            )
        assert wire.requests == []

    @pytest.mark.asyncio
    async def test_cap_limits_lookups(self) -> None:
        mr = _mr(domains=[{"fqdn": f"d{i}.com"} for i in range(50)])
        wire = _Wire({VT_HOST: _vt_answer()})
        async with wire.client() as http:
            await enrich_malware_report(
                mr,
                sources=[_shipped("virustotal", _key("vt", "k"))],
                http_client=http,
                max_lookups_per_kind=5,
            )
        assert len(wire.requests) == 5


class TestIPEnrichment:
    @pytest.mark.asyncio
    async def test_falls_back_to_the_next_source_when_the_first_has_nothing(self) -> None:
        mr = _mr(ips=[{"address": "1.2.3.4"}])
        wire = _Wire({VT_HOST: None, ABUSE_HOST: {"data": {"abuseConfidenceScore": 65}}})
        async with wire.client() as http:
            with patch("maljan.enrichment.orchestrator.WhoisClient", return_value=_whois_mock()):
                out = await enrich_malware_report(
                    mr,
                    sources=[
                        _shipped("abuseipdb", _key("ab", "k")),
                        _shipped("virustotal", _key("vt", "k")),
                    ],
                    http_client=http,
                )
        rep = out["network"]["ips"][0].get("reputation")
        assert rep is not None
        assert rep["source"] == "abuseipdb"
        # Asked in the declared order, whatever order the list came in.
        assert [r.url.host for r in wire.requests] == [VT_HOST, ABUSE_HOST]

    @pytest.mark.asyncio
    async def test_asn_and_geo_populated(self) -> None:
        mr = _mr(ips=[{"address": "8.8.8.8"}])
        wire = _Wire({})
        async with wire.client() as http:
            with patch(
                "maljan.enrichment.orchestrator.WhoisClient",
                return_value=_whois_mock(asn="AS15169 GOOGLE", geo="US"),
            ):
                await enrich_malware_report(mr, http_client=http)
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

    def test_a_record_is_malicious_by_its_source_s_thresholds(self) -> None:
        vt = effective_sources({})["virustotal"]
        abuse = effective_sources({})["abuseipdb"]
        assert is_malicious({"source": "virustotal", "malicious": 3}, vt) is True
        assert is_malicious({"source": "virustotal", "malicious": 0}, vt) is False
        assert is_malicious({"source": "virustotal", "suspicious": 3}, vt) is True
        assert is_malicious({"source": "abuseipdb", "abuse_confidence": 80}, abuse) is True
        assert is_malicious({"source": "abuseipdb", "abuse_confidence": 10}, abuse) is False
        # Stale reputation never drives a verdict.
        assert is_malicious({"source": "virustotal", "malicious": 9, "stale": True}, vt) is False

    def test_annotate_age_marks_stale(self) -> None:
        vt = effective_sources({})["virustotal"]
        old = {"source": "virustotal", "last_analysis_date_unix": 1_000_000_000}  # 2001
        annotate_age(old, vt)
        assert old.get("stale") is True
        assert old["age_days"] > 90

        fresh = {"source": "virustotal", "last_analysis_date_unix": int(time.time()) - 100}
        annotate_age(fresh, vt)
        assert fresh.get("stale") is None
        assert fresh["age_days"] >= 0


class TestTheEarlierRecordsContextIsKept:
    """A new record keeps the earlier record's sandbox context, and its link with its source."""

    def test_the_sandbox_context_is_kept(self) -> None:
        prev = {"hostname": "h", "contacted_ports": [443]}
        rep: dict[str, Any] = {"source": "anylookup", "malicious": 0}
        _carry_seeded_context(prev, rep)
        assert rep == {"source": "anylookup", "malicious": 0, **prev}

    def test_a_link_moves_together_with_its_source(self) -> None:
        prev = {"source": "firstlookup", "link": "https://lookup.example/x"}
        rep: dict[str, Any] = {"source": "anylookup", "malicious": 0}
        _carry_seeded_context(prev, rep)
        assert rep["link"] == "https://lookup.example/x"
        assert rep["link_source"] == "firstlookup"
        assert rep["source"] == "anylookup"
        # Carried again, it keeps the source that gave it, not the record's.
        later: dict[str, Any] = {"source": "thirdlookup"}
        _carry_seeded_context(rep, later)
        assert later["link_source"] == "firstlookup"

    def test_a_link_with_no_source_is_not_carried(self) -> None:
        rep: dict[str, Any] = {"source": "anylookup"}
        _carry_seeded_context({"link": "https://lookup.example/x", "hostname": "h"}, rep)
        assert "link" not in rep and "link_source" not in rep
        assert rep["hostname"] == "h"

    def test_a_stored_rows_legacy_permalink_key_is_still_kept(self) -> None:
        from maljan.core.legacy_reputation import STORED_REPUTATION_LINK_KEYS

        prev = {key: f"https://stored.example/{key}" for key in STORED_REPUTATION_LINK_KEYS}
        rep: dict[str, Any] = {"source": "anylookup"}
        _carry_seeded_context(prev, rep)
        assert all(rep[key] == prev[key] for key in STORED_REPUTATION_LINK_KEYS)

    def test_a_field_of_the_new_record_is_never_overwritten(self) -> None:
        rep: dict[str, Any] = {"source": "anylookup", "link": "https://new.example/"}
        _carry_seeded_context({"link": "https://old.example/"}, rep)
        assert rep["link"] == "https://new.example/"


class TestSignalQualityFeedback:
    @pytest.mark.asyncio
    async def test_private_ip_skipped_no_lookup(self) -> None:
        mr = _mr(ips=[{"address": "10.0.0.5"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            with patch("maljan.enrichment.orchestrator.WhoisClient", return_value=_whois_mock()):
                await enrich_malware_report(
                    mr, sources=[_shipped("virustotal", _key("k"))], http_client=http
                )
        assert wire.requests == []
        assert mr["network"]["ips"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_private_fqdn_skipped_no_lookup(self) -> None:
        mr = _mr(domains=[{"fqdn": "build.corp.internal"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("k"))], http_client=http
            )
        assert wire.requests == []
        assert mr["network"]["domains"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_a_name_found_only_in_the_byte_image_is_not_looked_up(self) -> None:
        """One PE's string sweep spent 452 s of reputation budget on fragments."""
        mr = _mr(domains=[{"fqdn": "rosoft.com", "source": "strings"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("k"))], http_client=http
            )
        assert wire.requests == []
        assert mr["network"]["domains"][0].get("reputation") is None

    @pytest.mark.asyncio
    async def test_a_name_the_sandbox_resolved_is_looked_up(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com", "source": "sandbox"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("k"))], http_client=http
            )
        assert len(wire.requests) == 1

    @pytest.mark.asyncio
    async def test_malicious_reputation_sets_is_suspicious(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com", "is_suspicious": False}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=8)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("k"))], http_client=http
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
        """Callers that don't pass memory_store still work."""
        mr = _mr(ips=[{"address": "1.2.3.4"}])
        wire = _Wire({})
        async with wire.client() as http:
            with patch("maljan.enrichment.orchestrator.WhoisClient", return_value=_whois_mock()):
                out = await enrich_malware_report(mr, http_client=http)
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
        out = await enrich_malware_report(mr, memory_store=store)  # type: ignore[arg-type]
        assert len(out["attribution"]["similar_samples"]) == 1


def test_a_source_validates_as_its_own_model() -> None:
    assert isinstance(effective_sources({})["virustotal"], EnrichmentSource)


class TestWhatTheCapLeavesUnasked:
    @pytest.mark.asyncio
    async def test_the_report_states_each_row_and_question_not_asked(self) -> None:
        mr = _mr(
            domains=[{"fqdn": f"d{i}.com"} for i in range(4)],
            ips=[
                {"address": "8.8.8.8"},
                {"address": "1.1.1.1", "reputation": {"source": "x"}, "geo": "US"},
            ],
        )
        wire = _Wire({VT_HOST: _vt_answer()})
        async with wire.client() as http:
            with patch("maljan.enrichment.orchestrator.WhoisClient", return_value=_whois_mock()):
                out = await enrich_malware_report(
                    mr,
                    sources=[_shipped("virustotal", _key("vt", "k"))],
                    http_client=http,
                    max_lookups_per_kind=1,
                )
        rows = {(r["kind"], r["value"]): r for r in out["enrichment_not_asked"]}
        assert [v for k, v in rows if k == "domain"] == ["d1.com", "d2.com", "d3.com"]
        assert rows[("domain", "d1.com")]["questions"] == ["reputation"]
        # An address holding its reputation is not said to lack it: only the ASN is not asked.
        assert rows[("ip", "1.1.1.1")]["questions"] == ["asn"]
        assert rows[("ip", "1.1.1.1")]["cap"] == 1

    @pytest.mark.asyncio
    async def test_nothing_unasked_leaves_no_statement_and_clears_an_old_one(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        mr["enrichment_not_asked"] = [
            {"kind": "domain", "value": "evil.com", "questions": ["reputation"], "cap": 1}
        ]
        wire = _Wire({VT_HOST: _vt_answer()})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("vt", "k"))], http_client=http
            )
        assert "enrichment_not_asked" not in mr


class TestTheDeclaredVerdictIsStored:
    @pytest.mark.asyncio
    async def test_the_record_carries_the_sources_verdict(self) -> None:
        mr = _mr(domains=[{"fqdn": "bad.com"}, {"fqdn": "fine.com"}])
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            await enrich_malware_report(
                mr, sources=[_shipped("virustotal", _key("vt", "k"))], http_client=http
            )
        assert all(d["reputation"]["malicious_verdict"] is True for d in mr["network"]["domains"])

    def test_no_count_is_unknown_not_false(self) -> None:
        vt = effective_sources({})["virustotal"]
        assert (
            declared_verdict({"source": "virustotal", "malicious": 0, "suspicious": 0}, vt) is False
        )
        assert declared_verdict({"source": "virustotal", "malicious": 0}, vt) is None
        assert declared_verdict({"source": "virustotal"}, vt) is None
        assert declared_verdict({"source": "virustotal", "malicious": 9, "stale": True}, vt) is None


class TestOrThresholds:
    def test_a_met_threshold_is_true_whatever_the_other_holds(self) -> None:
        abuse = effective_sources({})["abuseipdb"].model_copy(
            update={
                "malicious_when": [
                    Threshold(field="abuse_confidence", at_least=50),
                    Threshold(field="reports", at_least=3),
                ]
            }
        )
        assert declared_verdict({"abuse_confidence": 80}, abuse) is True
        assert declared_verdict({"reports": 5}, abuse) is True

    def test_false_only_when_every_threshold_field_holds_a_count(self) -> None:
        abuse = effective_sources({})["abuseipdb"].model_copy(
            update={
                "malicious_when": [
                    Threshold(field="abuse_confidence", at_least=50),
                    Threshold(field="reports", at_least=3),
                ]
            }
        )
        assert declared_verdict({"abuse_confidence": 10, "reports": 1}, abuse) is False
        # One count missing and the held one unmet: the missing one could have met it.
        assert declared_verdict({"abuse_confidence": 10}, abuse) is None

    @pytest.mark.asyncio
    async def test_a_second_enrichment_overwrites_the_verdict_and_pops_an_unknown(self) -> None:
        mr = _mr(domains=[{"fqdn": "evil.com"}])
        source = _shipped("virustotal", _key("vt", "k"))
        wire = _Wire({VT_HOST: _vt_answer(malicious=5)})
        async with wire.client() as http:
            await enrich_malware_report(mr, sources=[source], http_client=http)
        assert mr["network"]["domains"][0]["reputation"]["malicious_verdict"] is True
        # The same keys come back in a later answer carrying the key itself.
        rep = {"source": "virustotal", "malicious_verdict": True, "harmless": 3}
        from maljan.enrichment.orchestrator import _keep

        _keep({}, (source, rep))
        assert "malicious_verdict" not in rep
