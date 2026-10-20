"""The lookup cap counts the rows still to ask about, never the ones already answered.

The cap used to be sliced before the answered rows were skipped, so a stored
report re-enriched with its first rows answered spent every place on them and
asked nothing; the rows past the cap went unasked without a word. Answered
rows now hold no place, and the rows the cap leaves unasked are logged with
the count.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from maljan.enrichment.declared import ReadySource, effective_sources
from maljan.enrichment.orchestrator import enrich_malware_report


def _source() -> ReadySource:
    source = effective_sources({"virustotal": {"rate_limit_seconds": 0.0}})["virustotal"]
    return ReadySource(key="virustotal", source=source, credential="-".join(("vt", "k")))


def _answered() -> dict[str, Any]:
    return {"source": "virustotal", "malicious": 0}


class _Wire:
    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.asked.append(request.url.path.rsplit("/", 1)[-1])
        stats = {"malicious": 0, "suspicious": 0}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})


@pytest.mark.asyncio
async def test_answered_domains_hold_no_place_under_the_cap() -> None:
    domains = [{"fqdn": f"done{i}.com", "reputation": _answered()} for i in range(3)]
    domains += [{"fqdn": "new1.com"}, {"fqdn": "new2.com"}]
    wire = _Wire()
    async with httpx.AsyncClient(transport=httpx.MockTransport(wire)) as http:
        await enrich_malware_report(
            {"network": {"domains": domains, "ips": []}},
            sources=[_source()],
            http_client=http,
            max_lookups_per_kind=2,
        )

    assert wire.asked == ["new1.com", "new2.com"]


@pytest.mark.asyncio
async def test_a_fully_looked_up_address_holds_no_place_under_the_cap() -> None:
    ips = [
        {
            "address": "8.8.4.4",
            "source": "sandbox",
            "reputation": _answered(),
            "asn": "AS1",
            "geo": "US",
        },
        {"address": "1.1.1.1", "source": "sandbox"},
    ]
    whois = MagicMock()
    whois.asn_lookup = AsyncMock(return_value="AS13335")
    whois.geoip = MagicMock(return_value="AU")
    wire = _Wire()
    with patch("maljan.enrichment.orchestrator.WhoisClient", return_value=whois):
        async with httpx.AsyncClient(transport=httpx.MockTransport(wire)) as http:
            out = await enrich_malware_report(
                {"network": {"domains": [], "ips": ips}},
                sources=[_source()],
                http_client=http,
                max_lookups_per_kind=1,
            )

    assert wire.asked == ["1.1.1.1"]
    assert out["network"]["ips"][1]["asn"] == "AS13335"


@pytest.mark.asyncio
async def test_rows_the_cap_leaves_unasked_are_counted_in_the_log() -> None:
    domains = [{"fqdn": f"d{i}.com"} for i in range(5)]
    wire = _Wire()
    with patch("maljan.enrichment.orchestrator.logger") as log:
        async with httpx.AsyncClient(transport=httpx.MockTransport(wire)) as http:
            await enrich_malware_report(
                {"network": {"domains": domains, "ips": []}},
                sources=[_source()],
                http_client=http,
                max_lookups_per_kind=2,
            )

    assert len(wire.asked) == 2
    warned = [call.args for call in log.warning.call_args_list]
    assert any(args[1:3] == (3, "domain") for args in warned), warned
