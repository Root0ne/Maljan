"""Orchestrate VT/AbuseIPDB/WHOIS providers and patch a ``MalwareReport`` dict.

The orchestrator is pipeline-side (Python only) — the API worker imports
it. It mutates *and* returns the dict so callers can choose to persist
the new copy without read-modify-write race risk.

Idempotent: any domain/IP whose ``reputation`` already holds a value is
skipped. Lookup budgets are enforced per kind (default 25 each) so a
single enrichment never floods the provider quota.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from maljan.core.logger import logger
from maljan.enrichment.abuseipdb_client import AbuseIPDBClient
from maljan.enrichment.virustotal_client import VirusTotalClient
from maljan.enrichment.whois_client import WhoisClient
from maljan.extractors.attribution import populate_similar_samples

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


async def enrich_malware_report(
    malware_report: dict[str, Any],
    *,
    vt_api_key: str | None,
    abuseipdb_api_key: str | None,
    max_lookups_per_kind: int = 25,
    http_client: httpx.AsyncClient | None = None,
    memory_store: MemoryStore | None = None,
    similar_top_k: int = 5,
) -> dict[str, Any]:
    """Populate reputation/asn/geo + attribution.similar_samples in place.

    Returns the (mutated) dict for convenience. Providers without API
    keys are skipped — the matching fields stay ``None``. When
    ``memory_store`` is provided, the report's ``attribution.similar_samples``
    is also populated from the LTM nearest-neighbour search (idempotent —
    skipped when already filled). The caller is expected to persist the
    returned dict back to ``AnalysisReport.malware_report``.
    """
    network = malware_report.get("network") or {}
    domains = network.get("domains") or []
    ips = network.get("ips") or []

    # Attribution always runs (even with no network IOCs) so reports that
    # touched nothing on the wire still get a "you have seen this before"
    # panel from the LTM.
    if memory_store is not None:
        populate_similar_samples(malware_report, memory_store, top_k=similar_top_k)

    if not (domains or ips):
        logger.info("enrich: no network IOCs in report, skipping reputation lookups.")
        return malware_report

    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        vt: VirusTotalClient | None = None
        abuse: AbuseIPDBClient | None = None
        if vt_api_key:
            try:
                vt = VirusTotalClient(api_key=vt_api_key, http=client)
            except ValueError:
                vt = None
        if abuseipdb_api_key:
            try:
                abuse = AbuseIPDBClient(api_key=abuseipdb_api_key, http=client)
            except ValueError:
                abuse = None
        whois = WhoisClient(client)

        if vt is None and abuse is None:
            logger.warning("enrich: no provider API keys available; reputation fields left null.")

        await _enrich_domains(domains, vt=vt, cap=max_lookups_per_kind)
        await _enrich_ips(ips, vt=vt, abuse=abuse, whois=whois, cap=max_lookups_per_kind)
    finally:
        if own_client:
            await client.aclose()

    logger.info("enrich: completed (domains=%d, ips=%d).", len(domains), len(ips))
    return malware_report


async def _enrich_domains(
    domains: list[dict[str, Any]],
    *,
    vt: VirusTotalClient | None,
    cap: int,
) -> None:
    if vt is None:
        return
    for dom in domains[:cap]:
        if dom.get("reputation"):
            continue
        fqdn = dom.get("fqdn")
        if not isinstance(fqdn, str) or not fqdn:
            continue
        rep = await vt.domain_reputation(fqdn)
        if rep is not None:
            dom["reputation"] = rep


async def _enrich_ips(
    ips: list[dict[str, Any]],
    *,
    vt: VirusTotalClient | None,
    abuse: AbuseIPDBClient | None,
    whois: WhoisClient,
    cap: int,
) -> None:
    for ip in ips[:cap]:
        address = ip.get("address")
        if not isinstance(address, str) or not address:
            continue
        if not ip.get("reputation"):
            rep: dict[str, Any] | None = None
            if vt is not None:
                rep = await vt.ip_reputation(address)
            if rep is None and abuse is not None:
                rep = await abuse.ip_check(address)
            if rep is not None:
                ip["reputation"] = rep
        if not ip.get("asn"):
            asn = await whois.asn_lookup(address)
            if asn:
                ip["asn"] = asn
        if not ip.get("geo"):
            geo = whois.geoip(address)
            if geo:
                ip["geo"] = geo
