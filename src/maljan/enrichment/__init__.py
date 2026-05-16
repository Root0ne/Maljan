"""Post-hoc threat-intelligence enrichment for ``MalwareReport`` IOCs.

The pipeline emits a ``MalwareReport`` whose ``network.domains`` and
``network.ips`` carry ``reputation=None``. The enrichment package fills
those slots by querying external CTI providers (VirusTotal, AbuseIPDB)
and WHOIS/GeoIP. It runs as an ARQ background task so the verdict
latency stays unaffected.

Public surface:
  - :func:`enrich_malware_report` — orchestrator, accepts dict, returns dict.
  - :class:`VirusTotalClient`, :class:`AbuseIPDBClient`, :class:`WhoisClient` —
    provider clients. Each one returns ``None`` on error so the caller
    can degrade gracefully.

Every provider is **fail-safe by design**: missing API keys, HTTP errors,
rate-limit responses and SSRF attempts all degrade to ``None`` with a
single warning log.
"""

from __future__ import annotations

from maljan.enrichment.abuseipdb_client import AbuseIPDBClient
from maljan.enrichment.orchestrator import enrich_malware_report
from maljan.enrichment.virustotal_client import VirusTotalClient
from maljan.enrichment.whois_client import WhoisClient

__all__ = [
    "AbuseIPDBClient",
    "VirusTotalClient",
    "WhoisClient",
    "enrich_malware_report",
]
