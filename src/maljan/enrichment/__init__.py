"""Post-hoc threat-intelligence enrichment for ``MalwareReport`` IOCs.

The pipeline emits a ``MalwareReport`` whose ``network.domains`` and
``network.ips`` carry ``reputation=None``. The enrichment package fills
those slots by asking the declared enrichment sources
(:mod:`maljan.enrichment.declared`; the shipped ones in
:mod:`maljan.enrichment.builtin_sources`) and WHOIS/GeoIP. It runs as an ARQ
background task so the verdict latency stays unaffected.

Public surface:
  - :func:`enrich_malware_report` — orchestrator, accepts dict, returns dict.
  - :class:`EnrichmentSource`, :class:`ReadySource`, :func:`effective_sources` —
    the declarations and the sources in force.
  - :class:`WhoisClient` — the ASN/GeoIP client.

Every source is **fail-safe by design**: a missing credential, HTTP errors,
rate-limit responses and requests leaving the declared host all degrade to
no record with a single warning log.
"""

from __future__ import annotations

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    effective_sources,
)
from maljan.enrichment.orchestrator import enrich_malware_report
from maljan.enrichment.whois_client import WhoisClient
from maljan.extractors.attribution import populate_similar_samples

__all__ = [
    "EnrichmentSource",
    "ReadySource",
    "WhoisClient",
    "effective_sources",
    "enrich_malware_report",
    "populate_similar_samples",
]
