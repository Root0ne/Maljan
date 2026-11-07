"""Post-hoc threat-intelligence enrichment for ``MalwareReport`` IOCs.

The pipeline emits a ``MalwareReport`` whose ``network.domains`` and
``network.ips`` carry ``reputation=None``. The enrichment package fills
those slots by asking the declared enrichment sources
(:mod:`malspark.enrichment.declared`; the shipped ones in
:mod:`malspark.enrichment.builtin_sources`) and WHOIS/GeoIP. It runs as an ARQ
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

from malspark.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    effective_sources,
)
from malspark.enrichment.orchestrator import enrich_malware_report
from malspark.enrichment.whois_client import WhoisClient
from malspark.extractors.attribution import populate_similar_samples

__all__ = [
    "EnrichmentSource",
    "ReadySource",
    "WhoisClient",
    "effective_sources",
    "enrich_malware_report",
    "populate_similar_samples",
]
