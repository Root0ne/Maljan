"""Ask the declared enrichment sources and patch a ``MalwareReport`` dict.

The orchestrator is pipeline-side (Python only) — the API worker imports
it. It mutates *and* returns the dict so callers can choose to persist
the new copy without read-modify-write race risk.

The sources are the declared ones (:mod:`maljan.enrichment.declared`), each
ready with its credential: for each indicator kind the report holds a slot
for, the configured sources that answer that kind are asked in their declared
order and the first record is kept.

Idempotent: any domain/IP whose ``reputation`` already holds a value is
skipped. Lookup budgets are enforced per kind (default 25 each) so a
single enrichment never floods the provider quota.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

import httpx

from maljan.core.logger import logger
from maljan.enrichment.declared import (
    AskListener,
    ReadySource,
    SourceAsker,
    ToolCaller,
    annotate_age,
    is_malicious,
)
from maljan.enrichment.whois_client import WhoisClient
from maljan.extractors.attribution import populate_similar_samples
from maljan.extractors.network_extractor import (
    domain_is_corroborated,
    host_is_private_use,
    ip_corroboration_reason,
)

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore

# The report's slot for each indicator kind a post-verdict lookup fills: the
# network list and the field holding the value. ``hash`` and ``url`` have no
# reputation slot in the report, so a source answering only those is asked
# nothing here.
SLOTS: dict[str, tuple[str, str]] = {"domain": ("domains", "fqdn"), "ip": ("ips", "address")}


def _has_successful_rep(obj: dict[str, Any]) -> bool:
    """True only when a *successful* reputation lookup is already recorded.

    A bare-truthy ``reputation`` (e.g. an empty/failed shell) must NOT short-
    circuit a retry — only a dict carrying a provider ``source`` counts as done.
    """
    rep = obj.get("reputation")
    return isinstance(rep, dict) and bool(rep.get("source"))


# The fields of a row's earlier reputation a new record keeps where it has
# none of its own: the sandbox context of an IP. A record's ``link`` (the
# neutral field a source declares its permalink under, in its ``record``) is
# its own source's, so it is carried only together with that source, as
# ``link`` and ``link_source`` (:func:`_carry_seeded_context`). A stored row
# seeded before ``link`` holds its permalink under the legacy key
# (``core.legacy_reputation``), whose key names its service, kept as it is.
CARRIED_REPUTATION_FIELDS: tuple[str, ...] = ("hostname", "contacted_ports")
LINK_FIELD = "link"
LINK_SOURCE_FIELD = "link_source"


def _carry_seeded_context(prev: Any, rep: dict[str, Any]) -> None:
    """Preserve the earlier record's context when live enrichment replaces reputation.

    A row's reputation may already hold, for an IP, ``hostname`` /
    ``contacted_ports`` from the sandbox report, and a permalink (``link``).
    The live records are richer but may lack those keys, so they are folded
    forward instead of clobbered. A ``link`` moves only with the source that
    gave it (the earlier record's ``link_source``, else its ``source``), into
    ``link`` and ``link_source``, so it is never read as the new record's
    source's; a link with no source is not carried, and that is logged.
    """
    from maljan.core.legacy_reputation import STORED_REPUTATION_LINK_KEYS

    if not isinstance(prev, dict):
        return
    for key in (*STORED_REPUTATION_LINK_KEYS, *CARRIED_REPUTATION_FIELDS):
        val = prev.get(key)
        if val is not None and rep.get(key) is None:
            rep[key] = val
    link = prev.get(LINK_FIELD)
    if link is None or rep.get(LINK_FIELD) is not None:
        return
    given_by = prev.get(LINK_SOURCE_FIELD) or prev.get("source")
    if not given_by:
        logger.debug("enrichment: an earlier record's link names no source; not carried.")
        return
    rep[LINK_FIELD] = link
    rep[LINK_SOURCE_FIELD] = given_by


def _is_public_ip(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )


# A hidden service is the one name this refuses that the export does not. The
# export publishes a valid Tor address because its own checksum stands in for
# the second source no sandbox can ever give it; no reputation provider can
# resolve one, so asking about it spends quota on a certain "unknown".
_TOR_SUFFIX = ".onion"


def _is_public_fqdn(name: str) -> bool:
    """True for a name a public reputation service can say something about.

    IP literals, single-label names and the special-use suffixes are internal
    infrastructure: sending them to a reputation service leaks the operator's
    naming and costs quota for an answer that is always "unknown". The
    suffixes are the ones the export holds back, read from the one list, so a
    name this pipeline will not publish is not one it posts to somebody else
    either.
    """
    host = name.strip().rstrip(".").lower().strip("[]")
    if not host or ".." in host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not host.endswith(_TOR_SUFFIX) and not host_is_private_use(host)


async def enrich_malware_report(
    malware_report: dict[str, Any],
    *,
    sources: Sequence[ReadySource] = (),
    max_lookups_per_kind: int = 25,
    http_client: httpx.AsyncClient | None = None,
    tool_caller: ToolCaller | None = None,
    tool_arguments: Callable[[str, str], Mapping[str, str]] | None = None,
    memory_store: MemoryStore | None = None,
    similar_top_k: int = 5,
    on_ask: AskListener | None = None,
    memory_owner: str | None = None,
) -> dict[str, Any]:
    """Populate reputation/asn/geo + attribution.similar_samples in place.

    Returns the (mutated) dict for convenience. Only the ``sources`` that
    are configured (enabled, holding the credential they need) are asked;
    a kind no configured source answers keeps its fields ``None``.
    ``tool_caller`` asks a server source's tool, and ``tool_arguments`` reads
    the argument a server's tool declares for a kind. When ``memory_store``
    is provided, the report's ``attribution.similar_samples`` is also
    populated from the LTM nearest-neighbour search (idempotent — skipped
    when already filled), among ``memory_owner``'s cases, or the unscoped
    ones for ``None`` (``long_term_memory.recall``). ``on_ask`` is told of
    each question just before it is sent, a source's and RDAP's alike. The
    caller is expected to persist the returned dict back to
    ``AnalysisReport.malware_report``.
    """
    network = malware_report.get("network") or {}
    domains = network.get(SLOTS["domain"][0]) or []
    ips = network.get(SLOTS["ip"][0]) or []

    # Attribution always runs (even with no network IOCs) so reports that
    # touched nothing on the wire still get a "you have seen this before"
    # panel from the LTM.
    if memory_store is not None:
        populate_similar_samples(
            malware_report, memory_store, top_k=similar_top_k, owner=memory_owner
        )

    if not (domains or ips):
        logger.info("enrich: no network IOCs in report, skipping reputation lookups.")
        return malware_report

    ready = sorted((s for s in sources if s.configured), key=lambda s: s.source.order)
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        asker = SourceAsker(
            client, tool_caller=tool_caller, tool_arguments=tool_arguments, on_ask=on_ask
        )
        whois = WhoisClient(client, on_ask=on_ask)

        if not ready:
            logger.warning("enrich: no enrichment source configured; reputation fields left null.")

        domains_skipped = await _enrich_domains(
            domains,
            sources=[s for s in ready if s.answers("domain")],
            asker=asker,
            cap=max_lookups_per_kind,
        )
        await _enrich_ips(
            ips,
            sources=[s for s in ready if s.answers("ip")],
            asker=asker,
            whois=whois,
            cap=max_lookups_per_kind,
        )
    finally:
        if own_client:
            await client.aclose()

    logger.info(
        "enrich: completed (domains=%d, ips=%d, domains_not_looked_up=%d).",
        len(domains),
        len(ips),
        domains_skipped,
    )
    return malware_report


async def _first_record(
    sources: Sequence[ReadySource], asker: SourceAsker, kind: str, value: str
) -> tuple[ReadySource, dict[str, Any]] | None:
    """The first source in order that answers ``value`` with a record, and that record."""
    for source in sources:
        rep = await asker.ask(source, kind, value)
        if rep is not None:
            return source, rep
    return None


def _keep(row: dict[str, Any], found: tuple[ReadySource, dict[str, Any]]) -> None:
    source, rep = found
    annotate_age(rep, source.source)
    _carry_seeded_context(row.get("reputation"), rep)
    row["reputation"] = rep
    # Feed verified reputation back into the heuristic suspicion flag so an
    # enriched-malicious indicator is not stuck at is_suspicious=False.
    if is_malicious(rep, source.source):
        row["is_suspicious"] = True


async def _enrich_domains(
    domains: list[dict[str, Any]],
    *,
    sources: Sequence[ReadySource],
    asker: SourceAsker,
    cap: int,
) -> int:
    skipped = 0
    if not sources:
        return skipped
    askable: list[dict[str, Any]] = []
    for dom in domains:
        fqdn = dom.get("fqdn")
        if not isinstance(fqdn, str) or not fqdn:
            continue
        if not _is_public_fqdn(fqdn):
            skipped += 1
            continue
        if not domain_is_corroborated(dom.get("source"), dom.get("reputation"), fqdn):
            # A name only the sample's byte image knows. One PE's twenty-five
            # string-derived "domains" held the single enrichment slot for
            # 452 s, and fifteen of them were fragments of longer names.
            skipped += 1
            continue
        askable.append(dom)
    # The cap is applied to what is worth asking about, not to the raw list:
    # a page of string noise at the front used to spend the whole budget
    # before the first name anything else had seen.
    for dom in askable[:cap]:
        if _has_successful_rep(dom):
            continue
        found = await _first_record(sources, asker, "domain", str(dom["fqdn"]))
        if found is not None:
            _keep(dom, found)
    return skipped


async def _enrich_ips(
    ips: list[dict[str, Any]],
    *,
    sources: Sequence[ReadySource],
    asker: SourceAsker,
    whois: WhoisClient,
    cap: int,
) -> None:
    askable: list[dict[str, Any]] = []
    for ip in ips:
        address = ip.get("address")
        if not isinstance(address, str) or not address:
            continue
        # Pre-filter private/reserved IPs: external providers reject them and
        # they are not real infrastructure — saves API budget and avoids noise.
        if not _is_public_ip(address):
            continue
        if ip_corroboration_reason(address, ip.get("source"), ip.get("reputation")) is None:
            # A run of digits the string sweep read as an address, or one no
            # second source knows. The same answer the domains get, for the
            # same reason: an endpoint only the sample's own byte image knows
            # is not worth a paid lookup, and one live run spent its whole
            # enrichment budget on twenty-five of them.
            continue
        askable.append(ip)
    # The cap is applied to what is worth asking about, as it is for the
    # domains: a page of string noise at the front used to spend the budget
    # before the first address anything else had seen.
    for ip in askable[:cap]:
        address = str(ip["address"])
        if not _has_successful_rep(ip):
            found = await _first_record(sources, asker, "ip", address)
            if found is not None:
                _keep(ip, found)
        if not ip.get("asn"):
            asn = await whois.asn_lookup(address)
            if asn:
                ip["asn"] = asn
        if not ip.get("geo"):
            geo = whois.geoip(address)
            if geo:
                ip["geo"] = geo
