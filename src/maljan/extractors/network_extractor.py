"""Extract the NetworkIOCs section from the sandbox report.

The CAPEv2 sandbox report exposes ``network`` with sub-lists for ``dns``,
``http``, ``tcp``, ``udp``, ``hosts``, ``domains``. Each accessor below
tolerates minor shape variation across CAPE versions (some report TCP/UDP
flows under ``flows`` rather than dedicated keys).

Suspicion heuristics are deliberately simple and additive — the narrative
agent and the threat-intel enrichment worker layer richer signal on top.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkIP, NetworkURL

# Domains we never want to flag as suspicious — common SaaS / OS update
# infrastructure. Extend rather than replace.
_BENIGN_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "windowsupdate.com",
        "windows.com",
        "msftncsi.com",
        "msftconnecttest.com",
        "apple.com",
        "icloud.com",
        "googleapis.com",
        "google.com",
        "gstatic.com",
        "cloudfront.net",
        "akamai.net",
        "akamaiedge.net",
    }
)

# Substrings that strongly suggest C2 / commodity-malware infra.
_SUSPICIOUS_DOMAIN_TOKENS: tuple[str, ...] = (
    ".bit",
    ".onion",
    "duckdns",
    "no-ip",
    "ddns.net",
    "ngrok.io",
    "pastebin",
    "transfer.sh",
    "anonfiles",
    "tempuri.org",
)


def build_network_iocs(
    sandbox_report: dict[str, Any] | None,
) -> NetworkIOCs | None:
    """Return NetworkIOCs aggregated from the sandbox report, or None if empty."""
    if not sandbox_report:
        return None
    raw = sandbox_report.get("network") or {}
    if not isinstance(raw, dict):
        return None

    domains = _extract_domains(raw)
    ips = _extract_ips(raw)
    urls = _extract_urls(raw)
    user_agents = _extract_user_agents(raw)
    ja3 = _extract_ja3(raw)

    if not (domains or ips or urls or user_agents or ja3):
        return None

    logger.info(
        "network_extractor: domains=%d ips=%d urls=%d ja3=%d",
        len(domains),
        len(ips),
        len(urls),
        len(ja3),
    )
    return NetworkIOCs(
        domains=domains,
        ips=ips,
        urls=urls,
        user_agents=user_agents,
        ja3_fingerprints=ja3,
    )


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


def _extract_domains(raw: dict[str, Any]) -> list[NetworkDomain]:
    by_fqdn: dict[str, NetworkDomain] = {}

    # 1. DNS queries
    for entry in raw.get("dns") or []:
        if not isinstance(entry, dict):
            continue
        fqdn = (entry.get("request") or entry.get("hostname") or entry.get("name") or "").strip()
        if not fqdn:
            continue
        node = _get_or_create_domain(by_fqdn, fqdn)
        if isinstance(entry.get("answers"), list):
            for ans in entry["answers"]:
                if isinstance(ans, dict):
                    ip = ans.get("data") or ans.get("ip")
                    if ip and ip not in node.resolved_ips:
                        node.resolved_ips.append(str(ip))
        pid = entry.get("pid")
        if isinstance(pid, int) and pid not in node.queried_pids:
            node.queried_pids.append(pid)

    # 2. HTTP host headers
    for entry in raw.get("http") or []:
        if not isinstance(entry, dict):
            continue
        host = (entry.get("host") or entry.get("hostname") or "").strip()
        if host:
            _get_or_create_domain(by_fqdn, host)

    # 3. ``domains`` aggregate (some sandboxes pre-compute)
    for d in raw.get("domains") or []:
        if isinstance(d, str):
            _get_or_create_domain(by_fqdn, d.strip())
        elif isinstance(d, dict) and d.get("domain"):
            _get_or_create_domain(by_fqdn, str(d["domain"]).strip())

    # Suspicion scoring
    for node in by_fqdn.values():
        node.is_suspicious, node.reason = _domain_suspicious(node.fqdn)

    return sorted(by_fqdn.values(), key=lambda d: (not d.is_suspicious, d.fqdn))


def _get_or_create_domain(table: dict[str, NetworkDomain], fqdn: str) -> NetworkDomain:
    key = fqdn.lower().rstrip(".")
    if key not in table:
        table[key] = NetworkDomain(fqdn=key, queried_pids=[], resolved_ips=[])
    return table[key]


def _domain_suspicious(fqdn: str) -> tuple[bool, str | None]:
    lower = fqdn.lower()
    # Strip subdomains for the benign check
    parts = lower.split(".")
    if len(parts) >= 2:
        registered = ".".join(parts[-2:])
        if registered in _BENIGN_DOMAINS:
            return False, None
    for token in _SUSPICIOUS_DOMAIN_TOKENS:
        if token in lower:
            return True, f"contains '{token}'"
    if _looks_like_dga(lower):
        return True, "DGA-like (high consonant ratio)"
    return False, None


def _looks_like_dga(domain: str) -> bool:
    """Cheap DGA heuristic: long label + consonant heavy + no recognisable TLD."""
    parts = domain.split(".")
    if not parts:
        return False
    label = parts[0]
    if len(label) < 10:
        return False
    vowels = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")
    if consonants == 0:
        return False
    ratio = consonants / max(vowels + consonants, 1)
    return ratio > 0.75


# ---------------------------------------------------------------------------
# IPs
# ---------------------------------------------------------------------------


def _extract_ips(raw: dict[str, Any]) -> list[NetworkIP]:
    seen: dict[tuple[str, int | None, str | None], NetworkIP] = {}

    def _add(address: str, port: int | None, transport: str | None) -> None:
        if not _is_valid_ip(address):
            return
        key = (address, port, transport)
        if key in seen:
            return
        suspicious, reason = _ip_suspicious(address)
        seen[key] = NetworkIP(
            address=address,
            port=port,
            transport=transport,  # type: ignore[arg-type]
            is_suspicious=suspicious,
        )
        if reason:
            seen[key].reputation = {"_heuristic_reason": reason}

    for entry in raw.get("tcp") or []:
        _read_flow(entry, "tcp", _add)
    for entry in raw.get("udp") or []:
        _read_flow(entry, "udp", _add)
    for entry in raw.get("hosts") or []:
        if isinstance(entry, str):
            _add(entry, None, None)
        elif isinstance(entry, dict):
            _add(str(entry.get("ip") or entry.get("address") or ""), None, None)

    return list(seen.values())


def _read_flow(entry: Any, transport: str, add: Any) -> None:
    if isinstance(entry, str):
        add(entry, None, transport)
        return
    if not isinstance(entry, dict):
        return
    dst = entry.get("dst") or entry.get("dst_ip") or entry.get("ip") or entry.get("address")
    port = entry.get("dport") or entry.get("dst_port") or entry.get("port")
    if dst:
        try:
            port_int = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_int = None
        add(str(dst), port_int, transport)


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _ip_suspicious(ip: str) -> tuple[bool, str | None]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, None
    if addr.is_private or addr.is_loopback or addr.is_multicast:
        return False, None
    # Naive RBL-style heuristic: just flag every public routable IP as
    # "to be enriched" — the threat-intel worker fills in actual reputation.
    return False, "public_address"


# ---------------------------------------------------------------------------
# URLs / UAs / JA3
# ---------------------------------------------------------------------------


def _extract_urls(raw: dict[str, Any]) -> list[NetworkURL]:
    out: list[NetworkURL] = []
    seen: set[str] = set()
    for entry in raw.get("http") or []:
        if not isinstance(entry, dict):
            continue
        host = (entry.get("host") or "").strip()
        path = (entry.get("uri") or entry.get("path") or "/").strip()
        if not host:
            continue
        scheme = "https" if entry.get("port") in (443, "443") else "http"
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
        if url in seen:
            continue
        seen.add(url)
        raw_status = entry.get("status")
        try:
            status = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            status = None
        out.append(
            NetworkURL(
                url=url,
                method=str(entry.get("method") or "GET").upper(),
                status=status,
                user_agent=entry.get("user_agent") or entry.get("ua"),
            )
        )
    return out


def _extract_user_agents(raw: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw.get("http") or []:
        if not isinstance(entry, dict):
            continue
        ua = entry.get("user_agent") or entry.get("ua")
        if ua and ua not in seen:
            seen.add(ua)
            out.append(str(ua))
    return out


def _extract_ja3(raw: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw.get("tls") or []:
        if not isinstance(entry, dict):
            continue
        ja3 = entry.get("ja3") or entry.get("ja3_hash")
        if ja3 and ja3 not in seen:
            seen.add(str(ja3))
            out.append(str(ja3))
    return out


# ---------------------------------------------------------------------------
# Wave 10 W10-NET-01 (2026-05-30) — fold Triage SandboxCTI.network into the
# typed NetworkIOCs. The 2026-05-30 UI walk found that
# ``stix_bundle_extended.x_maljan_cti.network`` carried 6 domains + 19 IPs +
# 3 URLs from Triage but ``MalwareReport.network`` was None, so the NETWORK
# tab and SUMMARY snapshot card both rendered zeros.
# ---------------------------------------------------------------------------


def merge_sandbox_cti_network(
    network_iocs: NetworkIOCs | None,
    sandbox_cti: dict[str, Any] | None,
) -> NetworkIOCs | None:
    """Augment NetworkIOCs with the Triage SandboxCTI block (or build fresh).

    SandboxCTI shape (from ``maljan/analysis/sandbox_cti.py``)::

        {
          "network": {
            "ips":         [str],
            "domains":     [str],
            "http_urls":   [str],
            "tls_ja3":     [str],
            "tls_sni":     [str],   # treated as additional FQDNs
            "dns_queries": [str],   # treated as additional FQDNs
          },
          ...
        }

    Returns ``network_iocs`` unchanged when ``sandbox_cti`` has no usable
    network entries, or a merged ``NetworkIOCs`` with CTI rows appended (and
    deduped by FQDN / address / URL).
    """
    if not isinstance(sandbox_cti, dict):
        return network_iocs
    cti_net = sandbox_cti.get("network")
    if not isinstance(cti_net, dict):
        return network_iocs

    cti_domains_raw = _gather_strings(
        cti_net.get("domains"), cti_net.get("tls_sni"), cti_net.get("dns_queries")
    )
    cti_ips_raw = _gather_strings(cti_net.get("ips"))
    cti_urls_raw = _gather_strings(cti_net.get("http_urls"), cti_net.get("urls"))
    cti_ja3_raw = _gather_strings(cti_net.get("tls_ja3"))

    if not (cti_domains_raw or cti_ips_raw or cti_urls_raw or cti_ja3_raw):
        return network_iocs

    base = network_iocs or NetworkIOCs()
    seen_fqdn = {d.fqdn.lower() for d in base.domains}
    seen_addr = {ip.address for ip in base.ips}
    seen_url = {u.url for u in base.urls}
    seen_ja3 = set(base.ja3_fingerprints)

    new_domains = list(base.domains)
    for fqdn in cti_domains_raw:
        key = fqdn.lower()
        if key in seen_fqdn:
            continue
        seen_fqdn.add(key)
        new_domains.append(
            NetworkDomain(
                fqdn=fqdn,
                is_suspicious=_domain_is_suspicious(fqdn),
                reason="From Triage SandboxCTI" if _domain_is_suspicious(fqdn) else None,
            )
        )

    new_ips = list(base.ips)
    for addr in cti_ips_raw:
        if addr in seen_addr:
            continue
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            continue
        seen_addr.add(addr)
        new_ips.append(NetworkIP(address=addr))

    new_urls = list(base.urls)
    for url in cti_urls_raw:
        if url in seen_url:
            continue
        seen_url.add(url)
        new_urls.append(NetworkURL(url=url))

    new_ja3 = list(base.ja3_fingerprints)
    for ja3 in cti_ja3_raw:
        if ja3 in seen_ja3:
            continue
        seen_ja3.add(ja3)
        new_ja3.append(ja3)

    added = (
        (len(new_domains) - len(base.domains))
        + (len(new_ips) - len(base.ips))
        + (len(new_urls) - len(base.urls))
        + (len(new_ja3) - len(base.ja3_fingerprints))
    )
    if added:
        logger.info(
            "network_extractor: merged %d SandboxCTI entries "
            "(domains+%d, ips+%d, urls+%d, ja3+%d).",
            added,
            len(new_domains) - len(base.domains),
            len(new_ips) - len(base.ips),
            len(new_urls) - len(base.urls),
            len(new_ja3) - len(base.ja3_fingerprints),
        )

    return NetworkIOCs(
        domains=new_domains,
        ips=new_ips,
        urls=new_urls,
        user_agents=list(base.user_agents),
        ja3_fingerprints=new_ja3,
    )


def _gather_strings(*sources: Any) -> list[str]:
    """Flatten the given sources into a deduped ordered list of clean strings."""
    out: list[str] = []
    seen: set[str] = set()
    for src in sources:
        if not isinstance(src, list):
            continue
        for item in src:
            if not isinstance(item, str):
                continue
            v = item.strip()
            if not v or v in seen:
                continue
            seen.add(v)
            out.append(v)
    return out


def _domain_is_suspicious(fqdn: str) -> bool:
    lower = fqdn.lower()
    for token in _SUSPICIOUS_DOMAIN_TOKENS:
        if token in lower:
            return True
    return False
