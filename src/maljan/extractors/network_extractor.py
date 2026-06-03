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
import math
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkIP, NetworkURL

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR

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
        # CDN / cloud / infra commonly seen in benign traffic (FP sources).
        "fastly.net",
        "cloudflare.com",
        "amazonaws.com",
        "jsdelivr.net",
        "gvt1.com",
        "ntp.org",
        "pool.ntp.org",
        "debian.org",
        "ubuntu.com",
        "archlinux.org",
    }
)

# RFC 6761/6762 reserved suffixes that must never be emitted as network IOCs.
_RESERVED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".localhost",
    ".test",
    ".example",
    ".invalid",
    ".arpa",
)
_RESERVED_DOMAIN_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})

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

# ---------------------------------------------------------------------------
# DGA scoring
# ---------------------------------------------------------------------------
# A label whose composite score (Shannon entropy + bigram rarity + supporting
# signals) clears this threshold is treated as algorithmically generated
# (surfaced as ``is_suspicious`` in the NETWORK tab).
_DGA_SCORE_THRESHOLD: float = 0.55
# Asserting a deterministic ATT&CK technique (T1568.002) demands more certainty
# than a surface suspicion flag, so the claim is only emitted above this higher
# bar. Borderline domains (0.55..0.65) stay flagged but assert no technique.
_DGA_CLAIM_THRESHOLD: float = 0.65
# Labels shorter than this are never scored as DGA. Short brandable names
# (e.g. "facebook", "telegram") have inflated normalised entropy simply
# because they have few repeated characters, so scoring them invites false
# positives. 10 matches the legacy heuristic's floor.
_DGA_MIN_LABEL_LEN: int = 10

# Most-common English letter bigrams. A natural-language label is dense in
# these; a random/DGA label is sparse — the classic "gibberish detector"
# signal. Membership-based (not full log-prob) to keep the table compact and
# the result deterministic + trivially testable.
_COMMON_BIGRAMS: frozenset[str] = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
        "ca",
        "el",
        "ta",
        "la",
        "ns",
        "di",
        "fo",
        "ho",
        "pe",
        "ec",
        "pr",
        "no",
        "ct",
        "us",
        "ac",
        "ot",
        "il",
        "tr",
        "ly",
        "nc",
        "et",
        "ut",
        "ss",
        "so",
        "rs",
        "un",
        "lo",
        "wa",
        "ge",
        "ie",
        "wh",
        "ee",
        "wi",
        "em",
        "ad",
        "ol",
        "rt",
        "po",
        "we",
        "na",
        "ul",
        "ni",
        "ts",
        "mo",
        "ow",
        "pa",
        "im",
        "mi",
        "ai",
        "sh",
        "ir",
        "su",
        "id",
        "os",
        "ia",
        "am",
        "fi",
        "ci",
        "ig",
        "ab",
        "ap",
        "do",
        "ds",
        "ru",
        "tu",
        "ess",
        "men",
    }
)

# Vowels used by the consonant-run / vowel-ratio supporting signals.
_VOWELS: frozenset[str] = frozenset("aeiou")

# ---------------------------------------------------------------------------
# IDN / punycode homograph
# ---------------------------------------------------------------------------
# Confusable (Cyrillic / Greek) -> ASCII skeleton. Used to decide whether a
# decoded IDN label is a look-alike of a well-known brand. Kept compact; the
# common Latin look-alikes cover the overwhelming majority of homograph abuse.
_CONFUSABLE_TO_ASCII: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "һ": "h",
    "ј": "j",
    "ӏ": "i",
    "ԁ": "d",
    "ԛ": "q",
    "ɡ": "g",
    # Greek
    "ο": "o",
    "α": "a",
    "ρ": "p",
    "ν": "v",
    "ι": "i",
}

# Brand "skeletons" (ASCII, no TLD) worth flagging as homograph targets.
_HOMOGRAPH_BRANDS: frozenset[str] = frozenset(
    {
        "paypal",
        "google",
        "apple",
        "microsoft",
        "amazon",
        "facebook",
        "binance",
        "netflix",
        "instagram",
        "whatsapp",
        "coinbase",
        "github",
        "dropbox",
        "linkedin",
        "twitter",
        "outlook",
        "office",
        "yahoo",
        "wellsfargo",
        "chase",
        "steamcommunity",
        "steampowered",
    }
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
    ja3s = _extract_ja3s(raw)

    if not (domains or ips or urls or user_agents or ja3 or ja3s):
        return None

    logger.info(
        "network_extractor: domains=%d ips=%d urls=%d ja3=%d ja3s=%d",
        len(domains),
        len(ips),
        len(urls),
        len(ja3),
        len(ja3s),
    )
    return NetworkIOCs(
        domains=domains,
        ips=ips,
        urls=urls,
        user_agents=user_agents,
        ja3_fingerprints=ja3,
        ja3s_fingerprints=ja3s,
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

    # Drop reserved / local / single-label names, then score suspicion.
    emittable = [n for n in by_fqdn.values() if _is_emittable_domain(n.fqdn)]
    for node in emittable:
        verdict = _assess_domain(node.fqdn)
        node.is_suspicious = verdict.suspicious
        node.reason = verdict.reason
        node.dga_score = verdict.dga_score
        node.is_punycode = verdict.is_punycode
        node.homograph_target = verdict.homograph_target

    return sorted(emittable, key=lambda d: (not d.is_suspicious, d.fqdn))


def _get_or_create_domain(table: dict[str, NetworkDomain], fqdn: str) -> NetworkDomain:
    key = fqdn.lower().rstrip(".")
    if key not in table:
        table[key] = NetworkDomain(fqdn=key, queried_pids=[], resolved_ips=[])
    return table[key]


@dataclass(frozen=True)
class _DomainVerdict:
    """Outcome of scoring one FQDN — the single source of truth for both the
    CAPE-path extractor and the Triage-CTI merge so domains are judged
    identically regardless of source."""

    suspicious: bool
    reason: str | None = None
    dga_score: float | None = None
    is_punycode: bool = False
    homograph_target: str | None = None


def _assess_domain(fqdn: str) -> _DomainVerdict:
    """Score an FQDN for suspicion. Order: benign allowlist -> IDN/punycode
    homograph -> C2/commodity tokens -> DGA score.

    Homograph and DGA checks scan every label except the trailing TLD (not
    just the leftmost), so a look-alike or algorithmic label that sits in a
    subdomain — ``login.pаypal.com`` — or under a multi-level public suffix —
    ``xjqz8frandom.co.uk`` — is still caught.
    """
    lower = fqdn.lower()
    parts = lower.split(".")
    # Strip subdomains for the benign check.
    if len(parts) >= 2:
        registered = ".".join(parts[-2:])
        if registered in _BENIGN_DOMAINS:
            return _DomainVerdict(suspicious=False)

    # Labels to inspect: everything except the trailing TLD label.
    labels = parts[:-1] if len(parts) >= 2 else parts

    # IDN / punycode homograph — scan all inspected labels (checked before
    # tokens so a look-alike of a benign brand is still flagged).
    is_puny_any = False
    for label in labels:
        is_puny, homograph = _idn_assessment(label)
        is_puny_any = is_puny_any or is_puny
        if homograph is not None:
            kind = "punycode IDN" if is_puny else "mixed-script"
            return _DomainVerdict(
                suspicious=True,
                reason=f"IDN homograph ({kind}, looks like '{homograph}')",
                is_punycode=is_puny,
                homograph_target=homograph,
            )

    for token in _SUSPICIOUS_DOMAIN_TOKENS:
        if token in lower:
            return _DomainVerdict(
                suspicious=True, reason=f"contains '{token}'", is_punycode=is_puny_any
            )

    # DGA — score each inspected label and keep the most suspicious one.
    best_label, best_score = "", 0.0
    for label in labels:
        s = _dga_score(label)
        if s > best_score:
            best_score, best_label = s, label
    if best_score >= _DGA_SCORE_THRESHOLD:
        ent = _normalised_entropy(best_label)
        rarity = _bigram_rarity(best_label)
        return _DomainVerdict(
            suspicious=True,
            reason=(
                f"DGA-like (score {best_score:.2f}: entropy {ent:.2f}, bigram-rarity {rarity:.2f})"
            ),
            dga_score=round(best_score, 3),
            is_punycode=is_puny_any,
        )

    return _DomainVerdict(suspicious=False, dga_score=round(best_score, 3), is_punycode=is_puny_any)


def _normalised_entropy(label: str) -> float:
    """Shannon entropy of the label's character distribution, normalised to
    [0,1] by the maximum entropy for its length (random strings -> ~1.0)."""
    chars = [c for c in label if c != "."]
    n = len(chars)
    if n < 2:
        return 0.0
    counts: dict[str, int] = {}
    for c in chars:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((k / n) * math.log2(k / n) for k in counts.values())
    max_entropy = math.log2(n)
    return entropy / max_entropy if max_entropy > 0 else 0.0


def _bigram_rarity(label: str) -> float:
    """Fraction of adjacent letter-bigrams NOT in the common-English set
    (1.0 -> every bigram is unusual; 0.0 -> all natural-language-like)."""
    letters = [c for c in label if c.isalpha()]
    if len(letters) < 2:
        return 0.0
    bigrams = ["".join(letters[i : i + 2]) for i in range(len(letters) - 1)]
    rare = sum(1 for bg in bigrams if bg not in _COMMON_BIGRAMS)
    return rare / len(bigrams)


def _max_consonant_run(label: str) -> int:
    run = best = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _dga_score(label: str) -> float:
    """Composite DGA likelihood in [0,1] for a single domain label.

    Combines normalised Shannon entropy, common-bigram rarity, digit ratio,
    a long-consonant-run signal, and the legacy consonant ratio. Deterministic
    and dependency-free so it is trivially testable and reproducible.
    """
    if len(label) < _DGA_MIN_LABEL_LEN:
        return 0.0
    alpha = [c for c in label if c.isalpha()]
    if not alpha:
        return 0.0

    entropy = _normalised_entropy(label)
    rarity = _bigram_rarity(label)
    digits = sum(1 for c in label if c.isdigit())
    digit_ratio = digits / len(label)
    consonants = sum(1 for c in alpha if c not in _VOWELS)
    consonant_ratio = consonants / len(alpha)
    long_run = 1.0 if _max_consonant_run(label) >= 5 else 0.0

    # Weighted blend. Bigram rarity is the strongest discriminator; entropy is
    # weighted down because it saturates for short distinct strings; the legacy
    # consonant ratio is retained as a minor contributor for continuity.
    score = (
        0.50 * rarity
        + 0.20 * entropy
        + 0.12 * min(digit_ratio * 2.0, 1.0)
        + 0.10 * long_run
        + 0.08 * consonant_ratio
    )
    return min(score, 1.0)


def _idn_assessment(label: str) -> tuple[bool, str | None]:
    """Detect IDN/punycode homographs on a single domain label.

    Returns ``(is_punycode, homograph_target)``. ``homograph_target`` is set
    when the label:

      * skeletonises (via the confusable map) onto a known brand — this also
        catches a fully non-Latin spoof such as an all-Cyrillic ``paypal``; or
      * mixes scripts (Latin + Cyrillic/Greek letters in the same label) — the
        defining signature of a homograph attack, even when it doesn't match a
        brand.

    A pure-ASCII label, or a legitimate single-script IDN (e.g. an all-Cyrillic
    Russian word that isn't a brand spoof), is never flagged.
    """
    is_puny = label.startswith("xn--")
    decoded = label
    if is_puny:
        try:
            decoded = label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            # Undecodable punycode is itself anomalous, but we have no target.
            return True, None

    # Plain ASCII (and not punycode) carries no homograph risk.
    if decoded.isascii() and not is_puny:
        return False, None

    skeleton = "".join(_CONFUSABLE_TO_ASCII.get(c, c) for c in decoded)
    skeleton_ascii = skeleton if skeleton.isascii() else None

    # Brand spoof — works for mixed-script *and* all-confusable single-script
    # look-alikes (e.g. an all-Cyrillic rendering of "paypal").
    if skeleton_ascii is not None:
        core = skeleton_ascii.strip("-")
        if core in _HOMOGRAPH_BRANDS:
            return is_puny, core

    # Mixed-script homograph: a single label containing BOTH Latin and
    # non-Latin letters is the classic look-alike signature.
    has_latin = any(ch.isalpha() and _is_latin(ch) for ch in decoded)
    has_non_latin = any(ch.isalpha() and not _is_latin(ch) for ch in decoded)
    if has_latin and has_non_latin:
        return is_puny, skeleton_ascii or decoded

    return is_puny, None


def _is_latin(ch: str) -> bool:
    try:
        return "LATIN" in unicodedata.name(ch)
    except ValueError:
        return False


def build_dga_isr(network_iocs: NetworkIOCs | None) -> AgentISR | None:
    """Turn high-confidence DGA domains into a deterministic ATT&CK claim.

    Mirrors ``SigmaLayer.to_isr`` / ``YaraLayer.to_isr``: emits one
    ``AgentISR`` (domain ``"network"``) carrying a ``T1568.002`` (Dynamic
    Resolution: Domain Generation Algorithms) claim per domain whose
    ``dga_score`` clears :data:`_DGA_CLAIM_THRESHOLD` — a higher bar than the
    suspicion threshold, so only strong signals assert the technique.

    Confidence is the domain's own score capped at 0.75: a lone heuristic must
    not by itself drive a high-confidence verdict (the TTP cascade boosts it
    only when another layer corroborates). Returns ``None`` when nothing
    qualifies.
    """
    if network_iocs is None:
        return None
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    claims: list[ClaimEvidence] = []
    for domain in network_iocs.domains:
        score = domain.dga_score
        if score is None or score < _DGA_CLAIM_THRESHOLD:
            continue
        claims.append(
            ClaimEvidence(
                claim=(
                    f"Algorithmically-generated domain (DGA): {domain.fqdn} (score {score:.2f})"
                ),
                evidence_ref=f"network_extractor: dga_score={score:.3f} for {domain.fqdn}",
                confidence=round(min(score, 0.75), 2),
                technique_id="T1568.002",
                rule_platforms=["any"],
            )
        )

    if not claims:
        return None
    return AgentISR(
        agent_id="network_dga",
        domain="network",
        claims=claims,
        dissent_items=[],
        revision_round=0,
    )


# ---------------------------------------------------------------------------
# IPs
# ---------------------------------------------------------------------------


def _extract_ips(raw: dict[str, Any]) -> list[NetworkIP]:
    seen: dict[tuple[str, int | None, str | None], NetworkIP] = {}

    def _add(address: str, port: int | None, transport: str | None) -> None:
        if not _is_valid_ip(address) or not _is_emittable_ip(address):
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
        if port_int is not None and not (1 <= port_int <= 65535):
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


def _is_emittable_ip(ip: str) -> bool:
    """True only for routable public addresses worth emitting as an IOC.

    Drops private / loopback / multicast / reserved / link-local / unspecified /
    broadcast — these are sandbox/test noise, never malware infrastructure, and
    pollute CTI feeds + waste threat-intel API budget.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    ):
        return False
    return str(addr) != "255.255.255.255"


def _is_emittable_domain(fqdn: str) -> bool:
    """True only for FQDNs worth emitting as an IOC.

    Drops RFC 6761/6762 reserved names/suffixes (localhost, *.local, *.test,
    *.example, *.invalid, *.arpa) and single-label hostnames (no dot) which are
    local resolutions, not external infrastructure.
    """
    lower = fqdn.lower().strip().rstrip(".")
    if not lower or "." not in lower:
        return False
    if lower in _RESERVED_DOMAIN_NAMES:
        return False
    return not any(lower.endswith(suffix) for suffix in _RESERVED_DOMAIN_SUFFIXES)


# ---------------------------------------------------------------------------
# URLs / UAs / JA3
# ---------------------------------------------------------------------------


def _extract_urls(raw: dict[str, Any]) -> list[NetworkURL]:
    out: list[NetworkURL] = []
    seen: set[str] = set()
    for entry in raw.get("http") or []:
        if not isinstance(entry, dict):
            continue
        # Host is case-insensitive (RFC 3986) — lowercase so casing variants
        # dedupe to one URL.
        host = (entry.get("host") or "").strip().lower()
        path = (entry.get("uri") or entry.get("path") or "/").strip()
        if not host:
            continue
        is_https = (
            entry.get("port") in (443, "443", 8443, "8443")
            or bool(entry.get("encrypted"))
            or bool(entry.get("ssl"))
        )
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
        if url in seen:
            continue
        seen.add(url)
        raw_status = entry.get("status")
        try:
            status = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            status = None
        if status is not None and not (100 <= status <= 599):
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
        ua = str(entry.get("user_agent") or entry.get("ua") or "").strip()
        if ua and ua not in seen:
            seen.add(ua)
            out.append(ua)
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


def _extract_ja3s(raw: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw.get("tls") or []:
        if not isinstance(entry, dict):
            continue
        ja3s = entry.get("ja3s") or entry.get("ja3s_hash")
        if ja3s and ja3s not in seen:
            seen.add(str(ja3s))
            out.append(str(ja3s))
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
            "tls_ja3s":    [str],
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
    cti_ja3s_raw = _gather_strings(cti_net.get("tls_ja3s"))

    if not (cti_domains_raw or cti_ips_raw or cti_urls_raw or cti_ja3_raw or cti_ja3s_raw):
        return network_iocs

    base = network_iocs or NetworkIOCs()
    seen_fqdn = {d.fqdn.lower() for d in base.domains}
    seen_addr = {ip.address for ip in base.ips}
    seen_url = {u.url for u in base.urls}
    seen_ja3 = set(base.ja3_fingerprints)
    seen_ja3s = set(base.ja3s_fingerprints)

    new_domains = list(base.domains)
    for fqdn in cti_domains_raw:
        key = fqdn.lower().rstrip(".")
        if key in seen_fqdn or not _is_emittable_domain(fqdn):
            continue
        seen_fqdn.add(key)
        # Same scorer as the CAPE path (single source of truth) so CTI-sourced
        # domains are judged identically — and the real reason / scores are
        # preserved (previously overwritten with a generic provenance string).
        verdict = _assess_domain(fqdn)
        reason = verdict.reason
        if verdict.suspicious and reason:
            reason = f"{reason} [Triage CTI]"
        new_domains.append(
            NetworkDomain(
                fqdn=key,
                is_suspicious=verdict.suspicious,
                reason=reason,
                dga_score=verdict.dga_score,
                is_punycode=verdict.is_punycode,
                homograph_target=verdict.homograph_target,
            )
        )

    new_ips = list(base.ips)
    for addr in cti_ips_raw:
        if addr in seen_addr or not _is_emittable_ip(addr):
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

    new_ja3s = list(base.ja3s_fingerprints)
    for ja3s in cti_ja3s_raw:
        if ja3s in seen_ja3s:
            continue
        seen_ja3s.add(ja3s)
        new_ja3s.append(ja3s)

    added = (
        (len(new_domains) - len(base.domains))
        + (len(new_ips) - len(base.ips))
        + (len(new_urls) - len(base.urls))
        + (len(new_ja3) - len(base.ja3_fingerprints))
        + (len(new_ja3s) - len(base.ja3s_fingerprints))
    )
    if added:
        logger.info(
            "network_extractor: merged %d SandboxCTI entries "
            "(domains+%d, ips+%d, urls+%d, ja3+%d, ja3s+%d).",
            added,
            len(new_domains) - len(base.domains),
            len(new_ips) - len(base.ips),
            len(new_urls) - len(base.urls),
            len(new_ja3) - len(base.ja3_fingerprints),
            len(new_ja3s) - len(base.ja3s_fingerprints),
        )

    return NetworkIOCs(
        domains=new_domains,
        ips=new_ips,
        urls=new_urls,
        user_agents=list(base.user_agents),
        ja3_fingerprints=new_ja3,
        ja3s_fingerprints=new_ja3s,
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
