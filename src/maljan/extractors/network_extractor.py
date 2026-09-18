"""Score a domain, and decide whether an address is worth reporting.

This module used to pull the whole network section out of a sandbox report
inside the report builder. It does not any more — the report is assembled from
what the agents' tools returned — and what is left is the part that was never
extraction: the DGA scorer, the IDN homograph check and the emittable-address
rules that decide whether an observed indicator is worth reporting at all.

``reporting.ledger_projection`` applies the scorer to the domains a run
actually observed, and the score reaches the report as the ``is_suspicious``
flag on an observed domain — a described property of something a tool saw, not
a technique claim asserted over an analyst's head.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

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

# The suffixes a private network names its own machines with. Publishing one is
# a low-value indicator in a shared bundle and a small disclosure of how the
# analysis network is named, so no export carries one — but that is an export
# decision and not a projection one. A sandbox that resolved
# ``fileserver.corp.internal`` watched the sample resolve it, which is the
# thing an analyst reading a lateral-movement case most needs to see, and the
# report's network block keeps the row with its source. ``host_is_private_use``
# is the one reader of these, and it is asked where an indicator is minted and
# where a name is about to be sent to a reputation provider.
#
# ``.internal``, ``.alt`` and ``.home.arpa`` are reserved for the purpose. The
# rest are not reserved by anybody and are used for it anyway, and none of the
# four has ever been delegated, so a name under one cannot be looked up from
# outside the network that invented it.
_PRIVATE_USE_SUFFIXES: tuple[str, ...] = (
    ".internal",
    ".alt",
    ".home.arpa",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
)
_RESERVED_DOMAIN_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


def host_is_private_use(host: Any) -> bool:
    """Whether this name belongs to a private network rather than to the internet.

    One list, two readers. The export asks it before minting an indicator and
    the enrichment asks it before sending a name to a reputation provider, and
    the two answering differently is how ``x.alt`` and
    ``localhost.localdomain`` were held out of one bundle and posted to a
    public provider in the same run.
    """
    name = str(host or "").strip().rstrip(".").lower()
    if not name:
        return True
    if name in _RESERVED_DOMAIN_NAMES:
        return True
    return any(
        name.endswith(suffix) for suffix in _RESERVED_DOMAIN_SUFFIXES + _PRIVATE_USE_SUFFIXES
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

# ---------------------------------------------------------------------------
# DGA scoring
# ---------------------------------------------------------------------------
# A label whose composite score (Shannon entropy + bigram rarity + supporting
# signals) clears this threshold is treated as algorithmically generated
# (surfaced as ``is_suspicious`` in the NETWORK tab).
_DGA_SCORE_THRESHOLD: float = 0.55
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


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DomainVerdict:
    """Outcome of scoring one FQDN — the single source of truth for the
    sandbox-report extractor so every domain is judged identically."""

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


# ---------------------------------------------------------------------------
# IPs
# ---------------------------------------------------------------------------


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


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


# A v3 onion address is the base32 of a 32-byte key, a 2-byte checksum over
# it and a version byte; v2 is sixteen base32 characters and carries no
# checksum, so length and alphabet are all there is to check.
_TOR_SUFFIX = ".onion"
_TOR_V3_LENGTH = 56
_TOR_V2_LENGTH = 16
_TOR_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_TOR_V3_VERSION = 3
_TOR_CHECKSUM_SALT = b".onion checksum"


def tor_hidden_service(fqdn: Any) -> bool:
    """Whether ``fqdn`` is a syntactically valid Tor onion address.

    Checked rather than assumed: a v3 address carries its own checksum, so
    fifty-six characters of the right alphabet are not enough — the last three
    bytes have to check out against the first thirty-two, which is what makes
    the name impossible to produce by accident.
    """
    import base64
    import hashlib

    name = str(fqdn or "").strip().lower().rstrip(".")
    if not name.endswith(_TOR_SUFFIX):
        return False
    label = name[: -len(_TOR_SUFFIX)].rsplit(".", 1)[-1]
    if not label or set(label) - _TOR_ALPHABET:
        return False
    if len(label) == _TOR_V2_LENGTH:
        return True
    if len(label) != _TOR_V3_LENGTH:
        return False
    try:
        # Fifty-six base32 characters are exactly thirty-five bytes, so the
        # encoding needs no padding and adding any would corrupt it.
        decoded = base64.b32decode(label.upper())
    except Exception:  # noqa: BLE001 — a name that will not decode is not one
        return False
    if len(decoded) != 35 or decoded[34] != _TOR_V3_VERSION:
        return False
    public_key, checksum = decoded[:32], decoded[32:34]
    expected = hashlib.sha3_256(
        _TOR_CHECKSUM_SALT + public_key + bytes([_TOR_V3_VERSION])
    ).digest()[:2]
    return checksum == expected


def corroboration_reason(source: Any, reputation: Any, fqdn: Any = "") -> str | None:
    """Why this name may be published, or ``None`` when nothing says it may.

    Named rather than left implicit because one of the answers is surprising:
    a Tor address is published on the strength of its own syntax, and a reader
    finding it in a bundle beside no sandbox observation is owed the reason.
    """
    if source != "strings":
        return str(source) if source else "recorded without a source"
    if tor_hidden_service(fqdn):
        return "tor hidden service address, valid on its own syntax"
    if isinstance(reputation, dict):
        for key in ("malicious", "suspicious"):
            try:
                if int(reputation.get(key) or 0) > 0:
                    return "a reputation provider has a record of it"
            except (TypeError, ValueError):
                continue
    return None


def url_host(raw_url: Any) -> str:
    """The host of a URL, lowercased, or ``""`` when it has none."""
    from urllib.parse import urlparse

    try:
        return (urlparse(str(raw_url or "")).hostname or "").strip().lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


# One DNS label: letters, digits and hyphens, not starting or ending with a
# hyphen, at most sixty-three characters. The internet's own rule, which is the
# only rule that can be applied to a name nobody has tried to resolve.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# The last label of a name that could exist: two or more letters, or a
# punycode label. Deliberately a shape and not a list — a 136-entry list of
# TLDs omits `gov`, `edu`, `mobi`, every punycode TLD and most African and
# Middle-Eastern ccTLDs, and a sandbox-observed request to a university host is
# not a string sweep's cut-off.
_PUBLIC_SUFFIX_RE = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$")


def host_is_public(host: Any) -> bool:
    """Whether ``host`` is a name or address that could exist on the internet.

    A string sweep cuts hostnames wherever the surrounding bytes end, and the
    pieces are shaped like URLs: ``http://localho``, ``https://q``,
    ``http://3271``. Five of them were published as STIX indicators in one live
    run, each one something a consumer would block on.

    This asks one question only — could anything ever answer for this host —
    and it is deliberately the weakest question in the chain. Whether an
    endpoint that *could* exist is published is
    :func:`corroboration_reason`'s decision, not this one, so a plausible name
    the file's bytes alone know about is still held back for want of a second
    source rather than for the shape of its name.

    A Tor address is first, and for the reason it is first everywhere else:
    ``.onion`` never resolves, its own checksum is the only thing that can
    confirm it, and holding it to any other rule makes the strongest
    string-derived indicator there is unpublishable by every path.
    """
    name = str(host or "").strip().lower().rstrip(".")
    if not name:
        return False
    if name.endswith(_TOR_SUFFIX):
        # The suffix is reserved for hidden services and nothing else can ever
        # answer under it, so the checksum is the whole question: a valid
        # address is a host, and a name that merely ends in ``.onion`` is not.
        return tor_hidden_service(name)
    try:
        address = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        return not (address.is_loopback or address.is_unspecified or address.is_link_local)
    if not _is_emittable_domain(name) or host_is_private_use(name):
        return False
    labels = name.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        return False
    return bool(_PUBLIC_SUFFIX_RE.match(labels[-1]))


def url_corroboration_reason(raw_url: Any, source: Any, reputation: Any = None) -> str | None:
    """Why this URL may be published, or ``None`` when nothing says it may.

    The same rule the domains go through, asked of the URL's host, plus the
    syntactic question above — which no source can answer for: a cut-off host
    is not an endpoint whoever recorded it meant, whatever recorded it.
    """
    host = url_host(raw_url)
    if not host_is_public(host):
        return None
    return corroboration_reason(source, reputation, host)


# The addresses a document, a specification or an example reserves. Python reads
# them as private, which is not the same answer: a private address a sandbox
# really watched is lateral traffic worth publishing, and one of these is
# nobody's infrastructure whoever recorded it.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# The shared address space a carrier puts between its subscribers and the
# internet. It is somebody's infrastructure the way a private range is — the
# sandbox can really reach one — and it is nobody's the way a version number
# is, so it belongs beside the private ranges rather than among the addresses
# that are never published. Named rather than reached through ``is_private``,
# which answers False for it.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# The address every reader of the report would recognise as not an endpoint.
_BROADCAST_ADDRESS = "255.255.255.255"


def address_is_publishable(address: Any, source: Any = None) -> bool:
    """Whether this address could be infrastructure somebody should act on.

    The classes that are never an indicator, whoever recorded them: loopback,
    unspecified, link-local, multicast, the broadcast address, anything the
    registries reserve, and the ranges a document or an example is written
    with. A private address is the one that depends on who saw it — a sandbox
    watching a sample reach 10.0.0.5 is lateral movement and worth publishing,
    while the same run of digits out of a string sweep is a version number
    somebody typed with dots in it.
    """
    try:
        parsed = ipaddress.ip_address(str(address or "").strip().strip("[]"))
    except ValueError:
        return False
    if (
        parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_link_local
        or parsed.is_unspecified
        or parsed.is_reserved
        or str(parsed) == _BROADCAST_ADDRESS
    ):
        return False
    if any(parsed in network for network in _DOCUMENTATION_NETWORKS):
        return False
    if parsed.is_private or parsed in _SHARED_ADDRESS_SPACE:
        return str(source or "").strip().lower() not in ("", "strings")
    return True


def ip_corroboration_reason(address: Any, source: Any, reputation: Any = None) -> str | None:
    """Why this address may be published, or ``None`` when nothing says it may.

    The predicate the domains and the URLs already go through, asked of an
    address, so the three network kinds answer one rule rather than three. A
    string sweep turns any run of digits with dots in it into an "IP" — one
    live bundle published ``6.0.0.0``, a version number out of the strings
    table — and until this the IPs were the one kind with no gate at all.
    """
    if not address_is_publishable(address, source):
        return None
    return corroboration_reason(source, reputation, str(address))


def domain_is_corroborated(source: Any, reputation: Any, fqdn: Any = "") -> bool:
    """Whether anything but the sample's own byte image knows this name.

    A string sweep turns any run of bytes shaped like a hostname into a
    "domain": a truncated resource left `rosoft.com` beside `microsoft.com`,
    an identifier table left `jector.SA`. Those are strings, and the report
    prints them as strings. Publishing them as indicators, or spending a paid
    reputation lookup on each, states something no one observed.

    Corroboration is a second source: the sandbox resolved the name, an
    analyst put it in an artefact, or a reputation provider has a record that
    names it. A source this layer does not know about is left alone — only
    ``strings`` is held back.

    A Tor address is the exception, and it has to be: `.onion` does not
    resolve, so no sandbox can ever confirm one, and holding it to this rule
    made the strongest string-derived indicator there is unpublishable by any
    path. Its own syntax is the second source. It stays labelled ``strings``
    and it is still never sent to a paid provider, which has no record of a
    hidden service either.
    """
    return corroboration_reason(source, reputation, fqdn) is not None


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
