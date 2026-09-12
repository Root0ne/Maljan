"""Printable runs and the typed indicators hiding in them.

Moved here from ``extractors/pe_extractor``, which is where the regexes, the
per-kind quotas and the two "is this really a domain / really a path" filters
grew. They are not PE-specific and never were: the same scan runs over an ELF,
a document, a memory dump or a block of analyst prose. ``pe_extractor`` now
imports them from here and keeps its own ``StringIOC`` construction, so the
report shape is unchanged.

Two entry points are the tool surface: ``strings`` returns the printable runs
with their offsets and encoding, and ``iocs_from_text`` returns the typed
indicators. ``iter_string_iocs`` is the in-process form the extractor calls —
same scan, plain dicts.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

# The shortest run worth calling a string. Six characters is long enough to
# clear the accidental ASCII inside compiled code and short enough to keep a
# four-letter host with a two-letter TLD.
_MIN_STRING_LENGTH = 6
# How many printable runs the scan will look at before giving up. A runaway
# guard, not an output budget — see ``_iter_strings``. Real PEs routinely carry
# tens of thousands of runs and the interesting ones are rarely at the front.
_MAX_STRINGS_SCANNED = 200_000
_MAX_IOC_STRINGS = 120


_URL_RE = re.compile(rb"https?://[A-Za-z0-9._\-/?=&%:#~+]+")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE = re.compile(rb"HK(?:LM|CU|CR|U|CC)[\\\\][A-Za-z0-9_\-\\\\ ./]+")
# NB the single backslashes. This pattern used to read ``[A-Za-z]:\\\\`` and
# ``[...\\\\ ]``, which in a raw bytes literal is an escaped backslash *pair* —
# so it only ever matched paths written with doubled separators, i.e. paths that
# had already been JSON- or C-escaped. A plain ``C:\Users\victim\svchost.exe``,
# which is how a path actually appears in a binary, matched nothing. On a
# Windows-focused analyzer that meant filesystem IOCs were quietly missing from
# every report unless the sample happened to embed escaped text.
_PATH_RE = re.compile(rb"(?:[A-Za-z]:[\\/]|/)[A-Za-z0-9_\-./\\ ]+")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(
    rb"(?<![A-Za-z0-9.])(?:[A-Za-z0-9-]{1,63}\.){1,3}[A-Za-z]{2,24}(?![A-Za-z0-9.])"
)
_MUTEX_RE = re.compile(rb"\\BaseNamedObjects\\[A-Za-z0-9_\-]+")
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LENGTH)
# UTF-16LE runs. Windows binaries are full of wide strings — every ...W API call
# site, every resource string — and the ASCII scan above cannot see them,
# because the interleaved NULs break every run at the first character. Matching
# the pattern and dropping the NULs recovers a whole class of C2 hosts and file
# paths that were previously invisible.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING_LENGTH)

# Credentials and wallets. These are the highest-value strings in a stealer and
# were not extracted at all.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("discord_webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
_WALLET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bitcoin", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("ethereum", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("monero", re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")),
)
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")

# Per-kind budgets, replacing a single global cap.
#
# The old code kept one 80-slot budget and filled it in extraction order — url,
# ip, registry, path, email, mutex, and domain *last*. A binary with a few dozen
# embedded file paths therefore exhausted the budget before a single domain was
# considered, and the C2 host — the thing an analyst actually wants — was
# dropped in favour of `C:\Windows\System32\...`. Quotas make the failure mode
# per-kind and survivable instead of global and silent.
_IOC_QUOTAS: dict[str, int] = {
    "url": 25,
    "domain": 25,
    "ip": 20,
    "secret": 15,
    "crypto_wallet": 10,
    "registry": 20,
    "mutex": 10,
    "email": 10,
    "path": 20,
}


def _iter_strings(blob: bytes) -> Iterator[str]:
    """Yield printable ASCII then UTF-16LE runs, in one pass each.

    This replaces seven independent full-blob regex passes. The old shape was
    workable at seven patterns; at the dozen below it would have meant scanning
    the whole binary a dozen times over, at every one of this module's call
    sites.

    A generator rather than a list, and bounded by ``_MAX_STRINGS_SCANNED``
    rather than by ``_MAX_STRINGS_KEPT``. Those two are not the same number and
    conflating them is a real bug: a mid-size PE holds tens of thousands of
    printable runs, so a scan that stops after the first couple of hundred sees
    only the beginning of the file. The C2 host is rarely in the first two
    hundred strings — the import thunks and the CRT banner are. The scan bound
    exists to stop a pathological input, not to shape the output; the per-kind
    quotas do that, and the caller stops early once they are all full.
    """
    scanned = 0
    for match in _PRINTABLE_RE.finditer(blob):
        yield match.group().decode("ascii", errors="ignore")
        scanned += 1
        if scanned >= _MAX_STRINGS_SCANNED:
            return
    for match in _WIDE_RE.finditer(blob):
        yield match.group()[::2].decode("ascii", errors="ignore")
        scanned += 1
        if scanned >= _MAX_STRINGS_SCANNED:
            return


def iter_string_iocs(blob: bytes) -> list[dict[str, Any]]:
    """Scan binary strings for typed indicators of compromise.

    Rows are ``{"kind": ..., "value": ..., "notes": ...}``; ``notes`` is the
    sub-label a secret or wallet pattern carries and ``None`` otherwise.
    """
    iocs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    per_kind: Counter[str] = Counter()

    def _add(kind: str, decoded: str, notes: str | None = None) -> None:
        decoded = decoded.strip("\x00").strip()
        if len(decoded) < _MIN_STRING_LENGTH:
            return
        key = (kind, decoded.lower())
        if key in seen:
            return
        if per_kind[kind] >= _IOC_QUOTAS.get(kind, 10):
            return
        seen.add(key)
        per_kind[kind] += 1
        iocs.append({"kind": kind, "value": decoded, "notes": notes})

    def _all_quotas_full() -> bool:
        return all(per_kind[kind] >= quota for kind, quota in _IOC_QUOTAS.items())

    for text in _iter_strings(blob):
        # Nothing left to learn — stop walking the binary.
        if _all_quotas_full():
            break
        for match in _URL_RE.findall(text.encode("ascii", errors="ignore")):
            _add("url", match.decode("ascii", errors="ignore"))
        for match in _IP_RE.findall(text.encode("ascii", errors="ignore")):
            ip = match.decode("ascii", errors="ignore")
            # 127.0.0.1 / 0.0.0.0 / RFC1918 filtered as noise
            if _is_meaningful_ip(ip):
                _add("ip", ip)
        for match in _REG_RE.findall(text.encode("ascii", errors="ignore")):
            _add("registry", match.decode("ascii", errors="ignore"))
        for match in _PATH_RE.findall(text.encode("ascii", errors="ignore")):
            candidate = match.decode("ascii", errors="ignore")
            if _looks_like_path(candidate):
                _add("path", candidate)
        for match in _EMAIL_RE.findall(text.encode("ascii", errors="ignore")):
            _add("email", match.decode("ascii", errors="ignore"))
        for match in _MUTEX_RE.findall(text.encode("ascii", errors="ignore")):
            _add("mutex", match.decode("ascii", errors="ignore"))
        for match in _DOMAIN_RE.findall(text.encode("ascii", errors="ignore")):
            candidate = match.decode("ascii", errors="ignore")
            if _looks_like_domain(candidate):
                _add("domain", candidate)
        for label, pattern in _SECRET_PATTERNS:
            for hit in pattern.findall(text):
                _add("secret", hit, notes=label)
        for label, pattern in _WALLET_PATTERNS:
            for hit in pattern.findall(text):
                _add("crypto_wallet", hit, notes=label)
        for hit in _ONION_RE.findall(text):
            _add("domain", hit, notes="tor_hidden_service")

    return iocs[:_MAX_IOC_STRINGS]


def _is_meaningful_ip(ip: str) -> bool:
    """Heuristic filter: only keep IPs that *look like* real public hosts.

    This was tightened from the original RFC1918 +
    loopback filter — the IPv4 regex matched a flood of false positives
    on Go binaries (X.509 ASN.1 OIDs ``2.5.4.62``, the well-known
    ``1.1.1.1`` test constant, etc.). The full picture:

    * Reject any octet > 255 (already enforced).
    * Reject the canonical reserved blocks (loopback, broadcast,
      RFC1918, link-local, multicast, documentation, IETF reserved).
    * Reject ``1.x.x.x`` — Cloudflare's 1.1.1.1 / 1.0.0.1 are real, but
      every Go runtime + IETF doc string also pulls ``1.1.1.1`` /
      ``1.2.3.4`` out, so we drop the whole /8 rather than chase
      false-positives one at a time. Operators who *really* need to
      keep public 1.x.x.x can disable this filter at the caller.
    * Reject any IP whose first octet is in 0..5 — overlaps with X.509
      OID prefixes (``2.5.4.X``, ``5.4.X.X``) and reserved IETF blocks.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False

    a, b, c, d = nums

    # X.509 OID overlap + IETF reserved ranges
    if a <= 5:
        return False
    # RFC1122 loopback
    if a == 127:
        return False
    # RFC1918 private
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    # RFC3927 link-local
    if a == 169 and b == 254:
        return False
    # RFC5737 documentation blocks
    if (
        (a == 192 and b == 0 and c == 2)
        or (a == 198 and b == 51 and c == 100)
        or (a == 203 and b == 0 and c == 113)
    ):
        return False
    # Multicast + reserved
    if a >= 224:
        return False
    # Limited broadcast
    if a == 255 and b == 255 and c == 255 and d == 255:
        return False
    return True


_NON_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # Native binaries
    ".exe",
    ".dll",
    ".sys",
    ".so",
    ".dylib",
    # Source / scripts
    ".py",
    ".js",
    ".c",
    ".h",
    ".cpp",
    ".cxx",
    ".cc",
    ".hpp",
    ".java",
    # Bundled bytecode / archive build artefacts that otherwise surface as
    # bogus DOMAIN matches (resources.arsc, classes.dex, etc.) — deny them.
    ".apk",
    ".aab",
    ".arsc",
    ".dex",
    ".smali",
    ".kotlin_module",
    # Bundled assets shipped inside archives
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".xml",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".html",
    ".htm",
    ".css",
    ".txt",
    ".md",
    ".csv",
    # Java / .NET / Office formats
    ".jar",
    ".class",
    ".war",
    ".ear",
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
    ".pdf",
)


# Framework namespace roots. Deliberately excludes every word that is also a
# plausible registrable name — no "com", "net", "org", "google", "android",
# "core", "base" — because this set is used to *reject*, and a false entry here
# silently discards a real C2 host. `System.Net` must go; `google.com` must not.
_NAMESPACE_TOKENS = frozenset(
    {
        "system",
        "microsoft",
        "windows",
        "runtime",
        "collections",
        "generic",
        "reflection",
        "diagnostics",
        "threading",
        "interopservices",
        "componentmodel",
        "globalization",
        "serialization",
        "regularexpressions",
        "javax",
        "mscorlib",
        "winforms",
        "presentationframework",
    }
)

# Second-level labels of multi-part public suffixes. `example.co.uk` is a real
# hostname whose second-level label is two characters, so the minimum-length
# check below has to know about them.
_MULTIPART_TLD_SECOND_LEVELS = frozenset(
    {"co", "com", "net", "org", "ac", "gov", "edu", "mil", "or", "ne", "in", "web"}
)

# A positive TLD check, complementing the negative suffix list. Without one,
# every dotted identifier whose last label happens to be alphabetic reads as a
# hostname — the concrete example being `System.Collections.Generic`, which was
# emitted as a `domain` IOC on every .NET sample.
#
# Deliberately not the full IANA list: the goal is to reject compile artefacts,
# and a curated set of TLDs that actually appear in malware C2 does that with a
# far smaller false-negative surface than trying to be exhaustive would create
# false positives.
_KNOWN_TLDS = frozenset(
    {
        # generic
        "com",
        "net",
        "org",
        "info",
        "biz",
        "io",
        "co",
        "app",
        "dev",
        "xyz",
        "site",
        "online",
        "store",
        "shop",
        "club",
        "space",
        "website",
        "tech",
        "live",
        "life",
        "world",
        "today",
        "top",
        "icu",
        "cyou",
        "monster",
        "click",
        "link",
        "fun",
        "pw",
        "cc",
        "tv",
        "me",
        "ws",
        "su",
        "sbs",
        "digital",
        "cloud",
        "email",
        "network",
        "systems",
        "services",
        "host",
        "press",
        "wiki",
        "art",
        "blog",
        "page",
        "rest",
        "zone",
        "run",
        "bar",
        # ccTLDs that show up in real C2
        "ru",
        "cn",
        "br",
        "in",
        "ir",
        "ua",
        "pl",
        "de",
        "fr",
        "uk",
        "nl",
        "it",
        "es",
        "tr",
        "jp",
        "kr",
        "vn",
        "id",
        "th",
        "my",
        "ph",
        "hk",
        "tw",
        "sg",
        "za",
        "ng",
        "ke",
        "eg",
        "sa",
        "ae",
        "il",
        "gr",
        "pt",
        "ro",
        "cz",
        "sk",
        "hu",
        "bg",
        "rs",
        "hr",
        "si",
        "lt",
        "lv",
        "ee",
        "fi",
        "se",
        "no",
        "dk",
        "be",
        "at",
        "ch",
        "ie",
        "us",
        "ca",
        "mx",
        "ar",
        "cl",
        "pe",
        "ve",
        "au",
        "nz",
        "kz",
        "by",
        "md",
        "ge",
        "am",
        "az",
        "uz",
        "pk",
        "bd",
        "lk",
        "np",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "to",
        "st",
        "cx",
        "nu",
        "im",
        "gg",
        "je",
        # ".onion" is deliberately absent. Hidden services have a fixed address
        # shape that a dedicated pattern validates, and routing them through the
        # generic domain path would accept any `word.onion` while losing the
        # note that says what it is.
    }
)


def _looks_like_path(text: str) -> bool:
    """Reject path *fragments*, which the regex produces in bulk.

    Found by reading real output rather than by reasoning about it. A scan of
    one sample returned ``/Users``, ``/rd_lee``, ``/.vscode``, ``/extensions``,
    ``/plugin``, ``/const``, ``/errors`` — and ``/Vundo.gen``, ``/Ryuk.P``,
    ``/Obfuse.VAL``, which are AV signature names lifted out of an embedded
    definition database. All of them are what ``/[A-Za-z0-9_...]+`` matches when
    it meets ordinary text containing a slash.

    They were not merely ugly. ``path`` has a 20-slot quota, and filling it with
    single-segment fragments is exactly the starvation the quotas were added to
    prevent — one noisy kind crowding out the useful ones.

    A path earns its slot by having structure: a Windows drive letter, or at
    least two separators. ``/Users`` has neither; ``C:\\Users\\x`` and
    ``/etc/cron.d/persistence`` each have one.

    A file extension deliberately does *not* qualify a single-separator string.
    That exemption was tried and admitted ``/Vundo.gen`` and ``/Obfuse.VAL`` —
    AV signature names, which are ``/Word.ext`` shaped and were being reported
    as filesystem IOCs. A genuinely interesting path essentially always has a
    directory in it.
    """
    stripped = text.strip()
    if len(stripped) < 6:
        return False
    # A slice of a URL is not a path. The regex happily starts matching in the
    # middle of `https://host/x` and yields `s://host/x`, which was appearing in
    # reports beside the URL it was carved out of — the same indicator twice,
    # once mangled.
    if "://" in stripped:
        return False
    # A drive letter is unambiguous.
    if len(stripped) > 2 and stripped[1] == ":" and stripped[0].isalpha():
        return True
    return (stripped.count("/") + stripped.count("\\")) >= 2


# Second-level labels that are code, not hostnames. `self.id` was reported as a
# C2 domain: `.id` is Indonesia's ccTLD and `self` clears every structural check
# there is. No rule about shape can separate `self.id` from `evil.id`, so the
# only honest fix is a short list of the identifiers that actually collide.
_CODE_IDENTIFIER_LABELS = frozenset(
    {
        "self",
        "this",
        "cls",
        "obj",
        "item",
        "items",
        "data",
        "value",
        "values",
        "result",
        "results",
        "config",
        "options",
        "props",
        "state",
        "error",
        "errors",
        "args",
        "kwargs",
        "ctx",
        "req",
        "res",
        "response",
        "request",
        "index",
        "length",
        "name",
        "type",
        "target",
        "source",
        "parent",
        "child",
        "node",
        "root",
        "next",
        "prev",
        "key",
        "keys",
        "attr",
        "attrs",
        "meta",
    }
)


def _looks_like_domain(text: str) -> bool:
    """Filter out obvious non-domain matches (filenames, version strings)."""
    if text.startswith(".") or text.endswith("."):
        return False
    lower = text.lower()
    if any(lower.endswith(suffix) for suffix in _NON_DOMAIN_SUFFIXES):
        return False
    if text.count(".") > 4:
        return False
    if len(text) < 5:
        return False

    labels = lower.split(".")
    if len(labels) < 2:
        return False

    # Positive TLD check. A hostname ends in a real TLD; `Collections.Generic`
    # does not.
    if labels[-1] not in _KNOWN_TLDS:
        return False

    # Namespace shape. Most .NET identifiers die on the TLD check already
    # (`System.Collections.Generic` — "generic" is not a TLD), but the ones
    # whose last segment happens to be a real TLD survive it: `System.Net`,
    # `System.IO`, `Microsoft.Web`. Two signals together catch those without
    # touching real hostnames — a framework root among the non-TLD labels, and
    # PascalCase, which dotted identifiers use and hostnames in binaries
    # essentially never do.
    if any(label in _NAMESPACE_TOKENS for label in labels[:-1]) and text[:1].isupper():
        return False

    # A one-character second-level label is a version fragment, not a
    # registrable name. Two characters are allowed only for the second level of
    # a multi-part public suffix such as `example.co.uk`.
    sld = labels[-2]
    if len(sld) < 2 or (len(sld) == 2 and sld not in _MULTIPART_TLD_SECOND_LEVELS):
        return False

    # `self.id`, `data.io`, `result.co` — a code identifier followed by a short
    # ccTLD. Only applied to two-label candidates: `self.example.com` is a
    # perfectly ordinary hostname and must survive.
    if len(labels) == 2 and sld in _CODE_IDENTIFIER_LABELS:
        return False

    # `MyApplication.app`, `DataContract.io` — a CamelCase identifier wearing a
    # real TLD. Hostnames embedded in binaries are written lowercase; an
    # internal capital is the mark of a type or assembly name. Checked on the
    # original text because the comparison above is lowercased, and only for
    # two-label candidates, so `cdn.MyCorp.com` is left alone.
    if len(labels) == 2:
        original_sld = text.split(".")[0]
        if any(ch.isupper() for ch in original_sld[1:]):
            return False

    return True


# ---------------------------------------------------------------------------
# Tool surface
# ---------------------------------------------------------------------------

# The encodings ``strings`` knows how to walk. ``utf16le`` is not a nicety on a
# Windows binary: every wide API call site and every resource string lives
# there, and an ASCII-only scan cannot see any of it.
_ENCODINGS: tuple[str, ...] = ("ascii", "utf16le")

# One tool call must not try to return a whole binary's worth of text.
_MAX_STRINGS_LIMIT = 20_000

# The shortest run the caller may ask for. Below three characters the scan
# returns essentially every byte of a binary as a "string".
_MIN_REQUESTABLE_LENGTH = 3


@lru_cache(maxsize=32)
def _run_pattern(encoding: str, min_len: int) -> re.Pattern[bytes]:
    """The run regex for one encoding at one minimum length.

    Compiled per requested length rather than filtered after the fact: the
    module-level patterns are fixed at ``_MIN_STRING_LENGTH``, so a caller
    asking for shorter runs than that would silently get the default's — the
    argument would appear to work while only ever narrowing.
    """
    if encoding == "utf16le":
        return re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


def strings(
    path: str,
    min_len: int = _MIN_STRING_LENGTH,
    encodings: tuple[str, ...] = ("ascii", "utf16le"),
    limit: int = 2000,
    offset: int = 0,
) -> dict[str, Any]:
    """Printable runs in a file, with the byte offset each was found at.

    ``offset``/``limit`` page through the runs in scan order (every ASCII run,
    then every UTF-16LE one), so a caller can walk a large binary without ever
    asking for more than one page. ``total`` is how many runs the scan found
    before paging, and ``truncated`` says whether the page is the tail.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "strings"}
    minimum = max(_MIN_REQUESTABLE_LENGTH, int(min_len))
    limit = max(0, min(int(limit), _MAX_STRINGS_LIMIT))
    offset = max(0, int(offset))
    wanted = [enc for enc in encodings if enc in _ENCODINGS]
    if not wanted:
        known = ", ".join(_ENCODINGS)
        return {"error": f"unknown encodings {list(encodings)}; known: {known}", "tool": "strings"}

    blob = target.read_bytes()
    rows: list[dict[str, Any]] = []
    total = 0
    for enc in wanted:
        for match in _run_pattern(enc, minimum).finditer(blob):
            raw = match.group()
            text = raw[::2] if enc == "utf16le" else raw
            decoded = text.decode("ascii", errors="ignore")
            total += 1
            if total <= offset or len(rows) >= limit:
                continue
            rows.append({"offset": match.start(), "enc": enc, "text": decoded})
            if total >= _MAX_STRINGS_SCANNED:
                break
    return {
        "strings": rows,
        "total": total,
        "truncated": total > offset + len(rows),
    }


def iocs_from_text(text: str, kinds: list[str] | None = None) -> dict[str, Any]:
    """The typed indicators in a block of text, optionally narrowed by kind.

    Takes text rather than a path on purpose: the same regexes serve a decoded
    string table, a sandbox log line and an analyst's own paragraph, and a tool
    that insisted on a file could not be pointed at any of them.
    """
    blob = (text or "").encode("utf-8", errors="ignore")
    rows = iter_string_iocs(blob)
    if kinds:
        keep = {str(k).strip().lower() for k in kinds}
        rows = [row for row in rows if row["kind"] in keep]
    return {"iocs": rows, "kinds": sorted({row["kind"] for row in rows})}


def iocs_from_file(path: str, kinds: list[str] | None = None) -> dict[str, Any]:
    """``iocs_from_text`` over a file's bytes, wide strings included."""
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "iocs_from_file"}
    rows = iter_string_iocs(target.read_bytes())
    if kinds:
        keep = {str(k).strip().lower() for k in kinds}
        rows = [row for row in rows if row["kind"] in keep]
    return {"iocs": rows, "kinds": sorted({row["kind"] for row in rows})}
