"""ThreatIntel MCP Server — VirusTotal + AbuseIPDB integration.

Usage:
    uv run python services/threatintel-mcp/server.py

Environment:
    VIRUSTOTAL_API_KEY — VirusTotal API v3 key (hash and domain lookups, and addresses)
    ABUSEIPDB_API_KEY — AbuseIPDB API v2 key (addresses)

A lookup with no key for its service answers nothing of its own: its manifest
cell says the key is not configured, so the platform withholds the tool, and a
call that reaches it anyway answers the structured ``not_configured`` error.
There is no fallback that answers in the service's place.

Every indicator is checked for its shape (an IP address, a DNS name, an MD5,
SHA-1 or SHA-256 hex digest) before any request is built from it; anything
else is refused with a ``bad_argument`` error that says what was expected.

``check_hash`` answers a JSON document whose counts are the service's own
numbers under fixed keys (``last_analysis_stats``); text from the service's
data about the sample (a submitted file name) sits under keys of its own and
is never where a count is read.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
import idna
from mcp.server.fastmcp import FastMCP

from maljan.core.stdio_safe import route_logging_to_stderr

# Only when run as the stdio server: a test or tool that imports this module
# in-process keeps its own logging.
if __name__ == "__main__":
    route_logging_to_stderr()

from maljan.tools.arguments import says_unquoted, unquoted, with_read_as
from maljan.tools.capabilities import (
    CAPABILITIES_TOOL,
    Requirement,
    ToolNeeds,
    env,
    manifest,
)
from maljan.tools.errors import (
    BAD_ARGUMENT,
    NOT_CONFIGURED,
    TIMEOUT,
    TOOL_FAILED,
    error_parts,
    error_sentence,
    tool_error,
)

mcp = FastMCP("ThreatIntelMCP")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

# The wall clock every lookup on this server gives the network. Named once, so
# the client that enforces it and the manifest that declares it cannot drift:
# a console told "no timeout" for a call that gives up after fifteen seconds
# is being told something untrue by the one structure whose premise is that it
# was computed rather than claimed.
HTTP_TIMEOUT_S = 15.0

# Minimal in-memory cache to avoid hammering APIs during testing
_cache: dict[str, Any] = {}

# The service a hash lookup's answer is attributed to (``check_hash``'s
# ``service`` key).
VT_SERVICE = "VirusTotal"

# The shapes an indicator is checked against before a request is built from it.
# A hash is a hex digest of one of these lengths (MD5, SHA-1, SHA-256).
HASH_HEX_LENGTHS: dict[int, str] = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_HEX = re.compile(r"[0-9A-Fa-f]+")
# A DNS name: at most 253 characters, labels of 1 to 63 letters, digits,
# hyphens or underscores (an underscore label is common in malware's names),
# not starting or ending with a hyphen, and at least two labels.
DNS_NAME_MAX_CHARS = 253
DNS_LABEL_MAX_CHARS = 63
_DNS_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?")


def _ip_keys() -> tuple[Requirement, ...]:
    """What an address lookup needs: either key answers one.

    The keys that are set, so a host with only one is not told it lacks the
    other; both when neither is, which is what the reason then names.
    """
    keys = (env("VIRUSTOTAL_API_KEY"), env("ABUSEIPDB_API_KEY"))
    held = tuple(key for key in keys if key.probe() is None)
    return held or keys


# Every lookup needs its service's key and answers nothing without it: there
# is no fallback, so the manifest marks it unavailable and the platform
# withholds it, with the reason and the remedy.
TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds(
        "check_ip_reputation",
        _ip_keys(),
        timeout_s=HTTP_TIMEOUT_S,
        remediation=(
            "set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY (either answers an address) "
            "in Settings and run the probe again"
        ),
    ),
    ToolNeeds("check_domain_reputation", (env("VIRUSTOTAL_API_KEY"),), timeout_s=HTTP_TIMEOUT_S),
    ToolNeeds("check_hash", (env("VIRUSTOTAL_API_KEY"),), timeout_s=HTTP_TIMEOUT_S),
    ToolNeeds("get_threatintel_status"),
]
CAPABILITIES = manifest("threatintel", TOOL_NEEDS)


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, the setting it needs, and whether it is configured.
    """
    # Deep, so "computed once when the server started" also means a
    # caller cannot reach in and change what it says.
    return copy.deepcopy(CAPABILITIES)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vt_headers() -> dict[str, str]:
    return {"x-apikey": VT_API_KEY}


def _abuseipdb_headers() -> dict[str, str]:
    return {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}


def tool_error_text(code: str, message: str, tool: str) -> str:
    """One structured failure as the text these prose-answering tools return."""
    return json.dumps(tool_error(code, message, tool=tool))


def _lookup_error(code: str, message: str, tool: str) -> str:
    """A failed lookup as the structured error, in the text these tools return.

    These four answer with prose, so a failure that is also prose reads to
    every consumer as an answer: a rate-limited or timed-out lookup was
    recorded as a successful call whose result happened to say "timeout", and
    it never reached the run summary's failures, the report header or the
    console's failed row. The structured shape is what tells them apart, and
    ``normalise_error`` gives it the remedy for its code.
    """
    return tool_error_text(code, message, tool)


def _not_configured(tool: str) -> str:
    """The answer of a lookup whose service has no key: the error, never a stand-in.

    The reason and the remedy are the tool's manifest cell's, so the error a
    call gets and the manifest that withheld the tool say the same thing.
    """
    cell: dict[str, Any] = next((c for c in CAPABILITIES["tools"] if c["name"] == tool), {})
    reason = str(cell.get("reason") or f"{tool} has no service key configured")
    remediation = cell.get("remediation")
    return json.dumps(
        tool_error(
            NOT_CONFIGURED,
            f"{reason}; this lookup answers nothing without it.",
            tool=tool,
            remediation=str(remediation) if remediation else None,
        )
    )


def _refused(value: str, expected: str, tool: str) -> str:
    """A value that is not the indicator the tool looks up, refused before any request."""
    shown = json.dumps(value[: DNS_NAME_MAX_CHARS + 1])
    return tool_error_text(BAD_ARGUMENT, f"{shown} is not {expected}; nothing was looked up.", tool)


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``value`` as one address, or ``None``.

    An IPv6 zone (``fe80::1%eth0``) is refused: ``ipaddress`` accepts any text
    after the ``%`` and keeps it in ``str()``, and a zone names an interface on
    the asking host, never an address a reputation service knows. An IPv6
    address is rebuilt from its 128 bits alone, so nothing of the text given
    reaches the request, and an IPv4-mapped one is read as its IPv4 address.
    """
    text = value.strip()
    if "%" in text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.scope_id is not None:
            return None
        if parsed.ipv4_mapped is not None:
            return ipaddress.IPv4Address(int(parsed.ipv4_mapped))
        return ipaddress.IPv6Address(int(parsed))
    return ipaddress.IPv4Address(int(parsed))


def ip_shape(value: str) -> str | None:
    """``value`` as a canonical IPv4 or IPv6 address, or ``None`` when it is not one."""
    parsed = _address(value)
    return None if parsed is None else str(parsed)


def is_public(address: str) -> bool:
    """Whether a canonical address is a public one a reputation service can know.

    A private, loopback, link-local, multicast, reserved or documentation
    address is the asking side's own or no host's at all: sending it is a leak
    of the operator's network and the answer is nothing about the sample.
    """
    parsed = _address(address)
    return parsed is not None and parsed.is_global and not parsed.is_multicast


def _segment(value: str, safe: str = "") -> str:
    """``value`` as one URL path segment: every character but letters, digits,
    ``_.-~`` and ``safe`` percent-encoded, so no ``/``, ``?``, ``#`` or ``%`` in it
    can change the request.

    The values reaching here are already checked for their shape; this is the
    second wall, for every value placed in a VirusTotal path.
    """
    return quote(value, safe=safe)


# The one character a canonical IPv6 address carries besides hex digits, kept
# as written in its path segment.
_IPV6_SEPARATOR = ":"


def _address_segment(address: str) -> str:
    """A canonical address as its path segment: an IPv6 address keeps its colons."""
    parsed = _address(address)
    safe = _IPV6_SEPARATOR if isinstance(parsed, ipaddress.IPv6Address) else ""
    return _segment(address, safe=safe)


def _numeric_label(label: str) -> bool:
    """A label that reads as a number (decimal, or ``0x`` hex): a resolver may read the
    whole name as an address (``0x7f.1``, ``127.1``), so it is no DNS name."""
    lowered = label.lower()
    if lowered.isdigit():
        return True
    return lowered.startswith("0x") and all(ch in "0123456789abcdef" for ch in lowered[2:])


def domain_shape(value: str) -> str | None:
    """``value`` as a DNS name (lowercased, an IDN in its ASCII form), or ``None``.

    One trailing dot (the root) is dropped. An address is not a name, nor is a
    name whose last label reads as a number: each is looked up by the address
    tool, or not at all.
    """
    name = value.strip()
    if name.endswith(".") and not name.endswith(".."):
        name = name[:-1]
    if not name or _address(name) is not None:
        return None
    if not name.isascii():
        # An IDN in its ASCII form, only when that form reads back as the name
        # given: a mapping that drops or replaces a character (a zero-width
        # space, a full-width letter) would look up another name than the one
        # the sample holds.
        try:
            ascii_name = idna.encode(name, uts46=True).decode("ascii")
            if idna.decode(ascii_name) != name.lower():
                return None
        except (idna.IDNAError, UnicodeError):
            return None
        name = ascii_name
    if len(name) > DNS_NAME_MAX_CHARS:
        return None
    labels = name.split(".")
    if len(labels) < 2 or _numeric_label(labels[-1]):
        return None
    for label in labels:
        if len(label) > DNS_LABEL_MAX_CHARS or not _DNS_LABEL.fullmatch(label):
            return None
    return name.lower()


def hash_shape(value: str) -> str | None:
    """``value`` as a lowercase MD5, SHA-1 or SHA-256 hex digest, or ``None``."""
    digest = value.strip()
    if len(digest) not in HASH_HEX_LENGTHS or not _HEX.fullmatch(digest):
        return None
    return digest.lower()


_HASH_EXPECTED = "a hex digest of " + ", ".join(
    f"{length} characters ({name})" for length, name in sorted(HASH_HEX_LENGTHS.items())
)
_IP_EXPECTED = "an IPv4 or IPv6 address"
_PUBLIC_EXPECTED = (
    "a public address (a private, loopback, link-local, multicast, reserved or "
    "documentation address is not looked up)"
)
_DOMAIN_EXPECTED = (
    f"a DNS name (labels of letters, digits, hyphens or underscores, at most "
    f"{DNS_LABEL_MAX_CHARS} characters each, {DNS_NAME_MAX_CHARS} in all, the last "
    f"not a number)"
)


def _cache_key(prefix: str, query: str) -> str:
    return f"{prefix}:{hashlib.sha256(query.encode()).hexdigest()[:16]}"


def _check_cache(prefix: str, query: str) -> str | None:
    key = _cache_key(prefix, query)
    return _cache.get(key)


def _set_cache(prefix: str, query: str, value: str) -> None:
    """Keep an answer. A failure is not an answer and is never kept.

    The cache has no expiry, so one timed-out lookup cached as a failure would
    be replayed for every later look at that indicator for the life of the
    server — and every replay is another failed ledger entry and another row
    in the report header, for a service that came back a second later.
    """
    if error_parts(value) is not None:
        return
    _cache[_cache_key(prefix, query)] = value


def _with_read_as(answer: str, argument: str, given: str, read: str) -> str:
    """``answer`` saying first what a quoted argument was read as, when it was quoted.

    Every answer of these tools is a JSON object, an error included; the key is
    added only where the reading changed the value given.
    """
    if read == given:
        return answer
    try:
        document = json.loads(answer)
    except (TypeError, ValueError):
        return answer
    if not isinstance(document, dict):
        return answer
    return json.dumps(with_read_as(document, {argument: read}))


# ---------------------------------------------------------------------------
# Reading a service's counts
# ---------------------------------------------------------------------------


def _whole_counts(stats: Any) -> dict[str, int]:
    """The whole-number counts of a ``last_analysis_stats`` object, as the service wrote them.

    A count the service did not give is absent, never 0; counts that add up
    to no engine are none at all (``{}``), since no engine analysed it.
    """
    if not isinstance(stats, dict):
        return {}
    counts = {
        str(name): value
        for name, value in stats.items()
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }
    return counts if sum(counts.values()) else {}


def _engine_summary(counts: dict[str, int]) -> str:
    """The answer's own sentence, from the counts alone (nothing of the sample's text).

    No counts, or counts that add up to no engine, give no verdict: no engine
    analysed it, which is not "clean".
    """
    total = sum(counts.values())
    if not counts or total == 0:
        return f"no engine analysed it: {VT_SERVICE} gave no analysis counts."
    if "malicious" not in counts:
        return f"{VT_SERVICE} gave no malicious count ({total} engines counted)."
    malicious = counts["malicious"]
    suspicious = counts.get("suspicious")
    verdict = "malicious" if malicious else "suspicious" if suspicious else "clean"
    said = f"{verdict} — {malicious}/{total} malicious"
    if suspicious is not None:
        said += f", {suspicious}/{total} suspicious"
    return said + "."


def _attributes(resp: httpx.Response) -> dict[str, Any]:
    data = resp.json()
    held = data.get("data") if isinstance(data, dict) else None
    attrs = held.get("attributes") if isinstance(held, dict) else None
    return attrs if isinstance(attrs, dict) else {}


def _not_found(key: str, value: str, what: str, service: str = VT_SERVICE) -> str:
    """An answer, not a failure: the service has nothing on this indicator."""
    return json.dumps(
        {
            key: value,
            "service": service,
            "found": False,
            "summary": f"{what} {value} not found in {service} database.",
        }
    )


def _vt_failure(exc: Exception, what: str, value: str, tool: str) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return _lookup_error(
            TIMEOUT,
            f"VirusTotal did not answer for {what} {value} within {HTTP_TIMEOUT_S:.0f} s.",
            tool,
        )
    if isinstance(exc, httpx.HTTPStatusError):
        return _lookup_error(
            TOOL_FAILED, f"VirusTotal answered {exc.response.status_code} for {what} {value}.", tool
        )
    return _lookup_error(
        TOOL_FAILED, f"VirusTotal lookup failed for {value}: {type(exc).__name__}", tool
    )


def _vt_get(url: str, tool: str) -> httpx.Response | str:
    """The service's response, or the structured failure of a key it refused."""
    with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
        resp = client.get(url, headers=_vt_headers())
    if resp.status_code == 401:
        return _lookup_error(NOT_CONFIGURED, "VirusTotal API key invalid or quota exceeded.", tool)
    return resp


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------


def _vt_ip_lookup(ip_address: str) -> str:
    """Query VirusTotal for IP reputation; answers JSON (counts under ``last_analysis_stats``)."""
    tool = "check_ip_reputation"
    url = f"{VT_BASE}/ip_addresses/{_address_segment(ip_address)}"
    try:
        resp = _vt_get(url, tool)
        if isinstance(resp, str):
            return resp
        if resp.status_code == 404:
            return _not_found("ip", ip_address, "IP")
        resp.raise_for_status()
        attrs = _attributes(resp)
        counts = _whole_counts(attrs.get("last_analysis_stats"))
        return json.dumps(
            {
                "ip": ip_address,
                "service": VT_SERVICE,
                "found": True,
                "summary": _engine_summary(counts),
                "last_analysis_stats": counts,
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "network": attrs.get("network"),
            }
        )
    except Exception as exc:
        return _vt_failure(exc, "IP", ip_address, tool)


def _vt_domain_lookup(domain: str) -> str:
    """Query VirusTotal for domain reputation; answers JSON (counts: ``last_analysis_stats``)."""
    tool = "check_domain_reputation"
    url = f"{VT_BASE}/domains/{_segment(domain)}"
    try:
        resp = _vt_get(url, tool)
        if isinstance(resp, str):
            return resp
        if resp.status_code == 404:
            return _not_found("domain", domain, "Domain")
        resp.raise_for_status()
        attrs = _attributes(resp)
        counts = _whole_counts(attrs.get("last_analysis_stats"))
        categories = attrs.get("categories")
        return json.dumps(
            {
                "domain": domain,
                "service": VT_SERVICE,
                "found": True,
                "summary": _engine_summary(counts),
                "last_analysis_stats": counts,
                "categories": categories if isinstance(categories, dict) else {},
            }
        )
    except Exception as exc:
        return _vt_failure(exc, "domain", domain, tool)


def _vt_hash_lookup(file_hash: str) -> str:
    """Query VirusTotal for file hash reputation; ``file_hash`` already checked by ``hash_shape``.

    Answers a JSON document: the counts under ``last_analysis_stats`` as the
    service gave them, and the service's text about the file (a submitted
    name, a type) under keys of their own, where no count is ever read.
    """
    tool = "check_hash"
    url = f"{VT_BASE}/files/{_segment(file_hash)}"
    try:
        resp = _vt_get(url, tool)
        if isinstance(resp, str):
            return resp
        if resp.status_code == 404:
            return _not_found("hash", file_hash, "Hash")
        resp.raise_for_status()
        attrs = _attributes(resp)
        counts = _whole_counts(attrs.get("last_analysis_stats"))
        names = attrs.get("names")
        answer: dict[str, Any] = {
            "hash": file_hash,
            "service": VT_SERVICE,
            "found": True,
            "summary": _engine_summary(counts),
            "last_analysis_stats": counts,
            "file": {
                "name": names[0] if isinstance(names, list) and names else None,
                "type_description": attrs.get("type_description"),
                "size": attrs.get("size"),
            },
        }
        return json.dumps(answer)
    except Exception as exc:
        return _vt_failure(exc, "hash", file_hash, tool)


# ---------------------------------------------------------------------------
# AbuseIPDB helpers
# ---------------------------------------------------------------------------

ABUSEIPDB_SERVICE = "AbuseIPDB"
# The reports AbuseIPDB counts: those of the last this many days.
ABUSEIPDB_MAX_AGE_DAYS = 90
# AbuseIPDB's confidence (0-100) at which the answer calls an address
# malicious, and at which suspicious.
ABUSE_MALICIOUS_AT = 75
ABUSE_SUSPICIOUS_AT = 25


def _abuse_summary(score: int | None, reports: int | None) -> str:
    """AbuseIPDB's answer in one sentence; no score, or no report, gives no verdict."""
    if score is None:
        return f"{ABUSEIPDB_SERVICE} gave no confidence score."
    if not reports:
        return f"no report: {ABUSEIPDB_SERVICE} holds no report on it (confidence {score}%)."
    verdict = (
        "malicious"
        if score >= ABUSE_MALICIOUS_AT
        else "suspicious"
        if score >= ABUSE_SUSPICIOUS_AT
        else "clean"
    )
    return f"{verdict} — {ABUSEIPDB_SERVICE} confidence {score}% ({reports} reports)."


def _whole(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _abuseipdb_lookup(ip_address: str) -> str:
    """Query AbuseIPDB for IP reputation; answers JSON, a score it did not give left absent."""
    tool = "check_ip_reputation"
    url = f"{ABUSEIPDB_BASE}/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": str(ABUSEIPDB_MAX_AGE_DAYS)}
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
            resp = client.get(url, headers=_abuseipdb_headers(), params=params)
        if resp.status_code == 401:
            return _lookup_error(NOT_CONFIGURED, "AbuseIPDB API key invalid.", tool)
        resp.raise_for_status()
        data = resp.json()
        held = data.get("data") if isinstance(data, dict) else None
        d = held if isinstance(held, dict) else {}
        score = _whole(d.get("abuseConfidenceScore", d.get("abuseConfidencePercentage")))
        reports = _whole(d.get("totalReports"))
        answer: dict[str, Any] = {
            "ip": ip_address,
            "service": ABUSEIPDB_SERVICE,
            "found": True,
            "summary": _abuse_summary(score, reports),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "last_reported": d.get("lastReportedAt"),
        }
        if score is not None:
            answer["abuse_confidence"] = score
        if reports is not None:
            answer["total_reports"] = reports
        return json.dumps(answer)
    except httpx.TimeoutException:
        return _lookup_error(
            TIMEOUT,
            f"AbuseIPDB did not answer for IP {ip_address} within {HTTP_TIMEOUT_S:.0f} s.",
            tool,
        )
    except httpx.HTTPStatusError as exc:
        return _lookup_error(
            TOOL_FAILED, f"AbuseIPDB answered {exc.response.status_code} for IP {ip_address}.", tool
        )
    except Exception as exc:
        return _lookup_error(
            TOOL_FAILED, f"AbuseIPDB lookup failed for {ip_address}: {type(exc).__name__}", tool
        )


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


def _joined(parts: list[str], tool: str, ip_address: str) -> str:
    """Two sources as one answer, or one failure when neither answered.

    If every source failed, the answer is the first failure, whole and
    parseable. If one answered, the answer is one JSON object: each source's
    answer under ``answers`` and each failure's sentence under ``failed``, so
    a failure never reads as an answer and no document is glued to another.
    """
    failures = [(part, error_parts(part)) for part in parts]
    answered = [part for part, failure in failures if failure is None]
    if not answered:
        return parts[0] if parts else tool_error_text(TOOL_FAILED, "no source answered", tool)
    answers: list[Any] = []
    for part in answered:
        try:
            answers.append(json.loads(part))
        except (TypeError, ValueError):
            answers.append({"summary": part})
    joined: dict[str, Any] = {"ip": ip_address, "answers": answers}
    failed = [str(error_sentence(part)) for part, failure in failures if failure is not None]
    if failed:
        joined["failed"] = failed
    return json.dumps(joined)


def _every_part_answered(text: str, parts: list[str]) -> bool:
    """Whether the joined answer is safe to keep.

    A mixed result carries one source's failure sentence in it, and the cache
    has no expiry: keeping it would replay "VirusTotal did not answer" for
    every later look at that indicator for the life of the server, long after
    VirusTotal came back.
    """
    return all(error_parts(part) is None for part in parts) and error_parts(text) is None


@mcp.tool()
@says_unquoted("ip_address")
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of a public IP address.

    Queries VirusTotal and AbuseIPDB, each when its API key is set; with
    neither, answers a not_configured error. Answers JSON: ``ip`` and each
    service's answer under ``answers`` (its ``summary``, VirusTotal's engine
    counts under ``last_analysis_stats``, AbuseIPDB's ``abuse_confidence``),
    with any service that failed under ``failed``. A value that is not an IPv4
    or IPv6 address, or an address that is not public, is refused.
    """
    given = ip_address
    asked = unquoted(given)
    address = ip_shape(asked)
    if address is None:
        return _with_read_as(
            _refused(asked, _IP_EXPECTED, "check_ip_reputation"), "ip_address", given, asked
        )
    if not is_public(address):
        return _with_read_as(
            _refused(address, _PUBLIC_EXPECTED, "check_ip_reputation"), "ip_address", given, asked
        )
    cached = _check_cache("ip", address)
    if cached:
        return _with_read_as(cached, "ip_address", given, asked)

    parts = []
    if VT_API_KEY:
        parts.append(_vt_ip_lookup(address))
    if ABUSEIPDB_API_KEY:
        parts.append(_abuseipdb_lookup(address))
    if not parts:
        return _with_read_as(_not_configured("check_ip_reputation"), "ip_address", given, asked)

    result = _joined(parts, "check_ip_reputation", address)
    if _every_part_answered(result, parts):
        _set_cache("ip", address, result)
    return _with_read_as(result, "ip_address", given, asked)


@mcp.tool()
@says_unquoted("domain")
def check_domain_reputation(domain: str) -> str:
    """Check the reputation of a domain.

    Queries VirusTotal; without its API key, answers a not_configured error.
    Answers JSON: ``domain`` (an IDN in its ASCII form), ``service``,
    ``found``, ``summary``, the engine counts under ``last_analysis_stats``
    and ``categories``. A value that is not a DNS name is refused.
    """
    given = domain
    asked = unquoted(given)
    name = domain_shape(asked)
    if name is None:
        return _with_read_as(
            _refused(asked, _DOMAIN_EXPECTED, "check_domain_reputation"), "domain", given, asked
        )
    if not VT_API_KEY:
        return _with_read_as(_not_configured("check_domain_reputation"), "domain", given, asked)
    cached = _check_cache("domain", name)
    if cached:
        return _with_read_as(cached, "domain", given, asked)

    result = _vt_domain_lookup(name)
    _set_cache("domain", name, result)
    return _with_read_as(result, "domain", given, asked)


@mcp.tool()
@says_unquoted("file_hash")
def check_hash(file_hash: str) -> str:
    """Check the reputation of a file hash (MD5, SHA1, or SHA256).

    Queries VirusTotal; without its API key, answers a not_configured error.
    Answers JSON: ``hash``, ``service``, ``found``, ``summary``, the engine
    counts under ``last_analysis_stats``, and the service's details of the
    file under ``file``. A value that is not a hex digest of 32, 40 or 64
    characters is refused.
    """
    given = file_hash
    asked = unquoted(given)
    digest = hash_shape(asked)
    if digest is None:
        return _with_read_as(
            _refused(asked, _HASH_EXPECTED, "check_hash"), "file_hash", given, asked
        )
    if not VT_API_KEY:
        return _with_read_as(_not_configured("check_hash"), "file_hash", given, asked)
    cached = _check_cache("hash", digest)
    if cached:
        return _with_read_as(cached, "file_hash", given, asked)

    result = _vt_hash_lookup(digest)
    _set_cache("hash", digest, result)
    return _with_read_as(result, "file_hash", given, asked)


@mcp.tool()
def get_threatintel_status() -> str:
    """Return the current status of ThreatIntel MCP integrations."""
    services = []
    vt_status = (
        "configured"
        if VT_API_KEY
        else "not configured (set VIRUSTOTAL_API_KEY; no lookup answers in its place)"
    )
    abuse_status = (
        "configured"
        if ABUSEIPDB_API_KEY
        else "not configured (set ABUSEIPDB_API_KEY; no lookup answers in its place)"
    )
    services.append(f"VirusTotal: {vt_status}")
    services.append(f"AbuseIPDB: {abuse_status}")
    services.append(f"Cache entries: {len(_cache)}")
    return "\n".join(services)


if __name__ == "__main__":
    mcp.run(transport="stdio")
