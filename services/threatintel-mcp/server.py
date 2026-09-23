"""ThreatIntel MCP Server — VirusTotal + AbuseIPDB integration with mock fallback.

Usage:
    uv run python services/threatintel-mcp/server.py

Environment:
    VIRUSTOTAL_API_KEY — VirusTotal API v3 key (optional, mock fallback if missing)
    ABUSEIPDB_API_KEY — AbuseIPDB API v2 key (optional, mock fallback if missing)
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from maljan.tools.arguments import says_unquoted, unquoted
from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, env, manifest
from maljan.tools.errors import (
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

# Every lookup answers without a key, from heuristic mock data; what the key
# buys is the real service, and that is what the manifest says is missing.
TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds(
        "check_ip_reputation",
        (env("VIRUSTOTAL_API_KEY"), env("ABUSEIPDB_API_KEY")),
        timeout_s=HTTP_TIMEOUT_S,
        without="heuristic mock data",
    ),
    ToolNeeds(
        "check_domain_reputation",
        (env("VIRUSTOTAL_API_KEY"),),
        timeout_s=HTTP_TIMEOUT_S,
        without="heuristic mock data",
    ),
    ToolNeeds(
        "check_hash",
        (env("VIRUSTOTAL_API_KEY"),),
        timeout_s=HTTP_TIMEOUT_S,
        without="heuristic mock data",
    ),
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


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------


def _vt_ip_lookup(ip_address: str) -> str:
    """Query VirusTotal for IP reputation."""
    url = f"{VT_BASE}/ip_addresses/{ip_address}"
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return _lookup_error(
                NOT_CONFIGURED,
                "VirusTotal API key invalid or quota exceeded.",
                "check_ip_reputation",
            )
        if resp.status_code == 404:
            # An answer, not a failure: VirusTotal has nothing on this address.
            return f"IP {ip_address} not found in VirusTotal database."
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        as_owner = attrs.get("as_owner", "unknown")
        country = attrs.get("country", "unknown")
        network = attrs.get("network", "unknown")

        verdict = "clean"
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"

        return (
            f"IP {ip_address} ({country}, AS: {as_owner}, net: {network}): "
            f"{verdict} — {malicious}/{total} malicious, {suspicious}/{total} suspicious "
            f"(harmless={harmless}, undetected={undetected})."
        )
    except httpx.TimeoutException:
        return _lookup_error(
            TIMEOUT,
            f"VirusTotal did not answer for IP {ip_address} within {HTTP_TIMEOUT_S:.0f} s.",
            "check_ip_reputation",
        )
    except httpx.HTTPStatusError as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal answered {exc.response.status_code} for IP {ip_address}.",
            "check_ip_reputation",
        )
    except Exception as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal lookup failed for {ip_address}: {type(exc).__name__}",
            "check_ip_reputation",
        )


def _vt_domain_lookup(domain: str) -> str:
    """Query VirusTotal for domain reputation."""
    url = f"{VT_BASE}/domains/{domain}"
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return _lookup_error(
                NOT_CONFIGURED,
                "VirusTotal API key invalid or quota exceeded.",
                "check_domain_reputation",
            )
        if resp.status_code == 404:
            return f"Domain {domain} not found in VirusTotal database."
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        categories = attrs.get("categories", {})
        cat_str = ", ".join(f"{k}={v}" for k, v in list(categories.items())[:3]) or "none"

        verdict = "clean"
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"

        return (
            f"Domain {domain}: {verdict} — {malicious}/{total} malicious, "
            f"{suspicious}/{total} suspicious. Categories: {cat_str}."
        )
    except httpx.TimeoutException:
        return _lookup_error(
            TIMEOUT,
            f"VirusTotal did not answer for domain {domain} within {HTTP_TIMEOUT_S:.0f} s.",
            "check_domain_reputation",
        )
    except httpx.HTTPStatusError as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal answered {exc.response.status_code} for domain {domain}.",
            "check_domain_reputation",
        )
    except Exception as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal lookup failed for {domain}: {type(exc).__name__}",
            "check_domain_reputation",
        )


def _vt_hash_lookup(file_hash: str) -> str:
    """Query VirusTotal for file hash reputation."""
    url = f"{VT_BASE}/files/{file_hash}"
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return _lookup_error(
                NOT_CONFIGURED, "VirusTotal API key invalid or quota exceeded.", "check_hash"
            )
        if resp.status_code == 404:
            return f"Hash {file_hash} not found in VirusTotal database."
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        names = attrs.get("names", [])
        type_desc = attrs.get("type_description", "unknown")
        size = attrs.get("size", 0)

        verdict = "clean"
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"

        name_str = names[0] if names else "unknown"
        return (
            f"Hash {file_hash} ({name_str}, {type_desc}, {size} bytes): {verdict} — "
            f"{malicious}/{total} malicious, {suspicious}/{total} suspicious."
        )
    except httpx.TimeoutException:
        return _lookup_error(
            TIMEOUT,
            f"VirusTotal did not answer for hash {file_hash} within {HTTP_TIMEOUT_S:.0f} s.",
            "check_hash",
        )
    except httpx.HTTPStatusError as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal answered {exc.response.status_code} for hash {file_hash}.",
            "check_hash",
        )
    except Exception as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"VirusTotal lookup failed for {file_hash}: {type(exc).__name__}",
            "check_hash",
        )


# ---------------------------------------------------------------------------
# AbuseIPDB helpers
# ---------------------------------------------------------------------------


def _abuseipdb_lookup(ip_address: str) -> str:
    """Query AbuseIPDB for IP reputation."""
    url = f"{ABUSEIPDB_BASE}/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": "True"}
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_S) as client:
            resp = client.get(url, headers=_abuseipdb_headers(), params=params)
        if resp.status_code == 401:
            return _lookup_error(
                NOT_CONFIGURED, "AbuseIPDB API key invalid.", "check_ip_reputation"
            )
        resp.raise_for_status()
        data = resp.json()
        d = data.get("data", {})

        score = d.get("abuseConfidencePercentage", 0)
        country = d.get("countryCode", "unknown")
        isp = d.get("isp", "unknown")
        total_reports = d.get("totalReports", 0)
        last_reported = d.get("lastReportedAt", "never")

        verdict = "clean"
        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"

        return (
            f"IP {ip_address} ({country}, ISP: {isp}): {verdict} — "
            f"AbuseIPDB confidence {score}% ({total_reports} reports, last: {last_reported})."
        )
    except httpx.TimeoutException:
        return _lookup_error(
            TIMEOUT,
            f"AbuseIPDB did not answer for IP {ip_address} within {HTTP_TIMEOUT_S:.0f} s.",
            "check_ip_reputation",
        )
    except httpx.HTTPStatusError as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"AbuseIPDB answered {exc.response.status_code} for IP {ip_address}.",
            "check_ip_reputation",
        )
    except Exception as exc:
        return _lookup_error(
            TOOL_FAILED,
            f"AbuseIPDB lookup failed for {ip_address}: {type(exc).__name__}",
            "check_ip_reputation",
        )


# ---------------------------------------------------------------------------
# Mock fallbacks (used when no API key is configured)
# ---------------------------------------------------------------------------


def _mock_ip_reputation(ip_address: str) -> str:
    if ip_address.startswith("185."):
        return f"IP {ip_address} has 15/80 detections on VT. Known for Cobalt Strike C2."
    if ip_address.startswith("10.") or ip_address.startswith("192.168."):
        return f"IP {ip_address} is private. No external reputation data."
    return f"IP {ip_address} has 0/80 detections. Clean."


def _mock_domain_reputation(domain: str) -> str:
    if "evil" in domain or "dga" in domain or len(domain) > 20:
        return f"Domain {domain} is flagged as malicious (phishing/C2). Registered 2 days ago."
    return f"Domain {domain} is benign."


def _mock_hash_reputation(file_hash: str) -> str:
    empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if file_hash.lower() == empty_sha256:
        return "Clean. Empty file."
    first = file_hash[0].lower() if file_hash else "z"
    if first in "0123":
        return f"Hash {file_hash} identified as Ransomware (LockBit) with 55/70 detections."
    if first in "4567":
        return f"Hash {file_hash} identified as Trojan/Dropper with 40/70 detections."
    return f"Hash {file_hash} not found in VirusTotal database."


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


def _joined(parts: list[str], tool: str) -> str:
    """Two sources as one answer, or one failure when neither answered.

    A structured error joined to a sentence is neither: nothing downstream can
    parse it, so a rate-limited lookup was recorded as a successful call whose
    result happened to mention a rate limit, and the model read a JSON
    document glued to prose. So: if every source failed, the answer is the
    first failure, whole and parseable. If one answered, the failures are
    reduced to their own sentence and what the model reads stays prose.
    """
    failures = [(part, error_parts(part)) for part in parts]
    answered = [part for part, failure in failures if failure is None]
    if not answered:
        return parts[0] if parts else tool_error_text(TOOL_FAILED, "no source answered", tool)
    said: list[str] = []
    for part, failure in failures:
        said.append(part if failure is None else str(error_sentence(part)))
    return "\n\n".join(said)


def _every_part_answered(text: str, parts: list[str]) -> bool:
    """Whether the joined answer is safe to keep.

    A mixed result carries one source's failure sentence in it, and the cache
    has no expiry: keeping it would replay "VirusTotal did not answer" for
    every later look at that indicator for the life of the server, long after
    VirusTotal came back.
    """
    return all(error_parts(part) is None for part in parts) and error_parts(text) is None


@mcp.tool()
@says_unquoted("ip_address", text_answer=True)
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of an IP address.

    Queries VirusTotal and AbuseIPDB when API keys are available; falls back
    to heuristic mock data otherwise.
    """
    # Read without one pair of surrounding quotes: a quoted address is not an
    # address, and the answer names the one that was looked up.
    ip_address = unquoted(ip_address)
    cached = _check_cache("ip", ip_address)
    if cached:
        return cached

    parts = []
    if VT_API_KEY:
        parts.append(_vt_ip_lookup(ip_address))
    if ABUSEIPDB_API_KEY:
        parts.append(_abuseipdb_lookup(ip_address))
    if not parts:
        parts.append(_mock_ip_reputation(ip_address))

    result = _joined(parts, "check_ip_reputation")
    if _every_part_answered(result, parts):
        _set_cache("ip", ip_address, result)
    return result


@mcp.tool()
@says_unquoted("domain", text_answer=True)
def check_domain_reputation(domain: str) -> str:
    """Check the reputation of a domain.

    Queries VirusTotal when an API key is available; falls back to heuristic
    mock data otherwise.
    """
    domain = unquoted(domain)
    cached = _check_cache("domain", domain)
    if cached:
        return cached

    if VT_API_KEY:
        result = _vt_domain_lookup(domain)
    else:
        result = _mock_domain_reputation(domain)

    _set_cache("domain", domain, result)
    return result


@mcp.tool()
@says_unquoted("file_hash", text_answer=True)
def check_hash(file_hash: str) -> str:
    """Check the reputation of a file hash (MD5, SHA1, or SHA256).

    Queries VirusTotal when an API key is available; falls back to heuristic
    mock data otherwise.
    """
    file_hash = unquoted(file_hash)
    cached = _check_cache("hash", file_hash)
    if cached:
        return cached

    if VT_API_KEY:
        result = _vt_hash_lookup(file_hash)
    else:
        result = _mock_hash_reputation(file_hash)

    _set_cache("hash", file_hash, result)
    return result


@mcp.tool()
def get_threatintel_status() -> str:
    """Return the current status of ThreatIntel MCP integrations."""
    services = []
    vt_status = "configured" if VT_API_KEY else "not configured (mock fallback)"
    abuse_status = "configured" if ABUSEIPDB_API_KEY else "not configured (mock fallback)"
    services.append(f"VirusTotal: {vt_status}")
    services.append(f"AbuseIPDB: {abuse_status}")
    services.append(f"Cache entries: {len(_cache)}")
    return "\n".join(services)


if __name__ == "__main__":
    mcp.run(transport="stdio")
