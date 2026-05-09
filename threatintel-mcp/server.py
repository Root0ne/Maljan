"""ThreatIntel MCP Server — VirusTotal + AbuseIPDB integration with mock fallback.

Usage:
    uv run python threatintel-mcp/server.py

Environment:
    VIRUSTOTAL_API_KEY — VirusTotal API v3 key (optional, mock fallback if missing)
    ABUSEIPDB_API_KEY — AbuseIPDB API v2 key (optional, mock fallback if missing)
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ThreatIntelMCP")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

# Minimal in-memory cache to avoid hammering APIs during testing
_cache: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vt_headers() -> dict[str, str]:
    return {"x-apikey": VT_API_KEY}


def _abuseipdb_headers() -> dict[str, str]:
    return {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}


def _cache_key(prefix: str, query: str) -> str:
    return f"{prefix}:{hashlib.sha256(query.encode()).hexdigest()[:16]}"


def _check_cache(prefix: str, query: str) -> str | None:
    key = _cache_key(prefix, query)
    return _cache.get(key)


def _set_cache(prefix: str, query: str, value: str) -> None:
    key = _cache_key(prefix, query)
    _cache[key] = value


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------


def _vt_ip_lookup(ip_address: str) -> str:
    """Query VirusTotal for IP reputation."""
    url = f"{VT_BASE}/ip_addresses/{ip_address}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return "VirusTotal API key invalid or quota exceeded."
        if resp.status_code == 404:
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
        return f"VirusTotal timeout for IP {ip_address}."
    except httpx.HTTPStatusError as exc:
        return f"VirusTotal error {exc.response.status_code} for IP {ip_address}."
    except Exception as exc:
        return f"VirusTotal lookup failed for {ip_address}: {exc}"


def _vt_domain_lookup(domain: str) -> str:
    """Query VirusTotal for domain reputation."""
    url = f"{VT_BASE}/domains/{domain}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return "VirusTotal API key invalid or quota exceeded."
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
        return f"VirusTotal timeout for domain {domain}."
    except httpx.HTTPStatusError as exc:
        return f"VirusTotal error {exc.response.status_code} for domain {domain}."
    except Exception as exc:
        return f"VirusTotal lookup failed for {domain}: {exc}"


def _vt_hash_lookup(file_hash: str) -> str:
    """Query VirusTotal for file hash reputation."""
    url = f"{VT_BASE}/files/{file_hash}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, headers=_vt_headers())
        if resp.status_code == 401:
            return "VirusTotal API key invalid or quota exceeded."
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
        return f"VirusTotal timeout for hash {file_hash}."
    except httpx.HTTPStatusError as exc:
        return f"VirusTotal error {exc.response.status_code} for hash {file_hash}."
    except Exception as exc:
        return f"VirusTotal lookup failed for {file_hash}: {exc}"


# ---------------------------------------------------------------------------
# AbuseIPDB helpers
# ---------------------------------------------------------------------------


def _abuseipdb_lookup(ip_address: str) -> str:
    """Query AbuseIPDB for IP reputation."""
    url = f"{ABUSEIPDB_BASE}/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": "True"}
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, headers=_abuseipdb_headers(), params=params)
        if resp.status_code == 401:
            return "AbuseIPDB API key invalid."
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
        return f"AbuseIPDB timeout for IP {ip_address}."
    except httpx.HTTPStatusError as exc:
        return f"AbuseIPDB error {exc.response.status_code} for IP {ip_address}."
    except Exception as exc:
        return f"AbuseIPDB lookup failed for {ip_address}: {exc}"


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


@mcp.tool()
def check_ip_reputation(ip_address: str) -> str:
    """Check the reputation of an IP address.

    Queries VirusTotal and AbuseIPDB when API keys are available; falls back
    to heuristic mock data otherwise.
    """
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

    result = "\n\n".join(parts)
    _set_cache("ip", ip_address, result)
    return result


@mcp.tool()
def check_domain_reputation(domain: str) -> str:
    """Check the reputation of a domain.

    Queries VirusTotal when an API key is available; falls back to heuristic
    mock data otherwise.
    """
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
def check_hash(file_hash: str) -> str:
    """Check the reputation of a file hash (MD5, SHA1, or SHA256).

    Queries VirusTotal when an API key is available; falls back to heuristic
    mock data otherwise.
    """
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
