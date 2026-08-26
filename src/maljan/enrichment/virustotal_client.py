"""VirusTotal v3 API client — domain + IP reputation lookups.

Hard rules:
  - **Never raise**. Every error path returns ``None`` and logs a warning.
  - **Host whitelist** (`SSRF guard`): only ``www.virustotal.com``. The
    user-controlled IOC is sent only as a path segment and is URL-encoded;
    it can never become the request host.
  - **Rate limit**: free tier 4 req/min. The client enforces an
    ``asyncio.Semaphore(1)`` + 16 s sleep between calls.
  - **API key**: optional. When absent the client refuses to construct
    (``vt = None`` in the orchestrator).
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from maljan.core.logger import logger

_VT_HOST = "www.virustotal.com"
_VT_BASE_URL = f"https://{_VT_HOST}/api/v3"
_VT_RATE_LIMIT_SECONDS = 16.0  # 4 req/min → 15 s spacing + safety margin
_VT_TIMEOUT_SECONDS = 30.0


class VirusTotalClient:
    """Thin async client for the VirusTotal v3 domain/IP endpoints."""

    def __init__(
        self,
        api_key: str,
        http: httpx.AsyncClient,
        *,
        rate_limit_seconds: float = _VT_RATE_LIMIT_SECONDS,
    ) -> None:
        if not api_key:
            raise ValueError("VirusTotalClient: api_key is required")
        self._api_key = api_key
        self._http = http
        self._rate_limit_seconds = rate_limit_seconds
        self._semaphore = asyncio.Semaphore(1)

    async def domain_reputation(self, fqdn: str) -> dict[str, Any] | None:
        """Return the digest reputation summary for ``fqdn`` or ``None``."""
        if not _safe_lookup_value(fqdn):
            return None
        url = f"{_VT_BASE_URL}/domains/{quote(fqdn, safe='')}"
        payload = await self._get_json(url)
        if payload is None:
            return None
        return _summarise_vt_object(payload)

    async def ip_reputation(self, address: str) -> dict[str, Any] | None:
        """Return the digest reputation summary for ``address`` or ``None``."""
        if not _safe_lookup_value(address):
            return None
        url = f"{_VT_BASE_URL}/ip_addresses/{quote(address, safe='')}"
        payload = await self._get_json(url)
        if payload is None:
            return None
        return _summarise_vt_object(payload)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _get_json(self, url: str) -> dict[str, Any] | None:
        """Issue a GET request with SSRF guard, rate limit, and graceful failure."""
        if not _is_whitelisted_host(url, _VT_HOST):
            logger.warning("VirusTotalClient: refusing non-whitelisted URL host.")
            return None

        async with self._semaphore:
            try:
                resp = await self._http.get(
                    url,
                    headers={"x-apikey": self._api_key, "accept": "application/json"},
                    timeout=_VT_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                logger.warning("VirusTotal request failed: %s", exc)
                return None
            await asyncio.sleep(self._rate_limit_seconds)

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit (HTTP 429).")
            return None
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            logger.warning(
                "VirusTotal returned HTTP %s for %s",
                resp.status_code,
                _redact_url(url),
            )
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.warning("VirusTotal: response was not JSON")
            return None
        if not isinstance(data, dict):
            return None
        return data


def _summarise_vt_object(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce the verbose VT response to the fields the report needs."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    attrs = data.get("attributes") or {}
    last_stats = attrs.get("last_analysis_stats") or {}
    summary: dict[str, Any] = {
        "source": "virustotal",
        "malicious": int(last_stats.get("malicious") or 0),
        "suspicious": int(last_stats.get("suspicious") or 0),
        "harmless": int(last_stats.get("harmless") or 0),
        "undetected": int(last_stats.get("undetected") or 0),
        "reputation": int(attrs.get("reputation") or 0),
    }
    categories = attrs.get("categories")
    if isinstance(categories, dict):
        # VT returns `{vendor: label}`; collapse to a short ordered list.
        summary["categories"] = [str(v) for v in list(categories.values())[:5]]
    last_seen = attrs.get("last_analysis_date")
    if isinstance(last_seen, int):
        summary["last_analysis_date_unix"] = last_seen
    return summary


def _safe_lookup_value(value: str) -> bool:
    """Reject empty / oversized / control-char inputs before they hit the wire."""
    if not value:
        return False
    if len(value) > 253:  # max DNS label aggregate
        return False
    for ch in value:
        if ord(ch) < 0x20 or ch in {" ", "/", "?", "#"}:
            return False
    return True


def _is_whitelisted_host(url: str, expected_host: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in {"https", "http"} and parsed.hostname == expected_host


def _redact_url(url: str) -> str:
    """Strip the IOC value from the URL before logging."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return "<invalid>"
    return f"{parsed.scheme}://{parsed.hostname}{parsed.path.rsplit('/', 1)[0]}/<redacted>"
