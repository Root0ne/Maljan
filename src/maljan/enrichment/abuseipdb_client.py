"""AbuseIPDB v2 API client — IP abuse confidence + ISP / country.

Hard rules match :mod:`virustotal_client`:
  - Never raise; always return ``None`` on failure.
  - Host whitelist: ``api.abuseipdb.com``.
  - Rate limit: 1000 req/day free tier — we cap to 25 IP lookups per
    job via the orchestrator.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from maljan.core.logger import logger

_ABUSE_HOST = "api.abuseipdb.com"
_ABUSE_URL = f"https://{_ABUSE_HOST}/api/v2/check"
_ABUSE_TIMEOUT_SECONDS = 20.0


class AbuseIPDBClient:
    """Thin async client for ``GET /api/v2/check``."""

    # The id the settings probe tests this source under, its key's setting,
    # and what the console calls it and its test.
    source_id = "abuseipdb"
    credential_setting = "api.abuseipdb_api_key"
    title = "AbuseIPDB"
    probe_label = "Test AbuseIPDB"

    @classmethod
    async def probe(cls, api_key: str) -> Any:
        """Check a public address over the last day: the cheapest call the key may make."""
        from maljan.enrichment.sources import http_probe

        return await http_probe(
            f"{_ABUSE_URL}?ipAddress=8.8.8.8&maxAgeInDays=1",
            {"Key": api_key, "Accept": "application/json"},
        )

    def __init__(self, api_key: str, http: httpx.AsyncClient) -> None:
        if not api_key:
            raise ValueError("AbuseIPDBClient: api_key is required")
        self._api_key = api_key
        self._http = http

    async def ip_check(self, address: str) -> dict[str, Any] | None:
        """Return ``{"abuse_confidence", "country", "isp", "domain"}`` or ``None``."""
        if not _safe_ip(address):
            return None
        try:
            resp = await self._http.get(
                _ABUSE_URL,
                params={"ipAddress": address, "maxAgeInDays": 90},
                headers={
                    "Key": self._api_key,
                    "Accept": "application/json",
                },
                timeout=_ABUSE_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            logger.warning("AbuseIPDB request failed: %s", exc)
            return None
        if resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit (HTTP 429).")
            return None
        if resp.status_code >= 400:
            logger.warning("AbuseIPDB returned HTTP %s", resp.status_code)
            return None

        # Belt + braces: refuse responses that arrived from an unexpected host.
        actual_host = urlparse(str(resp.request.url)).hostname
        if actual_host != _ABUSE_HOST:
            logger.warning("AbuseIPDB: response host mismatch (%s); discarding.", actual_host)
            return None

        try:
            payload = resp.json()
        except ValueError:
            return None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return None
        return {
            "source": "abuseipdb",
            "abuse_confidence": int(data.get("abuseConfidenceScore") or 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": int(data.get("totalReports") or 0),
        }


def _safe_ip(value: str) -> bool:
    if not value:
        return False
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _register() -> None:
    from maljan.enrichment.sources import register_reputation_source

    register_reputation_source(AbuseIPDBClient)


_register()
