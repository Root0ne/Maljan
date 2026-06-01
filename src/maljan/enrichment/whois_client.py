"""WHOIS / RDAP + GeoIP lookups for IPv4/IPv6 addresses.

We avoid pulling new optional deps where possible — ``ipwhois`` and the
MaxMind GeoIP reader are loaded lazily; the client gracefully reports
``None`` when they are not installed.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import httpx

from maljan.core.logger import logger

_RDAP_BOOTSTRAP_URL = "https://rdap.arin.net/registry/ip/{address}"
_RDAP_TIMEOUT_SECONDS = 15.0


class WhoisClient:
    """Best-effort WHOIS / GeoIP lookups for the report's IP IOCs."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def asn_lookup(self, address: str) -> str | None:
        """Return ``"AS12345 ExampleCorp"`` style label or ``None``."""
        if not _is_public_ip(address):
            return None
        # 1) Try ipwhois (RDAP, locally cached).
        result = await _try_ipwhois(address)
        if result:
            return result
        # 2) Fallback to ARIN bootstrap (network call).
        try:
            resp = await self._http.get(
                _RDAP_BOOTSTRAP_URL.format(address=address),
                timeout=_RDAP_TIMEOUT_SECONDS,
                headers={"Accept": "application/rdap+json"},
            )
        except httpx.HTTPError as exc:
            logger.warning("WhoisClient: RDAP fallback failed: %s", exc)
            return None
        if resp.status_code >= 400:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        autnum = _find_first_autnum(data)
        if not autnum:
            return None
        name = data.get("name") or ""
        return f"AS{autnum} {name}".strip()

    def geoip(self, address: str) -> str | None:
        """Return ``"US"`` (ISO country code) when MaxMind is available."""
        if not _is_public_ip(address):
            return None
        try:
            import geoip2.database  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            # MaxMind reader path: ``GEO_IP_DB_PATH`` env override, else the
            # conventional mount point. Lets dev/CI point at a local .mmdb.
            import os

            db_path = os.environ.get("GEO_IP_DB_PATH") or "/var/lib/GeoIP/GeoLite2-Country.mmdb"
            reader = geoip2.database.Reader(db_path)
        except Exception:  # noqa: BLE001
            return None
        try:
            record = reader.country(address)
            iso = record.country.iso_code
            return str(iso) if iso else None
        except Exception:  # noqa: BLE001
            return None
        finally:
            try:
                reader.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)


async def _try_ipwhois(address: str) -> str | None:
    """Call the optional ``ipwhois`` package off the event loop."""
    try:
        import ipwhois  # type: ignore[import-not-found]
    except ImportError:
        return None

    def _blocking() -> str | None:
        try:
            obj = ipwhois.IPWhois(address)
            data = obj.lookup_rdap(depth=0)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(data, dict):
            return None
        asn = data.get("asn")
        asn_desc = data.get("asn_description") or ""
        if not asn:
            return None
        return f"AS{asn} {asn_desc}".strip()

    return await asyncio.to_thread(_blocking)


def _find_first_autnum(rdap: dict[str, Any]) -> str | None:
    """RDAP bootstrap can nest the autnum in several places; grab the first."""
    entities = rdap.get("entities") or []
    if isinstance(entities, list):
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            handle = ent.get("handle")
            if isinstance(handle, str) and handle.lower().startswith("as"):
                return handle[2:]
    return None
