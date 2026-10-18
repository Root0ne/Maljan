"""WHOIS / RDAP + GeoIP lookups for IPv4/IPv6 addresses.

We avoid pulling new optional deps where possible — ``ipwhois`` and the
MaxMind GeoIP reader are loaded lazily; the client gracefully reports
``None`` when they are not installed.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlsplit

import httpx

from maljan.core.logger import logger

_RDAP_BOOTSTRAP_URL = "https://rdap.arin.net/registry/ip/{address}"
_RDAP_TIMEOUT_SECONDS = 15.0
# How each lookup that needs no key is named to a listener (``(source, host)``)
# and in a run's disclosure block, with the path it takes. The fallback below
# asks the ARIN bootstrap through the job's HTTP client, which follows no
# redirect, so a referral to a regional registry is never reached. ipwhois,
# when it is installed, takes its own path: RDAP from the same bootstrap,
# following the referral, and its ASN lookup by DNS to the ASN service, with
# the whois and HTTP fallbacks it may take; it does not say which it reached.
RDAP_SOURCE = "rdap"
RDAP_HOST = str(urlsplit(_RDAP_BOOTSTRAP_URL).hostname)
IPWHOIS_RDAP_SOURCE = "rdap_ipwhois"
IPWHOIS_ASN_SOURCE = "asn_ipwhois"
IPWHOIS_ASN_HOST = "origin.asn.cymru.com"
REGISTRY_LOOKUPS: dict[str, tuple[str, str]] = {
    RDAP_SOURCE: (
        "RDAP",
        "the ARIN bootstrap alone: a referral to a regional registry is not followed",
    ),
    IPWHOIS_RDAP_SOURCE: (
        "RDAP through ipwhois",
        "from the ARIN bootstrap, which may refer to a regional registry",
    ),
    IPWHOIS_ASN_SOURCE: (
        "ASN lookups through ipwhois",
        "by DNS to the ASN service there, and the whois and HTTP fallbacks it may take",
    ),
}


def ipwhois_available() -> bool:
    """Whether the optional ``ipwhois`` package is installed, so its path is the one taken."""
    import importlib.util

    try:
        return importlib.util.find_spec("ipwhois") is not None
    except (ImportError, ValueError):
        return False


def registry_lookups() -> list[tuple[str, str]]:
    """``(source, host)`` of every lookup with no key an enrichment of an address may make."""
    first = (
        [(IPWHOIS_RDAP_SOURCE, RDAP_HOST), (IPWHOIS_ASN_SOURCE, IPWHOIS_ASN_HOST)]
        if ipwhois_available()
        else []
    )
    return [*first, (RDAP_SOURCE, RDAP_HOST)]


class WhoisClient:
    """Best-effort WHOIS / GeoIP lookups for the report's IP IOCs.

    ``on_ask`` is told of each RDAP question just before it is sent, as the
    declared sources' asker tells it (``enrichment.declared.AskListener``).
    """

    def __init__(self, http: httpx.AsyncClient, on_ask: Any = None) -> None:
        self._http = http
        self._on_ask = on_ask

    async def asn_lookup(self, address: str) -> str | None:
        """Return ``"AS12345 ExampleCorp"`` style label or ``None``."""
        if not _is_public_ip(address):
            return None
        from maljan.enrichment.declared import settle_asked, tell_listener

        # 1) Try ipwhois (RDAP, locally cached), which asks on its own path.
        if ipwhois_available():
            settles = [
                await tell_listener(self._on_ask, source, host, "ip", "")
                for source, host in registry_lookups()[:2]
            ]
            result = await _try_ipwhois(address)
            for each in settles:
                settle_asked(each, bool(result))
            if result:
                return result
        # 2) Fallback to ARIN bootstrap (network call).
        settle = await tell_listener(self._on_ask, RDAP_SOURCE, RDAP_HOST, "ip", "")
        try:
            resp = await self._http.get(
                _RDAP_BOOTSTRAP_URL.format(address=address),
                timeout=_RDAP_TIMEOUT_SECONDS,
                headers={"Accept": "application/rdap+json"},
            )
        except httpx.HTTPError as exc:
            settle_asked(settle, False)
            logger.warning("WhoisClient: RDAP fallback failed: %s", exc)
            return None
        settle_asked(settle, True)
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
