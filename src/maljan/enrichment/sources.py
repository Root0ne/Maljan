"""The reputation sources enrichment asks, each answering for its own connection test.

A source is a client class that declares ``source_id`` (the id its probe is
asked under), ``credential_setting`` (the settings key holding its key) and an
async ``probe(api_key)`` returning a ``ProviderProbe``. The settings probe
looks a source up here by id and never names one, so a source added with
:func:`register_reputation_source` gets its "Test" button by declaring those
three things.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from maljan.providers.base import ProviderProbe

# A connection test is a person waiting at a button.
PROBE_TIMEOUT_SECONDS = 10.0

_SOURCES: dict[str, type] = {}


def register_reputation_source(cls: type) -> type:
    """Make ``cls`` a reputation source the settings probe can test, under its ``source_id``."""
    source_id = str(getattr(cls, "source_id", "") or "")
    if not source_id:
        raise ValueError("a reputation source needs a non-empty source_id")
    _SOURCES[source_id] = cls
    return cls


def _discover() -> None:
    import maljan.enrichment.abuseipdb_client  # noqa: F401
    import maljan.enrichment.virustotal_client  # noqa: F401


def reputation_sources() -> dict[str, type]:
    """Every registered reputation source by id."""
    _discover()
    return dict(_SOURCES)


async def http_probe(url: str, headers: dict[str, str] | None = None) -> ProviderProbe:
    """One GET against ``url``: ok below HTTP 400, the status or the failure as the detail."""
    from maljan.core.settings_overrides import redact_url

    t0 = time.perf_counter()

    def _ms() -> int:
        return int((time.perf_counter() - t0) * 1000)

    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
            answer = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return ProviderProbe(False, f"timeout after {int(PROBE_TIMEOUT_SECONDS)} s", _ms())
    except httpx.HTTPError as exc:
        # httpx embeds the request URL in several transport errors.
        return ProviderProbe(False, redact_url(f"{type(exc).__name__}: {exc}"), _ms())
    return ProviderProbe(answer.status_code < 400, f"HTTP {answer.status_code}", _ms())


def credential_of(source: Any) -> str:
    """The settings key a source reads its credential from."""
    return str(getattr(source, "credential_setting", "") or "")
