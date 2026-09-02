"""Stub connection-test probes for ``POST /api/v1/settings/test/{probe}``.

Task 9 replaces this module with real probes (``llm``, ``ghidra``, ``cape``,
``qdrant``, ``redis``, ``virustotal``, ``abuseipdb``), each with a hard
10-second timeout and no persistence. Until then this stub keeps the route
importable: an empty registry means every probe name 404s.
"""

from __future__ import annotations

from typing import Any

PROBES: dict[str, object] = {}


async def run_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> Any:
    raise KeyError(name)
