"""The tool server a report section was built from.

A section built from tool answers cites ledger entries (``evidence_ids``), and
each indexed entry names the server that answered it (``server``), or, for a
provider-backed tool with no server, the source it recorded
(``source``, ``<kind>:<name>``), whose name is a provider's. A section whose
entries all agree on one server or provider is that one's: the console draws a
tab for it. A section built from
several servers, or from entries that name none, has no single server and
says none.

Nothing is stored for this: the builder sets it on a new report, and a stored
report is read through :func:`with_source_servers` when it is served, so no
migration is needed and a stored run gets the same answer. Names of servers
and tools are never read, only what each row recorded.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def _server_of_row(row: Any) -> str | None:
    """The server one index row records, else the server or provider name its source carries."""
    server = _field(row, "server")
    if isinstance(server, str) and server.strip():
        return server.strip()
    source = _field(row, "source")
    if isinstance(source, str) and ":" in source:
        name = source.split(":", 1)[1].strip()
        if name:
            return name
    return None


def index_of(evidence_index: Any) -> dict[str, Any]:
    """``{entry id: index row}`` for a report's ``evidence_index``."""
    index: dict[str, Any] = {}
    for row in evidence_index or []:
        entry_id = _field(row, "id")
        if isinstance(entry_id, str):
            index[entry_id] = row
    return index


def source_server(section: Any, index: Mapping[str, Any]) -> str | None:
    """The one server (or provider) every entry ``section`` cites agrees on, or ``None``."""
    ids = _field(section, "evidence_ids") or []
    servers = set()
    for entry_id in ids:
        row = index.get(entry_id) if isinstance(entry_id, str) else None
        servers.add(_server_of_row(row) if row is not None else None)
    if len(servers) != 1:
        return None
    return next(iter(servers))


def with_source_servers(report: Any) -> Any:
    """A stored ``MalwareReport`` dump with ``source_server`` derived where it is missing.

    Returns ``report`` itself when nothing changes; never raises on an odd
    stored shape (what cannot be read derives nothing).
    """
    if not isinstance(report, dict):
        return report
    sections = report.get("sections")
    if not isinstance(sections, list):
        return report
    try:
        index = index_of(report.get("evidence_index"))
        out: list[Any] = []
        changed = False
        for section in sections:
            if isinstance(section, dict) and not section.get("source_server"):
                server = source_server(section, index)
                if server:
                    section = {**section, "source_server": server}
                    changed = True
            out.append(section)
    except Exception:  # noqa: BLE001 — a derived label is never worth the report
        return report
    return {**report, "sections": out} if changed else report
