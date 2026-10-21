"""The console tab a report section from an operator's tool is drawn on.

The console places a section by its key (``apps/web/src/components/analysis/
reportSections.ts``): ``pe_imports`` on STATIC, ``sandbox_registry`` on
DYNAMIC. A section an operator's tool produced is keyed after the tool
(``tool_<name>``), which no key map can know, so it fell to the EVIDENCE
tab's "Sections no tab draws" footer. This module says, for each such section,
which tab it belongs on, read from what the report stored, never from the
reading process's settings:

* by the kind its tool declared when its entries were written (an accepted
  declaration): a sandbox kind on DYNAMIC, a capture or flow kind on NETWORK,
  a reputation lookup on IDENTITY, a code listing, a rule match, a strings or
  an import listing on STATIC;
* else by the tab the calling agent's definition declared when its entries
  were written (``LedgerEntry.agent_tab``, from ``AgentDefinition.tab``: the
  built-in roles declare theirs, a clone copies its source's, a generic or
  lead agent declares one only when an operator sets it). An agent's name is
  never read, and settings are never read while a report renders.

Only sections built from the answers of tools whose source the platform ships
no declaration for are placed by kind, and a ``tool_<name>`` section from a
platform server's answers by its declared tab (a built-in role declares its own): every other
built-in section keeps the key map's placement, so nothing a stored run of
built-in tools shows moves. A section
neither reading places is left out, and the console keeps drawing it in the
footer.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from maljan.reporting import tool_kinds

# The key endings the console places a section by (``BY_SUFFIX`` in
# ``reportSections.ts``): a ``tool_*`` key ending so keeps that placement.
CONSOLE_SUFFIXES: tuple[str, ...] = ("_header", "_sections", "_imports", "_exports")

# The tabs the console draws sections on that this module may name.
TABS: tuple[str, ...] = ("identity", "static", "dynamic", "network", "persistence")


# Consumers of declared kinds (``core.builtin_declarations.CONSUMER_KINDS``)
# and the tab a kind they read is drawn on, the first that reads a kind
# deciding: the network answers before the rest of a sandbox's.
_TAB_OF_CONSUMER: tuple[tuple[str, str], ...] = (
    ("evidence_bundles._NETWORK_SANDBOX_TOOLS", "network"),
    ("network_analyst._PCAP_TOOLS", "network"),
    ("evidence_bundles.SANDBOX_TOOL_PREFIXES", "dynamic"),
    ("markdown._REPUTATION_TOOLS", "identity"),
    ("evidence_roots._WHOLE_FILE_TOOLS", "identity"),
    ("ledger_report._FUNCTION_TOOLS", "static"),
    ("ledger_report._FUNCTION_LIST_TOOLS", "static"),
    ("markdown._ANALYSIS_TOOLS", "static"),
    ("evidence_bundles._STRING_TOOLS", "static"),
    ("evidence_roots._IMPORT_LISTINGS", "static"),
    ("evidence_roots._EXPORT_LISTINGS", "static"),
    ("evidence_roots._PROGRAM_TOOLS", "static"),
)


def _tab_of_kind(facts: Any) -> str:
    """The tab a declared kind is drawn on, or ``""``."""
    if facts is None:
        return ""
    if getattr(facts, "reputation", None) is not None:
        return "identity"
    from maljan.core.undeclared_tools import CODE_LISTING_KINDS, DECOMPILE_KINDS

    kind = facts.kind
    if kind in DECOMPILE_KINDS or kind in CODE_LISTING_KINDS:
        return "static"
    for consumer, tab in _TAB_OF_CONSUMER:
        if kind in tool_kinds.consumer_kinds(consumer):
            return tab
    return ""


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def section_tabs(report: Any) -> dict[str, str]:
    """``{section key: tab}`` for each section of ``report`` from an operator's tool that has one.

    ``report`` is a stored ``MalwareReport`` dump or the model. A section is
    placed when it was built from tool answers (``source`` ``tool:<name>``)
    and every entry it cites is indexed and recorded a source the platform
    ships no declaration for. Never raises on a stored report's odd shape:
    what cannot be read places nothing.
    """
    index: dict[str, Any] = {}
    for row in _field(report, "evidence_index") or []:
        entry_id = _field(row, "id")
        if isinstance(entry_id, str):
            index[entry_id] = row
    placed: dict[str, str] = {}
    for section in _field(report, "sections") or []:
        key = _field(section, "key")
        source = _field(section, "source")
        if not isinstance(key, str) or not str(source or "").startswith("tool:"):
            continue
        ids = _field(section, "evidence_ids") or []
        rows = [index[i] for i in ids if isinstance(i, str) and i in index]
        if not rows or len(rows) != len(ids):
            continue
        if not all(tool_kinds.from_an_operator_source(row) for row in rows):
            # A ``tool_<name>`` section the key map never places, built from
            # a platform server's answers: the tab its agents
            # declared gives it, so it is never drawn as a server's own.
            by_agent = key.startswith("tool_") and not key.endswith(CONSOLE_SUFFIXES)
            tab = _tab_of_agents(rows) if by_agent else ""
            if tab:
                placed[key] = tab
            continue
        tab = _tab_of_rows(rows)
        if tab:
            placed[key] = tab
    return placed


def _tab_of_agents(rows: list[Any]) -> str:
    """The one tab every cited entry's agent declared (a built-in role has its own), or ``""``.

    An entry written before sources were recorded declares nothing here.
    """
    if any(tool_kinds.source_of(row) is None for row in rows):
        return ""
    tabs = {str(_field(row, "agent_tab") or "") for row in rows}
    if len(tabs) == 1:
        tab = tabs.pop()
        return tab if tab in TABS else ""
    return ""


def _tab_of_rows(rows: list[Any]) -> str:
    """The tab the cited entries agree on: their declared kind's, else their agents' tab."""
    by_kind = {_tab_of_kind(tool_kinds.facts_of(row)) for row in rows}
    if len(by_kind) == 1 and "" not in by_kind:
        return by_kind.pop()
    if by_kind - {""}:
        return ""
    tabs = {str(_field(row, "agent_tab") or "") for row in rows}
    if len(tabs) == 1:
        tab = tabs.pop()
        return tab if tab in TABS else ""
    return ""
