"""A reputation answer, read once through its tool's declared paths into one record.

Any server whose tool declares ``kind: reputation`` (``ToolFacts.kind``) is a
reputation source: the triage pack asks it when it also declares the argument
it takes a hash in (``arguments.hash``), the judge counts it as a lookup tool
and as a source asked, and its answer is read by the paths its declaration
gives (``ToolFacts.reputation``: counts, labels, detections, dates, link,
summary, prose patterns) into one typed record, :class:`ReputationRecord`.

**The writer** (:func:`record_at_write`). The record is read when the entry is
written (``schemas.evidence.build_entry``), from the facts the entry stores
(``core.declared_reading.facts_record``), and stored beside them
(``LedgerEntry.reputation``); the report carries every record
(``MalwareReport.reputation``). A re-render, the API and the console read the
record as stored, never the reading process's settings.

**The reader** (:func:`reputation_of`). The record an entry stored; for an
entry that stored none (written before records were, or a test's), the same
reading of its answer through the facts it stored, or, for an entry with no
source and no facts, the facts the platform ships for its tool's name
(``core.declared_reading.facts_of``). Nothing here reads a tool by its name or
an answer by one service's shape: the built-in VirusTotal and threat-intel
lookups are read by the paths their declarations ship
(``core.builtin_declarations``).

**The lookups** (:func:`pack_lookups`, :func:`lookup_servers`,
:func:`is_lookup_tool`) are read from the live declarations, where nothing
persisted depends on the answer: which call the pack makes, and which tools
the judge holds.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from maljan.core.tool_declarations import ReputationFacts, ToolDeclarations, ToolFacts

# The kind a reputation lookup about the sample declares.
REPUTATION_KIND = "reputation"
# The version of the stored record's shape.
RECORD_VERSION = 1
# The argument role a lookup takes the sample's hash in (``ToolFacts.arguments``).
HASH_ARGUMENT = "hash"
# The argument roles a network indicator is given to a tool in, and every role
# that carries an indicator: the sample's hash and those.
NETWORK_INDICATOR_ARGUMENTS: tuple[str, ...] = ("domain", "ip", "url")
INDICATOR_ARGUMENTS: tuple[str, ...] = (HASH_ARGUMENT, *NETWORK_INDICATOR_ARGUMENTS)
# The kinds a lookup about an indicator declares, beside a reputation lookup
# about the sample: a service's report on an indicator, and its reputation.
INDICATOR_LOOKUP_KINDS: tuple[str, ...] = ("indicator_report", "indicator_reputation")
# The rank a lookup whose declaration names none is asked at.
DEFAULT_RANK = 100


class ReputationRecord(BaseModel):
    """What one reputation answer said about the sample, as its declaration reads it.

    ``service`` is the name the answer is attributed to. ``malicious``,
    ``suspicious`` and ``total`` are engine counts, ``engines`` the engine
    count the service gave beside them, ``stats`` the whole-number counts of
    the answer's counts object as written. ``labels`` are the threat labels
    in the order they were read, ``detections`` the per-engine result labels.
    ``first_seen`` and ``last_seen`` are dates (ISO-8601 as written, or from
    whole seconds since the epoch), ``link`` a URL the answer carried, and
    ``summary`` the service's own sentence. A field the answer did not give
    is ``None`` or empty: a record never holds a value its answer did not.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    v: int = RECORD_VERSION
    service: str = ""
    malicious: int | None = None
    suspicious: int | None = None
    total: int | None = None
    engines: int | None = None
    stats: dict[str, int] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    link: str | None = None
    summary: str = ""

    def says_something(self) -> bool:
        """Whether the answer established anything: a count, a label or the service's words."""
        return bool(
            self.malicious is not None
            or self.total is not None
            or self.engines is not None
            or self.labels
            or self.detections
            or self.summary
        )

    def engine_count(self) -> int | None:
        """How many engines the answer counted: the count it gave, else its total."""
        return self.engines if self.engines is not None else self.total

    def stored(self) -> dict[str, Any]:
        """The stored form: the version and every field the answer gave."""
        dumped = self.model_dump(mode="json", exclude_defaults=True)
        return {"v": RECORD_VERSION, **{k: v for k, v in dumped.items() if k != "v"}}


def is_lookup(facts: ToolFacts | None) -> bool:
    """Whether a tool's facts declare a reputation lookup about the sample."""
    from maljan.core.builtin_declarations import REPUTATION_KINDS

    return facts is not None and facts.kind in REPUTATION_KINDS


def asks_about_an_indicator(facts: ToolFacts | None) -> bool:
    """Whether a tool's facts declare that it asks a service about the sample or an indicator.

    A reputation lookup (:func:`is_lookup`), a tool of an indicator lookup kind
    (:data:`INDICATOR_LOOKUP_KINDS`), or a tool that declares an argument
    carrying an indicator (:data:`INDICATOR_ARGUMENTS`), whatever its kind.
    """
    if facts is None:
        return False
    return (
        is_lookup(facts)
        or facts.kind in INDICATOR_LOOKUP_KINDS
        or any(role in facts.arguments for role in INDICATOR_ARGUMENTS)
    )


def kinds_of_capability(capability: str) -> frozenset[str]:
    """The tool kinds a ``ToolRef(kind="capability")`` names: the kind itself.

    ``reputation`` also names the kinds a stored server row may still declare
    its lookup under (``core.legacy_reputation``), so a row saved then keeps
    reaching the agents.
    """
    from maljan.core.builtin_declarations import REPUTATION_KINDS

    return frozenset(REPUTATION_KINDS) if capability == REPUTATION_KIND else frozenset({capability})


# ---------------------------------------------------------------------------
# Reading an answer
# ---------------------------------------------------------------------------


def _whole(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _first_whole(document: Any, path: str) -> int | None:
    from maljan.core.tool_declarations import select

    for found in select(document, path):
        whole = _whole(found)
        if whole is not None:
            return whole
    return None


def _moment(value: Any) -> str | None:
    """A date as the record holds it: ISO-8601 text as written, or from epoch seconds."""
    if isinstance(value, str):
        return value.strip() or None
    whole = _whole(value)
    if whole is None and isinstance(value, float) and not isinstance(value, bool):
        whole = int(value)
    if whole is None or whole <= 0:
        return None
    try:
        return datetime.fromtimestamp(whole, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _first_moment(document: Any, paths: Iterable[str]) -> str | None:
    from maljan.core.tool_declarations import select

    for path in paths:
        for found in select(document, path):
            moment = _moment(found)
            if moment:
                return moment
    return None


def _first_link(document: Any, paths: Iterable[str]) -> str | None:
    from maljan.core.tool_declarations import select

    for path in paths:
        for found in select(document, path):
            if isinstance(found, str) and found.strip().lower().startswith(("http://", "https://")):
                return found.strip()
    return None


def _texts(document: Any, paths: Iterable[str]) -> list[str]:
    """Every text the paths name, a list's texts one by one, in order."""
    from maljan.core.tool_declarations import select

    out: list[str] = []
    for path in paths:
        for found in select(document, path):
            items = found if isinstance(found, list) else [found]
            out.extend(item.strip() for item in items if isinstance(item, str) and item.strip())
    return out


def _detections(document: Any, path: str) -> list[str]:
    """The per-engine labels: the first list the path names, each label's blanks squeezed.

    One label per engine, so they are counted, not merged: a label two
    engines gave is held twice.
    """
    from maljan.core.tool_declarations import select

    if not path:
        return []
    for found in select(document, path):
        if isinstance(found, list):
            return [" ".join(i.split()) for i in found if isinstance(i, str) and i.strip()]
    return []


def _once(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _document(output: str, structured: Any) -> Any:
    if isinstance(structured, dict | list):
        return structured
    text = (output or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict | list) else None


def read_answer(
    facts: ToolFacts, *, output: str, structured: Any = None, server: str | None = None
) -> ReputationRecord:
    """One reputation answer read through ``facts``' declared paths.

    Counts come from the declared paths; a count no path gave is looked for
    in the answer's text by the declared patterns. Linear in the size of the
    answer (``tool_declarations.select``, RE2 patterns).
    """
    from maljan.core.tool_declarations import ReputationFacts, first

    declared: ReputationFacts = facts.reputation or ReputationFacts()
    document = _document(output, structured)
    stats_found = first(document, declared.stats) if declared.stats else None
    stats = (
        {str(k): v for k, v in stats_found.items() if _whole(v) is not None}
        if isinstance(stats_found, Mapping)
        else {}
    )
    malicious = _first_whole(document, declared.malicious) if declared.malicious else None
    suspicious = _first_whole(document, declared.suspicious) if declared.suspicious else None
    total = _first_whole(document, declared.total) if declared.total else None
    if total is None and stats:
        total = sum(stats.values())
    if malicious is None and declared.text_patterns:
        counted = declared.counts_in_text(str(output or ""))
        if counted is not None:
            malicious, said_total, said_suspicious = counted
            total = total if total is not None else said_total
            suspicious = suspicious if suspicious is not None else said_suspicious
    if declared.summary:
        summary = next(iter(_texts(document, [declared.summary])), "")
    else:
        summary = "" if document is not None else str(output or "").strip()
    return ReputationRecord(
        service=declared.service or facts.display_name or str(server or ""),
        malicious=malicious,
        suspicious=suspicious,
        total=total,
        engines=_first_whole(document, declared.engines) if declared.engines else None,
        stats=stats,
        labels=_once(_texts(document, declared.labels)),
        detections=_detections(document, declared.detections),
        first_seen=_first_moment(document, declared.first_seen),
        last_seen=_first_moment(document, declared.last_seen),
        link=_first_link(document, declared.link),
        summary=summary,
    )


# ---------------------------------------------------------------------------
# The writer and the reader
# ---------------------------------------------------------------------------


def record_at_write(
    facts_record: Mapping[str, Any] | None,
    *,
    ok: bool,
    output: str,
    structured: Any = None,
    server: str | None = None,
) -> dict[str, Any] | None:
    """The stored record of an answer whose entry stored ``facts_record``, or ``None``.

    ``None`` for a call that did not answer and for a tool that is not a
    declared reputation lookup. Called once, when the entry is written.
    """
    if not ok or not isinstance(facts_record, Mapping):
        return None
    from maljan.core.declared_reading import facts_of

    facts = facts_of({"facts": facts_record})
    if not is_lookup(facts):
        return None
    assert facts is not None
    try:
        return read_answer(facts, output=output, structured=structured, server=server).stored()
    except Exception as exc:  # noqa: BLE001 — a record is never worth a lost entry
        from maljan.core.logger import logger

        logger.debug("reputation record not written (%s).", type(exc).__name__)
        return None


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def stored_record(held: Any) -> ReputationRecord | None:
    """A stored record as a record; ``None`` for one that is absent or cannot be read."""
    if not isinstance(held, Mapping):
        return None
    try:
        return ReputationRecord.model_validate(dict(held))
    except ValueError:
        return None


def holds_a_service_answer(entry: Any) -> bool:
    """Whether an entry's output is the service's own answer, read from its flags alone.

    Not a call that failed (``ok`` false), not a repeat (``repeated_of``: its
    output points at the earlier entry), and not an answer the platform cut or
    replaced (``truncated`` with an output left: the answer the conversation
    had no room for, or one cut to a prefix). An entry the byte budget blanked
    keeps no output and nothing to read, so it reads as nothing either way.
    """
    if _field(entry, "ok") is False or _field(entry, "repeated_of"):
        return False
    return not (_field(entry, "truncated") and str(_field(entry, "output") or ""))


def reputation_of(entry: Any) -> ReputationRecord | None:
    """The reputation record of an entry, or ``None`` when it holds no reputation answer.

    The record the entry stored when it was written. An entry that stored
    none and answered is read the same way now, through the facts it stored
    (an entry with no source and no facts through the facts shipped for its
    tool's name); never through the reading process's settings.
    """
    held = stored_record(_field(entry, "reputation"))
    if held is not None:
        return held
    if not holds_a_service_answer(entry):
        return None
    from maljan.core.declared_reading import facts_of

    facts = facts_of(entry)
    if not is_lookup(facts):
        return None
    assert facts is not None
    return read_answer(
        facts,
        output=str(_field(entry, "output") or ""),
        structured=_field(entry, "structured"),
        server=_field(entry, "server"),
    )


def is_lookup_entry(entry: Any) -> bool:
    """Whether an entry is a call to a reputation lookup, answered or not."""
    from maljan.core.declared_reading import facts_of

    return is_lookup(facts_of(entry))


def asked(rows: Iterable[Any] | None) -> bool:
    """Whether any entry of a ledger is a call to a reputation lookup.

    A row that cannot be read (not an entry, not a mapping) is passed over:
    one malformed row must not cost the answer.
    """
    for row in rows or ():
        if not isinstance(row, Mapping) and not hasattr(row, "tool"):
            continue
        if is_lookup_entry(row):
            return True
    return False


# ---------------------------------------------------------------------------
# The live lookups
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Lookup:
    """One reputation lookup the pack may ask: its server, tool and hash argument."""

    server: str
    tool: str
    hash_argument: str
    rank: int
    enabled: bool


def _shipped_rank(server: str, tool: str) -> int | None:
    """The rank the platform ships for ``server``'s lookup ``tool``, or ``None``."""
    from maljan.core.builtin_declarations import server_declaration

    shipped = (server_declaration(server).get("tool_facts") or {}).get(tool) or {}
    rank = (shipped.get("reputation") or {}).get("rank")
    return rank if isinstance(rank, int) and not isinstance(rank, bool) else None


def _rank(server: str, tool: str, facts: ToolFacts) -> int:
    """A lookup's rank: as declared; one that declares none takes the shipped rank, else 100.

    A server row stored with an edited ``tool_facts`` block written before
    ranks were declared keeps its place in the order the platform ships.
    """
    declared = facts.reputation
    if declared is not None and "rank" in declared.model_fields_set:
        return declared.rank
    shipped = _shipped_rank(server, tool)
    return shipped if shipped is not None else DEFAULT_RANK


def pack_lookups(servers: Mapping[str, Any], declared: ToolDeclarations) -> list[Lookup]:
    """Every server's declared reputation lookup that takes a hash, in the order the pack asks.

    ``servers`` is ``mcp.servers`` in its configured order. The lowest
    ``rank`` first; lookups of one rank in their servers' order, and a
    server's own lookups in their declaration's order.
    """
    found: list[Lookup] = []
    for key, cfg in servers.items():
        held = declared.source(f"mcp:{key}")
        if held is None:
            continue
        for name, facts in held.tools.items():
            argument = facts.arguments.get(HASH_ARGUMENT, "")
            if is_lookup(facts) and argument:
                found.append(
                    Lookup(
                        server=str(key),
                        tool=str(name),
                        hash_argument=argument,
                        rank=_rank(str(key), str(name), facts),
                        enabled=bool(getattr(cfg, "enabled", False)),
                    )
                )
    return sorted(found, key=lambda lookup: lookup.rank)


def lookup_servers(declared: ToolDeclarations) -> set[str]:
    """The keys of every tool server that declares a reputation lookup."""
    return {
        d.source.key
        for d in declared.sources()
        if d.source.kind == "mcp" and any(is_lookup(f) for f in d.tools.values())
    }


def is_lookup_tool(declared: ToolDeclarations, server: str, tool: str) -> bool:
    """Whether ``server``'s tool ``tool`` (a renamed tool's prefix off) is a reputation lookup."""
    return bool(server) and is_lookup(declared.declaration_for((f"mcp:{server}", tool)))
