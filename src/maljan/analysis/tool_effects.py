"""What each tool a run called does beyond answering, said once, from what the run recorded.

The **effects** part of the run's disclosure record
(``run_summary["disclosure"]["effects"]``), printed in Appendix B under its
own lead sentence after the isolation part. For every tool the run actually
called (each ledger entry that made a call, a repeat or a guard's answer
left out), it says:

* whether the call **runs the sample's code**: no, natively, under emulation,
  or in a sandbox (``ToolEffects.executes``);
* whether the tool **reaches the network** beyond its own server
  (``ToolEffects.network``), or reaches it only in a named way: to refresh
  reference data it keeps, the configured case store, or the operator's own
  sandbox, which is not a third party;
* what of the sample it **sends to a third party**: nothing, its hash or its
  bytes (``ToolEffects.third_party``; the bytes also by
  ``ToolFacts.discloses_sample``, :func:`sends_sample_bytes`).

Each answer is read, in this order, from:

1. the tool's declaration under the source it was called through, as the
   entry stored it when it was written (``LedgerEntry.facts``,
   ``core.declared_reading``): the built-in servers' and providers' shipped
   declarations and an operator's ``tool_facts`` alike, the same mechanism
   every other reading of a tool uses;
2. for the network only, the ``openWorldHint`` the tool's own MCP server gave
   it when it was attached, kept on the entry beside the declaration
   (``core.declared_reading.server_hints``) and said to be the server's own
   hint; ``readOnlyHint``, ``destructiveHint`` and ``idempotentHint`` say
   nothing of these three, and are kept in the part as given;
   before it, a server's own declaration that its tool reaches the network,
   where the block does not trust that declaration
   (``core.declared_reading.served_statement``), said as the server's own
   declaration (``server_stated``); anything else such a declaration said is
   said as the server's own statement and never answers a count;
3. otherwise **undeclared**, said as such and never taken as "no", with the
   reason the declaration gives where it gives one (``why_undeclared``). An
   entry with no recorded source is undeclared on every count: it is never
   read by its tool's name.

**Only a call that completed had an effect.** Each row counts its calls by
how they ended: completed, failed (made, and broke: whether its effect
happened cannot be told), not run (the pipeline wrote that it never made the
call, ``triage_pack.was_not_made``) and refused (a guard answered it with no
tool run, ``schemas.evidence.is_guard_answer``). An effect is said to have
happened only for a tool with a completed call; the others are said as such,
never as having run or sent anything. A repeat of an earlier entry is no call.
The platform's own in-process tools (no source and no server, or a question to
the team) are left out by the rule the disclosure uses
(:func:`is_platform_internal`).

**One source of truth with the disclosure.** Where the sample's bytes were
read is the isolation part (``analysis.isolation``): a tool that ran the
sample's code natively or under emulation is told with the isolation row of
its source. Where they were sent is the disclosure's upload rows, which read
the same rule as this part (:func:`sends_sample_bytes`), so a tool said here
to send the sample's bytes is always a tool upload there. A tool that reaches
the sandbox service its server fronts (``network: operator_sandbox``) is told
where the disclosure placed that call (``places``): the operator's own, not a
third party, only where it is placed on this machine; outside it, at the host
the settings name; and, where the disclosure cannot place it, that it cannot
be told, with the disclosure's own reason.

Never a tool's name. Linear in the entries.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

from maljan.core.tool_declarations import (
    EXECUTES_EMULATION,
    EXECUTES_NATIVE,
    EXECUTES_NO,
    EXECUTES_SANDBOX,
    NETWORK_CASE_STORE,
    NETWORK_ON_REFRESH,
    NETWORK_OPERATOR_SANDBOX,
    THIRD_PARTY_BYTES,
    THIRD_PARTY_HASH,
    THIRD_PARTY_NO,
)

# The version of the part's shape.
EFFECTS_VERSION = 1

# Where an answer came from.
DECLARED = "declared"
SERVER_HINT = "server_hint"
# What a server's own declaration of its tool said, where its block does not
# trust it (``core.served_declarations``): only that it reaches the network.
SERVER_STATED = "server_stated"
# The MCP hint that answers whether a tool reaches the network.
OPEN_WORLD_HINT = "openWorldHint"

INTRO_SENTENCE = (
    "**Tool effects:** what each tool this run called is declared to do beyond answering: run "
    "the sample's code, reach the network, or send the sample's hash or bytes to a third party. "
    "Where the sample's bytes were read is the isolation part above, and where they were sent "
    "the upload rows of the disclosure; a tool whose declaration does not say is listed as "
    "undeclared, and is not taken as safe."
)

# What a missing answer is, as the undeclared line says it.
_UNDECLARED_EXECUTES = "run the sample's code"
_UNDECLARED_NETWORK = "reach the network"
_UNDECLARED_THIRD_PARTY = "send the sample's hash or bytes to a third party"

# The lead of each line that names the tools with an effect.
_RAN = {
    EXECUTES_NATIVE: "Ran the sample's code natively",
    EXECUTES_EMULATION: "Ran the sample's code under emulation",
}
# The lead of each line that names the tools reaching a network in a named way.
_REACHED = {
    NETWORK_OPERATOR_SANDBOX: "Reached the sandbox service its server fronts",
    NETWORK_CASE_STORE: (
        "Reached the configured case-memory store, which the disclosure's case-memory row places"
    ),
    NETWORK_ON_REFRESH: (
        "Reach the network only to fetch or refresh reference data they keep, sending nothing "
        "of the sample"
    ),
}


@dataclass(frozen=True)
class Effects:
    """One tool's three answers, each empty (or ``None``) where nothing says."""

    executes: str = ""
    network: bool | str | None = None
    third_party: str = ""
    network_by: str = ""
    why_undeclared: str = ""
    when: str = ""


# How a call ended, as a row counts it.
COMPLETED = "completed"
FAILED = "failed"
NOT_RUN = "not_run"
REFUSED = "refused"
OUTCOMES: tuple[str, ...] = (COMPLETED, FAILED, NOT_RUN, REFUSED)


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def sends_sample_bytes(facts: Any) -> bool:
    """Whether a declaration says the tool sends the sample's bytes out of the deployment.

    ``discloses_sample``, or ``effects.third_party`` of ``bytes``: either one
    says it. The one rule the disclosure's upload rows and this part read.
    """
    if facts is None:
        return False
    if getattr(facts, "discloses_sample", False) is True:
        return True
    effects = getattr(facts, "effects", None)
    return effects is not None and getattr(effects, "third_party", "") == THIRD_PARTY_BYTES


def entry_effects(entry: Any) -> Effects:
    """What the entry's tool does beyond answering, as the entry stored it; never by its name.

    A declaration that says the tool sends the sample or its hash to a third
    party says it reaches the network too, whatever else it says: the
    cautious answer is kept.
    """
    from maljan.core.declared_reading import (
        declared_only,
        kind_free_facts,
        recorded,
        served_statement,
        server_hints,
    )

    if not recorded(entry):
        return Effects()
    facts = kind_free_facts(declared_only(entry))
    declared = facts.effects
    executes = declared.executes if declared is not None else ""
    network = declared.network if declared is not None else None
    third_party = declared.third_party if declared is not None else ""
    if sends_sample_bytes(facts):
        third_party = THIRD_PARTY_BYTES
    if third_party in (THIRD_PARTY_HASH, THIRD_PARTY_BYTES) and network not in (
        True,
        NETWORK_OPERATOR_SANDBOX,
    ):
        network = True
    network_by = DECLARED if network is not None else ""
    if network is None and served_statement(entry).get("effects.network") is True:
        # What the server itself declared of its tool, where no declaration
        # the operator trusts says: only that it reaches the network.
        network, network_by = True, SERVER_STATED
    if network is None:
        hint = server_hints(entry).get(OPEN_WORLD_HINT)
        if hint is not None:
            network, network_by = hint, SERVER_HINT
    why = declared.why_undeclared if declared is not None else ""
    when = declared.when if declared is not None else ""
    return Effects(executes, network, third_party, network_by, why, when)


def is_platform_internal(entry: Any) -> bool:
    """Whether the entry is the platform's own in-process tool, or a question put to the team.

    No source and no server (or the team's): the rule the disclosure leaves
    such an entry out by, whatever the tool's name.
    """
    from maljan.agents.delegation import TEAM_SERVER

    if _field(entry, "source"):
        return False
    server = str(_field(entry, "server") or "")
    return not server or server == TEAM_SERVER


def outcome(entry: Any) -> str | None:
    """How the entry's call ended (:data:`OUTCOMES`); ``None`` for a repeat, which is no call."""
    from maljan.pipeline.triage_pack import was_not_made
    from maljan.schemas.evidence import is_guard_answer

    if is_guard_answer(entry):
        return REFUSED
    if _field(entry, "repeated_of"):
        return None
    if _field(entry, "ok") is not False:
        return COMPLETED
    return NOT_RUN if was_not_made(entry) else FAILED


def _read_where(isolation: Mapping[str, Any] | None) -> dict[str, tuple[str, bool, str]]:
    """Each source the isolation part placed: where it read, whether isolated, and on what."""
    rows = isolation.get("rows") if isinstance(isolation, Mapping) else None
    out: dict[str, tuple[str, bool, str]] = {}
    for row in rows or []:
        if isinstance(row, Mapping):
            out[str(row.get("source") or "")] = (
                str(row.get("where") or ""),
                row.get("isolated") is True,
                str(row.get("isolated_by") or ""),
            )
    return out


def _least_isolated(
    places: list[str], source: str, placed: Mapping[str, tuple[str, bool, str]]
) -> str:
    """The place a row of several reads as: the least isolated, so none reads safer than it ran.

    The entry's own source (the worker, for the pack) whenever it is among
    them; otherwise a place the isolation part did not place, then one not
    isolated, then the one nearest the worker. ``source`` with no places.
    """
    from maljan.analysis.isolation import _ORDER

    if not places:
        return source
    if source in places:
        return source

    def exposure(place: str) -> tuple[int, int, int]:
        held = placed.get(place)
        if held is None:
            return (0, 0, 0)
        return (1, int(bool(held[1])), _ORDER.get(held[0], len(_ORDER)))

    return min(places, key=exposure)


def effects_part(
    entries: Iterable[Any],
    *,
    isolation: Mapping[str, Any] | None = None,
    partial_reason: str = "",
    places: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """The effects part of the disclosure record: one row per tool the run called.

    ``entries`` are the run's ledger entries; ``isolation`` the record's
    isolation part, which places the sources that read the sample;
    ``partial_reason`` why the record may miss a call; ``places`` where the
    disclosure placed each ``(source, tool)`` it placed. Linear in the entries.
    """
    from maljan.analysis.isolation import ran_on_sources
    from maljan.core.declared_reading import served_statement, server_hints

    placed = _read_where(isolation)
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        ended = outcome(entry)
        if ended is None or is_platform_internal(entry):
            continue
        server = str(_field(entry, "server") or "")
        source = str(_field(entry, "source") or "")
        tool = str(_field(entry, "tool") or "")
        key = (source, "" if source else server, tool)
        row = rows.get(key)
        if row is None:
            effects = entry_effects(entry)
            row = {
                "source": source,
                "server": key[1],
                "tool": tool,
                "calls": 0,
                "executes": effects.executes,
                "network": effects.network,
                "network_by": effects.network_by,
                "third_party": effects.third_party,
                "why_undeclared": effects.why_undeclared,
                "when": effects.when,
                "hints": server_hints(entry),
                **dict.fromkeys(OUTCOMES, 0),
            }
            stated = {
                name: value
                for name, value in served_statement(entry).items()
                if name != "effects.network"
            }
            if stated:
                # What its own server said of it that no declaration says:
                # said as such, never counted as declared.
                row["server_states"] = stated
            if effects.executes in (EXECUTES_NATIVE, EXECUTES_EMULATION):
                # Placed where its readings ran when the entry names a server
                # that ran them (``ran_on``), else by its source.
                reading = _least_isolated(ran_on_sources(entry), source, placed)
                where = placed.get(reading) if reading else None
                row["read_where"] = where[0] if where is not None else None
                row["read_isolated"] = where[1] if where is not None else False
                row["read_isolated_by"] = where[2] if where is not None else ""
            if effects.network == NETWORK_OPERATOR_SANDBOX:
                held = (places or {}).get((source, tool)) or {}
                row["placed_where"] = str(held.get("where") or "")
                row["placed_host"] = str(held.get("host") or "")
                row["placed_why"] = str(
                    held.get("why") or ("" if held else "the disclosure does not place it")
                )
            rows[key] = row
        row["calls"] += 1
        row[ended] += 1
    return {
        "v": EFFECTS_VERSION,
        "partial_reason": str(partial_reason or ""),
        "tools": [rows[key] for key in sorted(rows)],
    }


# ---------------------------------------------------------------------------
# The sentences
# ---------------------------------------------------------------------------


def _code(text: str) -> str:
    return f"`{text}`"


def _joined(items: list[str], word: str = "and") -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {word} " + items[-1]


@cache
def _in_process_labels() -> Mapping[str, str]:
    from maljan.core.builtin_declarations import in_process_declarations

    return {str(ref): cfg.label for ref, cfg in in_process_declarations().items()}


def _label(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    """Where the tool was called through, as a reader is told it."""
    source = str(row.get("source") or "")
    if not source:
        server = str(row.get("server") or "")
        if server:
            return f"tool server {code(server)}, which recorded no source"
        return "the platform's own tools, which record no source"
    labels = _in_process_labels()
    if source in labels:
        return f"{labels[source] or 'the in-process source'} ({code(source)})"
    kind, _, key = source.partition(":")
    if kind == "mcp" and key:
        return f"tool server {code(key)}"
    if kind == "provider" and key:
        return f"the {code(key)} provider's tool server"
    return f"source {code(source)}"


def _read_note(row: Mapping[str, Any]) -> str:
    """Where a tool that ran the sample's code read it, as the isolation part placed its source."""
    from maljan.analysis.isolation import (
        BY_DECLARATION,
        CHILD,
        IN_PROCESS,
        LOCAL_SERVICE,
        REMOTE_SERVICE,
    )

    where = row.get("read_where")
    if where is None:
        return "the isolation part records no read of the sample by its source"
    if where == IN_PROCESS:
        return "read in the worker process itself"
    if where == CHILD:
        kept = (
            "measured as kept from the worker"
            if row.get("read_isolated")
            else "not shown to be kept from the worker"
        )
        if row.get("read_isolated") and row.get("read_isolated_by") == BY_DECLARATION:
            kept = "kept from the worker as its block's declaration of a launcher says"
        return f"read in a process the worker started, {kept}"
    if where == LOCAL_SERVICE:
        return "read at a local server this run does not measure"
    if where == REMOTE_SERVICE:
        return "read outside this machine"
    return "where it read the sample cannot be told"


def _named(
    rows: list[Mapping[str, Any]],
    code: Callable[[str], str],
    note: Callable[[Mapping[str, Any]], str] | None = None,
) -> str:
    """The tools, grouped by where they were called through (and by ``note``), in row order."""
    groups: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        said = note(row) if note is not None else ""
        groups.setdefault((_label(row, code), said), []).append(code(str(row.get("tool") or "")))
    parts = []
    for (label, said), tools in groups.items():
        parts.append(f"{_joined(tools)} on {label}" + (f", {said}" if said else ""))
    return "; ".join(parts)


def _by_hint_only(row: Mapping[str, Any]) -> str:
    if row.get("network_by") == SERVER_STATED:
        return "by its server's own declaration, which its block does not trust"
    return "by its server's own hint" if row.get("network_by") == SERVER_HINT else ""


def _server_states(row: Mapping[str, Any]) -> str:
    held = row.get("server_states")
    if not isinstance(held, Mapping):
        return ""
    return ", ".join(f"{name} {value}" for name, value in sorted(held.items()))


def _when(row: Mapping[str, Any]) -> str:
    return str(row.get("when") or "")


def _with_when(note: Callable[[Mapping[str, Any]], str]) -> Callable[[Mapping[str, Any]], str]:
    def _both(row: Mapping[str, Any]) -> str:
        return ", ".join(part for part in (_when(row), note(row)) if part)

    return _both


def _sandbox_place(code: Callable[[str], str]) -> Callable[[Mapping[str, Any]], str]:
    """Where the disclosure placed a call to the sandbox service a tool's server fronts."""
    from maljan.core.host_locality import LOCAL, REMOTE

    def _note(row: Mapping[str, Any]) -> str:
        where, host = row.get("placed_where"), str(row.get("placed_host") or "")
        if where == LOCAL and host and not row.get("placed_why"):
            return (
                f"at {code(host)}, which the disclosure places on this machine, so the "
                "operator's own and not a third party"
            )
        if where == REMOTE and host:
            return (
                f"at {code(host)}, outside this machine; whether it is the operator's own the "
                "settings do not say"
            )
        why = str(row.get("placed_why") or "the record does not say")
        return f"where it went cannot be told: {why}"

    return _note


def _missing(row: Mapping[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    if not row.get("executes"):
        out.append(_UNDECLARED_EXECUTES)
    if row.get("network") is None:
        out.append(_UNDECLARED_NETWORK)
    if not row.get("third_party"):
        out.append(_UNDECLARED_THIRD_PARTY)
    return tuple(out)


def _closed(row: Mapping[str, Any]) -> bool:
    """Whether the row's tool is declared to do none of the three."""
    return (
        row.get("network") is False
        and row.get("network_by") == DECLARED
        and row.get("executes") == EXECUTES_NO
        and row.get("third_party") == THIRD_PARTY_NO
    )


def _of_calls(state: str) -> Callable[[Mapping[str, Any]], str]:
    def _note(row: Mapping[str, Any]) -> str:
        count, calls = int(row.get(state) or 0), int(row.get("calls") or 0)
        return f"{count} of {calls} calls" if count != calls else ""

    return _note


# What a call that did not complete is said to be, by how it ended.
_ENDED = {
    NOT_RUN: "Was not run, so none of its declared effects happened",
    REFUSED: "Was refused, so nothing was sent",
    FAILED: "Failed, so whether its declared effects happened cannot be told",
}


def effects_lines(part: Any, code: Callable[[str], str] = _code) -> list[str]:
    """The part's sentences, one per line; ``[]`` for a record without the part.

    An effect is said for the tools with a completed call only; a tool whose
    calls failed, were not run or were refused is said as such.
    """
    if not isinstance(part, Mapping) or "tools" not in part:
        return []
    every = [row for row in part.get("tools") or [] if isinstance(row, Mapping)]
    # A row stored before calls were counted by how they ended holds only
    # ``calls``: each is read as completed, as it was then.
    rows = [row for row in every if int(row.get(COMPLETED, row.get("calls")) or 0)]
    lines: list[str] = []
    if part.get("partial_reason"):
        lines.append(
            f"This part may be incomplete: {part['partial_reason']}, and a call made in the step "
            "it stopped in may not be recorded."
        )
    if not every:
        lines.append("This run recorded no tool call, so no tool's effects are said.")
        return lines
    for mode in (EXECUTES_NATIVE, EXECUTES_EMULATION):
        ran = [row for row in rows if row.get("executes") == mode]
        if ran:
            lines.append(f"{_RAN[mode]}: {_named(ran, code, _with_when(_read_note))}.")
    place = _sandbox_place(code)
    own = [
        row
        for row in rows
        if row.get("executes") == EXECUTES_SANDBOX
        and row.get("network") == NETWORK_OPERATOR_SANDBOX
    ]
    if own:
        lines.append(
            f"Had the sample run in the sandbox service its server fronts: "
            f"{_named(own, code, place)}."
        )
    theirs = [
        row
        for row in rows
        if row.get("executes") == EXECUTES_SANDBOX
        and row.get("network") != NETWORK_OPERATOR_SANDBOX
    ]
    if theirs:
        lines.append(
            f"Handed the sample to a third party's sandbox, which may run it: "
            f"{_named(theirs, code, _when)}."
        )
    reached = [row for row in rows if row.get("network") is True]
    if reached:
        lines.append(f"Reached the network: {_named(reached, code, _by_hint_only)}.")
    for mode, lead in _REACHED.items():
        held = [row for row in rows if row.get("network") == mode]
        if held:
            note = place if mode == NETWORK_OPERATOR_SANDBOX else None
            lines.append(f"{lead}: {_named(held, code, note)}.")
    hashed = [row for row in rows if row.get("third_party") == THIRD_PARTY_HASH]
    if hashed:
        lines.append(f"Sent the sample's hash to a third party: {_named(hashed, code)}.")
    sent = [row for row in rows if row.get("third_party") == THIRD_PARTY_BYTES]
    handed = [row for row in sent if row.get("network") == NETWORK_OPERATOR_SANDBOX]
    out = [row for row in sent if row.get("network") != NETWORK_OPERATOR_SANDBOX]
    if handed:
        lines.append(
            f"Handed the sample's bytes to the sandbox service its server fronts: "
            f"{_named(handed, code, place)}; where each call sent them is in the upload rows "
            "of the disclosure above."
        )
    if out:
        lines.append(
            f"Sent the sample's bytes to a third party: {_named(out, code)}; where each "
            "call sent them is in the upload rows of the disclosure above."
        )
    declared = [row for row in every if _closed(row)]
    if declared:
        places = list(dict.fromkeys(_label(row, code) for row in declared))
        lines.append(
            f"Declared to do none of these: {len(declared)} "
            f"{'tool' if len(declared) == 1 else 'tools'}, on {_joined(places)}."
        )
    hinted = [
        row for row in rows if row.get("network") is False and row.get("network_by") == SERVER_HINT
    ]
    if hinted:
        lines.append(
            f"Said not to reach the network by its server's own hint ({OPEN_WORLD_HINT} false), "
            f"which no declaration says: {_named(hinted, code)}."
        )
    stated = [row for row in rows if isinstance(row.get("server_states"), Mapping)]
    if stated:
        lines.append(
            "Said of itself by its own server, which no declaration the operator trusts says: "
            f"{_named(stated, code, _server_states)}."
        )
    for state, lead in _ENDED.items():
        held = [row for row in every if int(row.get(state) or 0) and not _closed(row)]
        if held:
            lines.append(f"{lead}: {_named(held, code, _of_calls(state))}.")
    groups: dict[tuple[tuple[str, ...], str], list[Mapping[str, Any]]] = {}
    for row in every:
        made = int(row.get(COMPLETED, row.get("calls")) or 0) + int(row.get(FAILED) or 0)
        missing = _missing(row)
        if missing and made:
            why = str(row.get("why_undeclared") or "")
            groups.setdefault((missing, why), []).append(row)
    for (missing, why), held in groups.items():
        lines.append(
            f"Undeclared whether it may {_joined(list(missing), 'or')}, so not taken as safe: "
            f"{_named(held, code)}" + (f"; its declaration says why: {why}" if why else "") + "."
        )
    return lines
