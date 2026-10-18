"""What a run spent its input on, counted by code from what the run recorded.

``run_summary.efficiency`` is built once, by :func:`efficiency_record`, in the
report node after the run's last model and tool call, and as of the stop for a
run stopped part-way. Every figure in it is counted from a record the run
already keeps — the requests its agents sent (``core.input_meter``), its token
ledger — and none is a model's. The report prints it at the end of the run
summary appendix (:func:`efficiency_lines`); a summary stored without it prints
nothing.

``inputs`` is what each agent loop's requests were made of: one row per tool
loop, and one per agent, stage and kind of single call, each split into the
parts of :data:`core.input_meter.PARTS` in **characters**, with the input
tokens the provider reported for the same requests beside them where it
reported any. ``calls`` is each agent's model calls in the token ledger, so an
agent whose calls the meter did not measure is named rather than left out.

``uncited`` is the evidence no claim cites: of the ledger entries whose tool
ran (a repeat and a guard's answer are not evidence of their own), those whose
id no analyst's final claim names, in its text or its evidence field. A cited
repeat counts for the entry that holds its answer.

``calls`` is the tool calls that cost a step and found nothing new: the ones
the repeat guard answered from an earlier identical call without running
(``repeated``), the ones a guard answered with no tool run at all
(``refused``), and the ones that ran again with the tool, server and arguments
of an earlier call that ran (``run_again``). A read of a cleared answer
(``read_evidence``) is a read, counted under ``rows_read``, not a repeat.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from types import SimpleNamespace
from typing import Any

from maljan.core.input_meter import PARTS, TOOL_LOOP

# The record's shape version: a reader that meets a newer one reads what it knows.
EFFICIENCY_VERSION = 1

INTRO_SENTENCE = (
    "**Efficiency:** counted by code from what this run recorded — the requests its "
    "agents sent, its token ledger and its evidence ledger; no figure here is a model's."
)

# How each part of a request is named in the report.
PART_LABELS: dict[str, str] = {
    "system_prompt": "system prompt",
    "task": "task and data",
    "pack": "pack",
    "run_state": "run state",
    "tool_answers": "tool answers",
    "peer_reports": "peer reports",
    "retries": "retries and questions after an answer",
    "own_turns": "own earlier turns",
    "tool_definitions": "tool definitions",
}


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _ledger_calls(container: Any) -> dict[str, int]:
    """Each agent's model calls in the run's token ledger, or ``{}`` where none is held."""
    ledger_of = getattr(container, "get_token_ledger", None)
    if not callable(ledger_of):
        return {}
    try:
        agents = (ledger_of().snapshot() or {}).get("agents") or {}
    except Exception:  # noqa: BLE001 — a figure the ledger cannot give is left out
        return {}
    return {
        str(name): _int(row.get("llm_calls"))
        for name, row in sorted(agents.items())
        if isinstance(row, Mapping) and _int(row.get("llm_calls"))
    }


def inputs_record(container: Any) -> dict[str, Any] | None:
    """``efficiency.inputs``: the meter's rows and the ledger's calls, or ``None`` with no meter."""
    meter = getattr(container, "input_meter", None)
    rows_of = getattr(meter, "rows", None)
    if not callable(rows_of):
        return None
    try:
        rows = list(rows_of())
    except Exception:  # noqa: BLE001 — a meter that cannot be read leaves the part out
        return None
    return {"unit": "characters", "loops": rows, "calls": _ledger_calls(container)}


def _field(entry: Any, name: str) -> Any:
    """One field of a ledger entry, a model or the dict a state channel holds."""
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _entry_id(entry: Any) -> str:
    return str(_field(entry, "id") or "").strip().lower()


def _ran(entry: Any) -> bool:
    """Whether the entry's tool ran: neither a repeat of another entry nor a guard's answer."""
    return bool(_entry_id(entry)) and not str(_field(entry, "repeated_of") or "").strip()


def _holders(entries: Sequence[Any]) -> dict[str, str]:
    """Each repeat's id, lower-cased, mapped to the id of the entry holding its answer."""
    from maljan.schemas.evidence import repeat_holders

    rows = [SimpleNamespace(id=_entry_id(e), repeated_of=_field(e, "repeated_of")) for e in entries]
    return repeat_holders(rows)


def _claims_of(report: Any) -> list[Any]:
    claims = _field(report, "claims")
    return list(claims) if isinstance(claims, list | tuple) else []


def cited_ids(isr_reports: Mapping[str, Any] | None) -> set[str]:
    """Every entry id an analyst's final claim names, in its text or its evidence field."""
    from maljan.schemas.evidence import entry_ids_in

    cited: set[str] = set()
    for report in (isr_reports or {}).values():
        for claim in _claims_of(report):
            text = f"{_field(claim, 'claim') or ''} {_field(claim, 'evidence_ref') or ''}"
            cited |= entry_ids_in(text)
    return cited


def uncited_record(
    entries: Sequence[Any], isr_reports: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """``efficiency.uncited``: the entries that ran and no claim cites, or ``None`` for none ran."""
    ran = [e for e in entries if _ran(e)]
    if not ran:
        return None
    holders = _holders(entries)
    cited = {holders.get(found) or found for found in cited_ids(isr_reports)}
    uncited = [e for e in ran if _entry_id(e) not in cited]
    by_agent: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for entry in uncited:
        agent = str(_field(entry, "agent") or "") or "pipeline"
        tool = str(_field(entry, "tool") or "")
        by_agent[agent] = by_agent.get(agent, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1
    return {
        "entries": len(ran),
        "cited": len(ran) - len(uncited),
        "uncited": len(uncited),
        "by_agent": dict(sorted(by_agent.items())),
        "by_tool": dict(sorted(by_tool.items())),
        "ids": [_entry_id(e) for e in uncited],
    }


def _reads_again(entry: Any) -> bool:
    """Whether the entry is a read of a cleared answer by its id (``read_evidence``)."""
    from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL

    return str(_field(entry, "tool") or "") == READ_EVIDENCE_TOOL


def _call_key(entry: Any) -> str:
    """A call's tool, server and arguments as one key; arguments in a canonical order."""
    try:
        args = json.dumps(_field(entry, "args") or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        args = str(_field(entry, "args"))
    return json.dumps([str(_field(entry, "server") or ""), str(_field(entry, "tool") or ""), args])


_CALL_COUNTS = ("repeated", "refused", "run_again")


def calls_record(entries: Sequence[Any]) -> dict[str, Any] | None:
    """``efficiency.calls``: repeated, refused and run-again calls, or ``None`` for no ledger."""
    from maljan.schemas.evidence import is_guard_answer

    held = [e for e in entries if _entry_id(e)]
    if not held:
        return None
    totals = dict.fromkeys(_CALL_COUNTS, 0)
    by_agent: dict[str, dict[str, int]] = {}
    by_tool: dict[str, dict[str, int]] = {}
    seen: set[str] = set()
    for entry in held:
        if is_guard_answer({"id": _entry_id(entry), "repeated_of": _field(entry, "repeated_of")}):
            kind = "refused"
        elif not _ran(entry):
            if _reads_again(entry):
                continue
            kind = "repeated"
        else:
            key = _call_key(entry)
            if key not in seen:
                seen.add(key)
                continue
            kind = "run_again"
        totals[kind] += 1
        agent = str(_field(entry, "agent") or "") or "pipeline"
        tool = str(_field(entry, "tool") or "")
        for table, name in ((by_agent, agent), (by_tool, tool)):
            row = table.setdefault(name, dict.fromkeys(_CALL_COUNTS, 0))
            row[kind] += 1
    return {
        **totals,
        "by_agent": dict(sorted(by_agent.items())),
        "by_tool": dict(sorted(by_tool.items())),
    }


def efficiency_record(
    container: Any,
    *,
    entries: Sequence[Any] = (),
    isr_reports: Mapping[str, Any] | None = None,
    partial_reason: str = "",
) -> dict[str, Any] | None:
    """``run_summary.efficiency`` as of now, or ``None`` when the run holds nothing to count.

    ``entries`` is the run's evidence ledger, in order; ``isr_reports`` the
    analysts' final answers. ``partial_reason`` says why the record may miss
    what the step the run stopped in did. Never raises.
    """
    try:
        record: dict[str, Any] = {"v": EFFICIENCY_VERSION}
        inputs = inputs_record(container)
        if inputs is not None:
            record["inputs"] = inputs
        held = list(entries or ())
        uncited = uncited_record(held, isr_reports)
        if uncited is not None:
            record["uncited"] = uncited
        calls = calls_record(held)
        if calls is not None:
            record["calls"] = calls
        if len(record) == 1:
            return None
        if partial_reason:
            record["partial_reason"] = str(partial_reason)
        return record
    except Exception:  # noqa: BLE001 — telemetry must never break a report
        return None


def _share(part: int, total: int) -> str:
    if not total:
        return "0%"
    share = 100.0 * part / total
    return f"{share:.0f}%" if share >= 1 or not part else "<1%"


def _count(n: int, one: str, many: str = "") -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _agent_input_line(agent: str, rows: Sequence[Mapping[str, Any]], calls: int | None) -> str:
    """One agent's requests, summed over its loops and calls, as a sentence."""
    loops = sum(1 for row in rows if row.get("kind") == TOOL_LOOP)
    singles = len(rows) - loops
    requests = sum(_int(row.get("requests")) for row in rows)
    parts = dict.fromkeys(PARTS, 0)
    for row in rows:
        held = row.get("parts")
        if isinstance(held, Mapping):
            for part in PARTS:
                parts[part] += _int(held.get(part))
    total = sum(parts.values())
    shown = ", ".join(
        f"{PART_LABELS[part]} {_share(chars, total)} ({chars:,})"
        for part, chars in parts.items()
        if chars
    )
    what = []
    if loops:
        what.append(_count(loops, "tool loop"))
    if singles:
        what.append(_count(singles, "kind of single call", "kinds of single call"))
    line = (
        f"Input of `{agent}`: {' and '.join(what) or 'no loop'}, {_count(requests, 'request')}, "
        f"{total:,} characters in all"
    )
    if shown:
        line += f" — {shown}"
    reported = sum(_int(row.get("reported_requests")) for row in rows)
    if reported:
        tokens = sum(_int(row.get("input_tokens")) for row in rows)
        line += (
            f". The provider reported {tokens:,} input tokens for {reported:,} of the "
            f"{requests:,} requests"
        )
    else:
        line += ". The provider reported no input tokens for these requests"
    if calls is not None:
        line += f"; the token ledger holds {_count(calls, 'model call')} of this agent"
    return line + "."


def _input_lines(inputs: Mapping[str, Any]) -> list[str]:
    rows = [row for row in inputs.get("loops") or [] if isinstance(row, Mapping)]
    held_calls = inputs.get("calls")
    calls: Mapping[str, Any] = held_calls if isinstance(held_calls, Mapping) else {}
    by_agent: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_agent.setdefault(str(row.get("agent") or ""), []).append(row)
    lines = [
        _agent_input_line(agent, held, _int(calls.get(agent)) if agent in calls else None)
        for agent, held in by_agent.items()
    ]
    unmeasured = [f"`{name}` ({n:,})" for name, n in calls.items() if name not in by_agent]
    if unmeasured:
        lines.append(
            "Not measured by part (model calls in the token ledger): " + ", ".join(unmeasured) + "."
        )
    if lines:
        lines.append(
            "Every part is a character count: no provider reports the tokens of each part "
            "of a prompt, only its total, which is given as reported."
        )
    return lines


def efficiency_lines(record: Any) -> list[str]:
    """The block's sentences, one per line, for a list; ``[]`` for no record."""
    if not isinstance(record, Mapping) or "v" not in record:
        return []
    lines: list[str] = []
    if record.get("partial_reason"):
        lines.append(
            f"These counts may be incomplete: {record['partial_reason']}, and what the step "
            "it stopped in did may not be counted."
        )
    inputs = record.get("inputs")
    if isinstance(inputs, Mapping):
        lines.extend(_input_lines(inputs))
    uncited = record.get("uncited")
    if isinstance(uncited, Mapping):
        lines.append(_uncited_line(uncited))
    calls = record.get("calls")
    if isinstance(calls, Mapping):
        lines.append(_calls_line(calls))
    return lines


def _summed(table: Any) -> dict[str, int]:
    """``{name: {count: n}}`` as ``{name: total}``."""
    if not isinstance(table, Mapping):
        return {}
    return {
        str(name): sum(_int(row.get(kind)) for kind in _CALL_COUNTS)
        for name, row in table.items()
        if isinstance(row, Mapping)
    }


def _calls_line(calls: Mapping[str, Any]) -> str:
    repeated, refused, again = (_int(calls.get(kind)) for kind in _CALL_COUNTS)
    line = (
        f"Tool calls that found nothing new: {repeated:,} answered from an earlier identical "
        f"call without running, {refused:,} refused by a guard with no tool run, and "
        f"{again:,} run again with the tool, server and arguments of an earlier call"
    )
    by_agent = _named_counts(_summed(calls.get("by_agent")))
    if repeated + refused + again and by_agent:
        by_tool = _named_counts(_summed(calls.get("by_tool")))
        line += f" (by agent: {by_agent}; by tool: {by_tool})"
    return line + "."


def _named_counts(counts: Any) -> str:
    """``{name: n}`` as "`a` 3, `b` 1", largest first; "" for none."""
    if not isinstance(counts, Mapping):
        return ""
    rows = sorted(((str(k), _int(v)) for k, v in counts.items()), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"`{name}` {n:,}" for name, n in rows if n)


def _uncited_line(uncited: Mapping[str, Any]) -> str:
    entries, none = _int(uncited.get("entries")), _int(uncited.get("uncited"))
    held = _count(entries, "ledger entry", "ledger entries")
    line = (
        f"Evidence no claim cites: {none:,} of the {held} whose tool ran are cited by no "
        "analyst's final claim"
    )
    by_agent, by_tool = (
        _named_counts(uncited.get("by_agent")),
        _named_counts(uncited.get("by_tool")),
    )
    if none and by_agent:
        line += f" (by agent: {by_agent}; by tool: {by_tool})"
    return line + "."
