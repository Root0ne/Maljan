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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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


def efficiency_record(
    container: Any,
    *,
    partial_reason: str = "",
) -> dict[str, Any] | None:
    """``run_summary.efficiency`` as of now, or ``None`` when the run holds nothing to count.

    ``partial_reason`` says why the record may miss what the step the run
    stopped in did. Never raises.
    """
    try:
        record: dict[str, Any] = {"v": EFFICIENCY_VERSION}
        inputs = inputs_record(container)
        if inputs is not None:
            record["inputs"] = inputs
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
    return lines
