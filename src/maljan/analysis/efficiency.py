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
reported any. ``calls`` is each agent's model calls as the summary's ``tokens``
block states them, so an agent whose calls the meter did not measure is named
rather than left out.

``uncited`` is the evidence nothing cites: of the ledger entries whose tool
ran and answered (a repeat and a guard's answer are not evidence of their own,
and a failed call is not evidence: those are counted apart as ``failed``),
those no analyst's final answer names — a claim in its text or its evidence
field, a finding or an artifact (a finding's own artifacts included) in its
``evidence_ids``. A cited repeat counts for the entry that holds its answer.

``calls`` is the tool calls that cost a step and found nothing new: the ones
the repeat guard answered from an earlier identical call without running
(``repeated``), the ones a guard answered with no tool run at all
(``refused``), the ones that ran again with the tool, server and arguments of
an earlier call the same maker ran (``run_again``, or ``retried_after_failure``
where that earlier call failed, the guard's own reason to serve it again), and
the ones identical to a call another maker ran first
(``same_call_elsewhere``). Each is filed under the maker of the call: the
agent that made it, the triage pack (``pack``) or the pipeline otherwise. A read of a cleared answer
(``read_evidence``) is a read, counted under ``rows_read``, not a repeat.

``rows_read`` is the ledger and pack rows each agent read back by id through
``read_evidence``: every read is filed as a repeat of the row it reads, so the
row is the entry holding the read's answer. Per row, who read it and how
often, its tool, and whether it is a pack row (an entry the triage pack wrote,
``pack_step``); a read whose id named no row the ledger holds is counted apart.
A read is not evidence of its own and is not counted under ``uncited`` or
``calls``.

``output`` is each agent's output in the token ledger, and of it the share its
validation retries (a retry, and the whole answer asked for after a retry that
could not be merged) and its drops questions took: provider-reported output
tokens only, with the calls that reported none counted beside them.

``fingerprint`` is one sha256 over how the job was set up (H5), never over
what the run sent: every system prompt the platform can send for the job, read
from where each is built (``analysis.setup_prompts``); the definitions of the
tools each agent was resolved with, as bound; the name and version each tool
server attached by then gave for itself; and the settings the run ran with,
masked as the stored snapshot masks them. A retry, a revision round, a cleared
tool answer or the mediator's fast path does not move it; editing any built-in
prompt does. Each of the four is hashed on its own (``components``), and each
per prompt, agent, server or settings section (``parts``), so two fingerprints
that differ name what changed. The sample does not move it either: an agent's
prompt is composed with the neutral format fragment (every fragment is hashed
as its template), and the job's own identifiers the platform writes in — the
sample's sha256, its paths and file name, the job id, taken from the job's
known values (``core.input_meter.job_identifiers``) — are masked as whole
tokens. Nor does the host: the paths that belong to it (the checkout, the
interpreter's environment, the home and working directories) are replaced in
the settings before they are hashed. Secrets never enter it: only the masked view of the settings is
hashed, where a secret reads as set or unset. A tool's own version is not
reported over MCP and is not in it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
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


def _per_agent(tokens: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    """Each named agent's row of the summary's ``tokens`` block, the figures the summary states.

    Read from the block rather than from the ledger again, so the record and
    the summary state one set of numbers; an agent with no name has no row.
    """
    rows = (tokens or {}).get("per_agent") if isinstance(tokens, Mapping) else None
    if not isinstance(rows, Mapping):
        return {}
    return {
        str(name): row
        for name, row in sorted(rows.items())
        if str(name).strip() and isinstance(row, Mapping)
    }


def _ledger_calls(tokens: Mapping[str, Any] | None) -> dict[str, int]:
    """Each named agent's model calls as the summary's ``tokens`` block states them."""
    return {
        name: _int(row.get("llm_calls"))
        for name, row in _per_agent(tokens).items()
        if _int(row.get("llm_calls"))
    }


def inputs_record(container: Any, tokens: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """``efficiency.inputs``: the meter's rows and the summary's calls; ``None`` with no meter."""
    meter = getattr(container, "input_meter", None)
    rows_of = getattr(meter, "rows", None)
    if not callable(rows_of):
        return None
    try:
        rows = list(rows_of())
    except Exception:  # noqa: BLE001 — a meter that cannot be read leaves the part out
        return None
    named = [row for row in rows if str(row.get("agent") or "").strip()]
    return {"unit": "characters", "loops": named, "calls": _ledger_calls(tokens)}


def _field(entry: Any, name: str) -> Any:
    """One field of a ledger entry, a model or the dict a state channel holds."""
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def _maker(entry: Any) -> str:
    """Who made the call: its agent, ``pack`` for the triage pack, ``pipeline`` otherwise."""
    agent = str(_field(entry, "agent") or "").strip()
    if agent:
        return agent
    return "pack" if _field(entry, "pack_step") is not None else "pipeline"


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


def _items_of(holder: Any, name: str) -> list[Any]:
    items = _field(holder, name)
    return list(items) if isinstance(items, list | tuple) else []


def _evidence_ids_of(item: Any) -> set[str]:
    from maljan.schemas.evidence import entry_ids_in

    return entry_ids_in(" ".join(str(i) for i in _items_of(item, "evidence_ids")))


def cited_ids(isr_reports: Mapping[str, Any] | None) -> set[str]:
    """Every entry id an analyst's final answer names.

    A claim in its text or its evidence field; a finding, an artifact, and a
    finding's own artifacts in their ``evidence_ids``.
    """
    from maljan.schemas.evidence import entry_ids_in

    cited: set[str] = set()
    for report in (isr_reports or {}).values():
        for claim in _claims_of(report):
            text = f"{_field(claim, 'claim') or ''} {_field(claim, 'evidence_ref') or ''}"
            cited |= entry_ids_in(text)
        for finding in _items_of(report, "findings"):
            cited |= _evidence_ids_of(finding)
            for artifact in _items_of(finding, "artifacts"):
                cited |= _evidence_ids_of(artifact)
        for artifact in _items_of(report, "artifacts"):
            cited |= _evidence_ids_of(artifact)
    return cited


def uncited_record(
    entries: Sequence[Any], isr_reports: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """``efficiency.uncited``: the entries that answered and nothing cites, or ``None``.

    ``None`` when no call ran. A failed call is not evidence: it is counted as
    ``failed`` and left out of the rest.
    """
    called = [e for e in entries if _ran(e) and not _reads_again(e)]
    if not called:
        return None
    ran = [e for e in called if _field(e, "ok") is not False]
    holders = _holders(entries)
    cited = {holders.get(found) or found for found in cited_ids(isr_reports)}
    uncited = [e for e in ran if _entry_id(e) not in cited]
    by_agent: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for entry in uncited:
        agent = _maker(entry)
        tool = str(_field(entry, "tool") or "")
        by_agent[agent] = by_agent.get(agent, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1
    return {
        "entries": len(ran),
        "cited": len(ran) - len(uncited),
        "uncited": len(uncited),
        "failed": len(called) - len(ran),
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


# ``retried_after_failure`` is the platform's intended re-run: the repeat guard
# serves an identical call again when the earlier one failed (a retry after a
# transient failure, its own stated reason, read from the ``ok`` of the entry it
# repeats). ``run_again`` is every other identical call that ran: the agent's.
_CALL_COUNTS = (
    "repeated",
    "refused",
    "run_again",
    "retried_after_failure",
    "same_call_elsewhere",
)


def calls_record(entries: Sequence[Any]) -> dict[str, Any] | None:
    """``efficiency.calls``: repeated, refused and run-again calls, or ``None`` for no ledger."""
    from maljan.schemas.evidence import is_guard_answer

    held = [e for e in entries if _entry_id(e)]
    if not held:
        return None
    totals = dict.fromkeys(_CALL_COUNTS, 0)
    by_agent: dict[str, dict[str, int]] = {}
    by_tool: dict[str, dict[str, int]] = {}
    # Each maker's last run of each call, and whether it failed; and every
    # call any maker ran.
    last_failed: dict[tuple[str, str], bool] = {}
    ran_by_anyone: set[str] = set()
    for entry in held:
        if _reads_again(entry):
            continue
        if is_guard_answer({"id": _entry_id(entry), "repeated_of": _field(entry, "repeated_of")}):
            kind = "refused"
        elif not _ran(entry):
            kind = "repeated"
        else:
            key = _call_key(entry)
            own = (_maker(entry), key)
            earlier = last_failed.get(own)
            last_failed[own] = _field(entry, "ok") is False
            if earlier is not None:
                kind = "retried_after_failure" if earlier else "run_again"
            elif key in ran_by_anyone:
                kind = "same_call_elsewhere"
            else:
                ran_by_anyone.add(key)
                continue
            ran_by_anyone.add(key)
        totals[kind] += 1
        agent = _maker(entry)
        tool = str(_field(entry, "tool") or "")
        for table, name in ((by_agent, agent), (by_tool, tool)):
            row = table.setdefault(name, dict.fromkeys(_CALL_COUNTS, 0))
            row[kind] += 1
    return {
        **totals,
        "by_agent": dict(sorted(by_agent.items())),
        "by_tool": dict(sorted(by_tool.items())),
    }


def rows_read_record(entries: Sequence[Any]) -> dict[str, Any] | None:
    """``efficiency.rows_read``: the rows read back through ``read_evidence``, or ``None``.

    ``None`` for a ledger with no entry; a ledger no read was made from reads
    as zero reads.
    """
    held = [e for e in entries if _entry_id(e)]
    if not held:
        return None
    by_id = {_entry_id(e): e for e in held}
    holders = _holders(held)
    rows: dict[str, dict[str, Any]] = {}
    by_agent: dict[str, dict[str, Any]] = {}
    reads = unfound = 0
    for entry in held:
        if not _reads_again(entry):
            continue
        reads += 1
        agent = _maker(entry)
        tally = by_agent.setdefault(agent, {"reads": 0, "rows": set(), "pack_rows": set()})
        tally["reads"] += 1
        first = str(_field(entry, "repeated_of") or "").strip().lower()
        wanted = holders.get(_entry_id(entry)) if first else ""
        row = by_id.get(wanted or "")
        if row is None or not first:
            unfound += 1
            continue
        pack = _field(row, "pack_step") is not None
        found = rows.setdefault(
            wanted or "",
            {"id": wanted, "tool": str(_field(row, "tool") or ""), "pack": pack, "by": {}},
        )
        found["by"][agent] = found["by"].get(agent, 0) + 1
        tally["rows"].add(wanted)
        if pack:
            tally["pack_rows"].add(wanted)
    record: dict[str, Any] = {
        "reads": reads,
        "rows": list(rows.values()),
        "by_agent": {
            name: {
                "reads": tally["reads"],
                "rows": len(tally["rows"]),
                "pack_rows": len(tally["pack_rows"]),
            }
            for name, tally in sorted(by_agent.items())
        },
    }
    if unfound:
        record["unfound"] = unfound
    return record


def _kinds() -> dict[str, frozenset[str]]:
    from maljan.core.token_ledger import (
        RETRY_DROPS_QUESTION_CALL,
        VALIDATION_RETRY_CALL,
        WHOLE_ANSWER_RETRY_CALL,
    )

    return {
        "retry": frozenset({VALIDATION_RETRY_CALL, WHOLE_ANSWER_RETRY_CALL}),
        "drop_question": frozenset({RETRY_DROPS_QUESTION_CALL}),
    }


def _tally(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "calls": sum(_int(r.get("calls")) for r in rows),
        "unreported_calls": sum(_int(r.get("unreported_calls")) for r in rows),
        "output_tokens": sum(_int(r.get("output_tokens")) for r in rows),
    }


def output_record(container: Any, tokens: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """``efficiency.output``: per agent, its output and the retries' and drops questions' share.

    An agent's calls, calls with no usage and output are the summary's
    ``tokens`` block's own figures; only the split by call name, which the
    block does not hold, is read from the ledger (``TokenLedger.by_call``).
    ``None`` where the summary states no agent's tokens.
    """
    per_agent = _per_agent(tokens)
    if not per_agent:
        return None
    ledger_of = getattr(container, "get_token_ledger", None)
    by_call_of = getattr(ledger_of(), "by_call", None) if callable(ledger_of) else None
    by_agent = by_call_of() if callable(by_call_of) else {}
    by_agent = by_agent if isinstance(by_agent, Mapping) else {}
    kinds = _kinds()
    out: dict[str, Any] = {}
    for agent, stated in per_agent.items():
        calls = by_agent.get(agent)
        calls = calls if isinstance(calls, Mapping) else {}
        rows = {str(name): row for name, row in calls.items() if isinstance(row, Mapping)}
        out[agent] = {
            "calls": _int(stated.get("llm_calls")),
            "unreported_calls": _int(stated.get("unreported_calls")),
            "output_tokens": _int(stated.get("output_tokens")),
            **{
                kind: _tally([row for name, row in rows.items() if name in names])
                for kind, names in kinds.items()
            },
        }
    return out


def _hash(value: Any) -> str:
    """The sha256 of ``value`` serialised with its keys in order."""
    from maljan.core.input_meter import digest

    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str))


def masked_settings(config: Any) -> dict[str, Any]:
    """The settings the run ran with, masked as the stored snapshot masks them, flattened.

    ``settings_overrides.public_snapshot`` with every catalogue path typed as a
    secret: a secret's value is replaced by whether it is set.
    """
    from maljan.core.settings_catalog import core_catalog
    from maljan.core.settings_overrides import public_snapshot

    secrets = [entry.path for entry in core_catalog() if entry.secret]
    return public_snapshot(config, secrets)


def host_paths() -> list[tuple[str, str]]:
    """``(path, placeholder)`` for each path that belongs to this host, longest first.

    The checkout the code runs from, the interpreter's environment and the one
    it was built from, the home directory and the working directory: a tool
    server's launch command and working directory name them, and the same
    setup on another host or in another worktree names others.
    """
    import os
    import sys
    from pathlib import Path

    # In rising order of what a path says, so where two are the same path the
    # later name is the one kept on every host.
    candidates = [
        (os.getcwd(), "<cwd>"),
        (str(Path.home()), "<home>"),
        (sys.base_prefix, "<interpreter>"),
        (sys.prefix, "<environment>"),
        (str(Path(__file__).resolve().parents[3]), "<checkout>"),
    ]
    held = {path.rstrip("/"): mark for path, mark in candidates if path.strip("/")}
    return sorted(held.items(), key=lambda pair: -len(pair[0]))


def _without_host(value: Any, host: Sequence[tuple[str, str]]) -> Any:
    """``value`` with every path of ``host`` in its strings replaced by its placeholder."""
    if isinstance(value, str):
        for path, mark in host:
            value = re.sub(rf"(?<![\w.-]){re.escape(path)}(?![\w.-])", mark, value)
        return value
    if isinstance(value, list):
        return [_without_host(item, host) for item in value]
    if isinstance(value, dict):
        return {key: _without_host(item, host) for key, item in value.items()}
    return value


def _settings_sections(
    config: Any, host: Sequence[tuple[str, str]] | None = None
) -> dict[str, str]:
    """Each top-level settings section's hash, over its masked leaves with this host's paths out.

    A server's declared identity and arguments are hashed with the paths that
    belong to this host (:func:`host_paths`) replaced, so the same setup on two
    hosts or in two worktrees hashes equal.
    """
    held = host_paths() if host is None else list(host)
    sections: dict[str, dict[str, Any]] = {}
    for key, value in masked_settings(config).items():
        sections.setdefault(str(key).split(".", 1)[0], {})[str(key)] = _without_host(value, held)
    return {name: _hash(leaves) for name, leaves in sorted(sections.items())}


def fingerprint_record(container: Any) -> dict[str, Any] | None:
    """``efficiency.fingerprint`` from the job's setup, or ``None`` outside a job.

    Read from the container's setup alone — its settings, the agents it
    resolved and the servers attached by then — never from the requests a run
    sent. A part the job could not give (no agent resolved yet, settings that
    would not dump) is named in ``unread`` and hashed as what it holds, so the
    fingerprint still says what it is made of.
    """
    from maljan.analysis.setup_prompts import setup_prompts
    from maljan.core.input_meter import job_identifiers, tool_digests, without_identifiers

    config = getattr(container, "config", None)
    resolved_of = getattr(container, "resolved_agents", None)
    servers_of = getattr(container, "setup_server_versions", None)
    if config is None and not callable(resolved_of) and not callable(servers_of):
        return None
    unread: list[str] = []
    parts: dict[str, dict[str, Any]] = {"prompts": {}, "tools": {}, "servers": {}, "settings": {}}
    identifiers = job_identifiers(container)

    def mask(text: str) -> str:
        return without_identifiers(text, identifiers)

    try:
        parts["prompts"] = {
            name: _hash(texts) for name, texts in sorted(setup_prompts(container, mask).items())
        }
    except Exception:  # noqa: BLE001 — an unread part is named, never guessed
        unread.append("prompts")
    resolved = resolved_of() if callable(resolved_of) else {}
    if not resolved:
        unread.append("agents")
    try:
        parts["tools"] = {
            str(key): _hash(tool_digests(getattr(agent, "tools", None) or []))
            for key, agent in sorted(resolved.items())
        }
    except Exception:  # noqa: BLE001 — an unread part is named, never guessed
        unread.append("tools")
    try:
        parts["servers"] = dict(servers_of()) if callable(servers_of) else {}
    except Exception:  # noqa: BLE001 — an unread part is named, never guessed
        unread.append("servers")
    try:
        parts["settings"] = _settings_sections(config) if config is not None else {}
    except Exception:  # noqa: BLE001 — an unread part is named, never guessed
        parts["settings"] = {}
    if config is None or not parts["settings"]:
        unread.append("settings")
    components = {name: _hash(held) for name, held in parts.items()}
    record: dict[str, Any] = {"sha256": _hash(components), "components": components, "parts": parts}
    if unread:
        record["unread"] = sorted(set(unread))
    return record


def efficiency_record(
    container: Any,
    *,
    entries: Sequence[Any] = (),
    isr_reports: Mapping[str, Any] | None = None,
    tokens: Mapping[str, Any] | None = None,
    partial_reason: str = "",
) -> dict[str, Any] | None:
    """``run_summary.efficiency`` as of now, or ``None`` when the run holds nothing to count.

    ``entries`` is the run's evidence ledger, in order; ``isr_reports`` the
    analysts' final answers; ``tokens`` the summary's own ``tokens`` block, whose
    figures the record states. ``partial_reason`` says why the record may miss
    what the step the run stopped in did. Never raises.
    """
    try:
        record: dict[str, Any] = {"v": EFFICIENCY_VERSION}
        inputs = inputs_record(container, tokens)
        if inputs is not None:
            record["inputs"] = inputs
        held = list(entries or ())
        uncited = uncited_record(held, isr_reports)
        if uncited is not None:
            record["uncited"] = uncited
        calls = calls_record(held)
        if calls is not None:
            record["calls"] = calls
        rows_read = rows_read_record(held)
        if rows_read is not None:
            record["rows_read"] = rows_read
        output = output_record(container, tokens)
        if output is not None:
            record["output"] = output
        fingerprint = fingerprint_record(container)
        if fingerprint is not None:
            record["fingerprint"] = fingerprint
        if len(record) == 1:
            return None
        if partial_reason:
            record["partial_reason"] = str(partial_reason)
        return record
    except Exception:  # noqa: BLE001 — telemetry must never break a report
        return None


# How the block being written prints a value that came from a run — an agent's,
# a tool's or a server's name, a version, a hash — set by :func:`efficiency_lines`.
_CODE: ContextVar[Callable[[str], str] | None] = ContextVar("efficiency_code", default=None)


def _guarded(text: str) -> str:
    """``text`` as the report prints any value it did not write: one line, one code span."""
    from maljan.reporting.renderers.markdown import _code_span, _one_line

    return _code_span(_one_line(text))


def _c(value: Any) -> str:
    """A run-supplied value as the block prints it (:data:`_CODE`, else the report's guard)."""
    code = _CODE.get()
    return code(str(value)) if code is not None else _guarded(str(value))


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
        f"Input of {_c(agent)}: {' and '.join(what) or 'no loop'}, {_count(requests, 'request')}, "
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
    unmeasured = [f"{_c(name)} ({n:,})" for name, n in calls.items() if name not in by_agent]
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


def efficiency_lines(record: Any, code: Callable[[str], str] | None = None) -> list[str]:
    """The block's sentences, one per line, for a list; ``[]`` for no record.

    ``code`` prints a value the run supplied (a name, a version, a hash) as the
    report prints every value it did not write; the report's own guard
    (``_code_span`` over one line) when none is given.
    """
    if not isinstance(record, Mapping) or "v" not in record:
        return []
    token = _CODE.set(code)
    try:
        return _lines(record)
    finally:
        _CODE.reset(token)


def _lines(record: Mapping[str, Any]) -> list[str]:
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
    rows_read = record.get("rows_read")
    if isinstance(rows_read, Mapping):
        lines.append(_rows_read_line(rows_read))
    output = record.get("output")
    if isinstance(output, Mapping):
        lines.extend(_output_lines(output))
    fingerprint = record.get("fingerprint")
    if isinstance(fingerprint, Mapping):
        lines.extend(_fingerprint_lines(fingerprint))
    return lines


# How each component of the fingerprint is named in the report.
_COMPONENT_LABELS = {
    "prompts": "system prompts as set up",
    "tools": "tool definitions as bound",
    "servers": "server names and versions",
    "settings": "masked settings",
}


def _fingerprint_lines(fingerprint: Mapping[str, Any]) -> list[str]:
    components = fingerprint.get("components")
    components = components if isinstance(components, Mapping) else {}
    shown = "; ".join(
        f"{label} {_c(str(components.get(name) or '')[:12])}"
        for name, label in _COMPONENT_LABELS.items()
        if name in components
    )
    line = f"Run fingerprint: {_c(fingerprint.get('sha256') or '')}"
    if shown:
        line += f" (sha256 of its components: {shown})"
    unread = [str(name) for name in fingerprint.get("unread") or []]
    if unread:
        line += f"; not read, and hashed as empty: {', '.join(unread)}"
    lines = [line + "."]
    parts = fingerprint.get("parts")
    servers = parts.get("servers") if isinstance(parts, Mapping) else None
    if isinstance(servers, Mapping) and servers:
        said = []
        for key, info in servers.items():
            info = info if isinstance(info, Mapping) else {}
            name, version = info.get("name"), info.get("version")
            text = _c(key)
            if name:
                text += f" as {_c(name)}"
            text += f" version {_c(version)}" if version else ", no version given"
            said.append(text)
        lines.append(
            "Tool servers as they gave themselves at attach: "
            + "; ".join(said)
            + ". A tool's own version is not reported over MCP."
        )
    return lines


def _kind_clause(what: str, part: Mapping[str, Any], total: int) -> str:
    calls, tokens = _int(part.get("calls")), _int(part.get("output_tokens"))
    clause = f"{what} {tokens:,} ({_share(tokens, total)}, {_count(calls, 'call')}"
    unreported = _int(part.get("unreported_calls"))
    if unreported:
        clause += f", {unreported:,} of them reporting no usage"
    return clause + ")"


def _output_lines(output: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for agent, row in output.items():
        if not isinstance(row, Mapping):
            continue
        retry, drop = row.get("retry"), row.get("drop_question")
        retry = retry if isinstance(retry, Mapping) else {}
        drop = drop if isinstance(drop, Mapping) else {}
        if not (_int(retry.get("calls")) or _int(drop.get("calls"))):
            continue
        total = _int(row.get("output_tokens"))
        line = (
            f"Output of {_c(agent)}: of its {total:,} reported output tokens, "
            f"{_kind_clause('validation retries', retry, total)} and "
            f"{_kind_clause('drops questions', drop, total)}"
        )
        unreported = _int(row.get("unreported_calls"))
        if unreported:
            line += f"; {_count(unreported, 'call')} of the agent's reported no usage"
        lines.append(line + ".")
    if not lines and output:
        lines.append("Output: no validation retry and no drops question was asked.")
    return lines


def _rows_read_line(rows_read: Mapping[str, Any]) -> str:
    reads = _int(rows_read.get("reads"))
    if not reads:
        return "Rows read back by id (read_evidence): none."
    parts = []
    for agent, tally in (rows_read.get("by_agent") or {}).items():
        if not isinstance(tally, Mapping):
            continue
        rows, pack = _int(tally.get("rows")), _int(tally.get("pack_rows"))
        parts.append(
            f"{_c(agent)} {_count(_int(tally.get('reads')), 'read')} of "
            f"{_count(rows, 'row')} ({pack:,} of them pack rows)"
        )
    line = f"Rows read back by id (read_evidence): {_count(reads, 'read')}"
    if parts:
        line += " — " + ", ".join(parts)
    unfound = _int(rows_read.get("unfound"))
    if unfound:
        line += f"; {_count(unfound, 'read')} named no row the ledger holds"
    return line + "."


def _summed(table: Any) -> dict[str, int]:
    """``{name: {count: n}}`` as ``{name: total}``."""
    if not isinstance(table, Mapping):
        return {}
    return {
        str(name): sum(_int(row.get(kind)) for kind in _CALL_COUNTS)
        for name, row in table.items()
        if isinstance(row, Mapping)
    }


# How each count is said for one maker.
_CALL_WORDS = {
    "repeated": "answered from its earlier identical call without running",
    "refused": "refused by a guard with no tool run",
    "run_again": "run again after its own earlier identical call",
    "retried_after_failure": "retried after its own earlier identical call failed",
    "same_call_elsewhere": "identical to a call another maker ran first",
}


def _maker_label(name: str) -> str:
    return {"pack": "the triage pack", "pipeline": "the pipeline"}.get(name) or _c(name)


def _calls_line(calls: Mapping[str, Any]) -> str:
    counts = {kind: _int(calls.get(kind)) for kind in _CALL_COUNTS}
    line = (
        f"Tool calls that found nothing new: {counts['repeated']:,} answered from an earlier "
        f"identical call without running, {counts['refused']:,} refused by a guard with no "
        f"tool run, {counts['run_again']:,} run again by the maker of an earlier identical call "
        f"and {counts['same_call_elsewhere']:,} identical to a call another maker ran first; "
        f"besides them, {counts['retried_after_failure']:,} retried after the maker's own "
        "earlier identical call failed"
    )
    makers = calls.get("by_agent")
    said = []
    for name, row in makers.items() if isinstance(makers, Mapping) else ():
        if not isinstance(row, Mapping):
            continue
        parts = [
            f"{_int(row.get(kind)):,} {_CALL_WORDS[kind]}"
            for kind in _CALL_COUNTS
            if _int(row.get(kind))
        ]
        if parts:
            said.append(f"{_maker_label(str(name))}: {', '.join(parts)}")
    if said:
        by_tool = _named_counts(_summed(calls.get("by_tool")))
        line += f". By who made them — {'; '.join(said)} (by tool: {by_tool})"
    return line + "."


def _named_counts(counts: Any, label: Callable[[str], str] = _c) -> str:
    """``{name: n}`` as "`a` 3, `b` 1", largest first; "" for none."""
    if not isinstance(counts, Mapping):
        return ""
    rows = sorted(((str(k), _int(v)) for k, v in counts.items()), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{label(name)} {n:,}" for name, n in rows if n)


def _uncited_line(uncited: Mapping[str, Any]) -> str:
    entries, none = _int(uncited.get("entries")), _int(uncited.get("uncited"))
    held = _count(entries, "ledger entry", "ledger entries")
    line = (
        f"Evidence nothing cites: {none:,} of the {held} whose tool answered are named by no "
        "claim, finding or artifact of an analyst's final answer"
    )
    by_agent, by_tool = (
        _named_counts(uncited.get("by_agent"), _maker_label),
        _named_counts(uncited.get("by_tool")),
    )
    if none and by_agent:
        line += f" (by maker: {by_agent}; by tool: {by_tool})"
    failed = _int(uncited.get("failed"))
    if "failed" in uncited:
        line += (
            f"; {_count(failed, 'failed call')} not counted as evidence"
            if failed
            else "; no call failed"
        )
    return line + "."
