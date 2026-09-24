"""The run-state block: what this run is, has done and has left, in a dozen lines.

A long tool loop on one local model server grows its transcript with every
step, and the facts that matter — what the sample is, what has already been
established, what failed, how much budget is left — end up buried under tool
output or dropped when the conversation is cut. This block is the answer to
that: derived from the ledger and the stage results, never written by a model,
rendered fresh on every turn and put between two markers.

Where it goes is decided by what a provider caches. A tool loop's block
changes on every turn — its budget line counts down — and a byte that changes
early in a request voids every byte after it in a provider's prefix cache, and
makes a local server read the whole conversation again. So the block a loop
regenerates travels last, as a turn of its own after the conversation
(:func:`run_state_turn`), and each turn's request is the previous one's with
the old block taken off and new turns added. Regenerating it is what keeps it
from accumulating: a prompt carries one block, the current one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from maljan.pipeline.triage_pack import NOT_RUN_PREFIX, PIPELINE, pack_entries, render_pack

__all__ = [
    "RUN_STATE_BEGIN",
    "RUN_STATE_END",
    "is_run_state_turn",
    "render_run_state",
    "run_state_turn",
    "with_run_state",
]

RUN_STATE_BEGIN = "=== RUN STATE (derived from the ledger; regenerated each turn) ==="
RUN_STATE_END = "=== END RUN STATE ==="

_BLOCK_RE = re.compile(re.escape(RUN_STATE_BEGIN) + r".*?" + re.escape(RUN_STATE_END), re.DOTALL)

# How many characters of a pack line the identity and reputation lines keep.
# The pack renders a line whole; this block repeats four of them on every
# turn of every loop, so here they are cut.
_LINE_CHARS = 240


def render_run_state(
    state: Mapping[str, Any],
    *,
    steps_left: int | None = None,
    seconds_left: float | None = None,
) -> str:
    """The block for ``state``, without its markers. Never raises.

    ``steps_left`` and ``seconds_left`` are the caller's budget when it has
    one; a caller outside a tool loop leaves them out and the line is absent
    rather than invented.
    """
    try:
        return "\n".join(_lines(state, steps_left, seconds_left))
    except Exception:  # noqa: BLE001 — a block that cannot be built is left out
        return ""


def with_run_state(system_text: str, body: str) -> str:
    """``system_text`` carrying exactly one run-state block, the one in ``body``.

    A block already there is replaced in place; none is appended. An empty
    ``body`` removes the block, so a caller with nothing to say leaves the
    system turn exactly as its author wrote it.
    """
    text = system_text or ""
    block = f"{RUN_STATE_BEGIN}\n{body}\n{RUN_STATE_END}" if body else ""
    if _BLOCK_RE.search(text):
        replaced = _BLOCK_RE.sub(lambda _m: block, text, count=1)
        return replaced.rstrip() if not block else replaced
    if not block:
        return text
    return f"{text.rstrip()}\n\n{block}" if text.strip() else block


def run_state_turn(body: str) -> str:
    """The text of the turn that carries ``body`` on its own, between its markers.

    Empty for an empty ``body``: a caller with nothing to say sends no turn.
    """
    return with_run_state("", body)


def is_run_state_turn(text: object) -> bool:
    """Whether ``text`` is a whole run-state turn and nothing else.

    Whole, not containing: a prompt that leads with the block and goes on to
    its task is a task, and taking it out would take the task with it.
    """
    if not isinstance(text, str):
        return False
    stripped = text.strip()
    return (
        stripped.startswith(RUN_STATE_BEGIN)
        and stripped.endswith(RUN_STATE_END)
        and stripped.count(RUN_STATE_BEGIN) == 1
    )


def _lines(
    state: Mapping[str, Any], steps_left: int | None, seconds_left: float | None
) -> list[str]:
    lines: list[str] = []
    sha256 = str(state.get("file_hash") or "")
    identity = " ".join(
        p
        for p in (
            str(state.get("file_type") or ""),
            str(state.get("platform") or ""),
        )
        if p and p != "unknown"
    )
    name = str(state.get("file_name") or "")
    sample = ", ".join(p for p in (sha256, identity, f"submitted as {name}" if name else "") if p)
    if sample:
        lines.append(f"sample: {sample}")

    rows = list(state.get("evidence_ledger") or [])
    pack = pack_entries(rows)
    by_tool = {entry.tool: entry for entry in pack if entry.ok}
    for tool in ("identify_file", "hashes", "signing_info"):
        entry = by_tool.get(tool)
        if entry is not None:
            lines.append(_cut(render_pack([entry], 0)))
    # ``reputation`` is the pack's own name for a lookup that did not happen;
    # the block wants it, because why there is no reputation answer is worth
    # as much to a model as the answer (see ``triage_pack._REPUTATION_TOOLS``).
    reputation = [e for e in pack if e.tool in ("get_file_report", "check_hash", "reputation")]
    if reputation:
        lines.append(_cut(render_pack([reputation[-1]], 0)))

    stages = state.get("stage_results") or {}
    if isinstance(stages, Mapping) and stages:
        parts = []
        for key, record in stages.items():
            if not isinstance(record, Mapping):
                continue
            if record.get("ran"):
                parts.append(f"{key} ran")
            else:
                reason = str(record.get("reason") or "").strip()
                parts.append(f"{key} skipped ({reason})" if reason else f"{key} skipped")
        if parts:
            lines.append("stages: " + "; ".join(parts))

    total = len(rows)
    if total:
        ids = [str(_get(row, "id") or "") for row in rows]
        first, last = ids[0], ids[-1]
        span = f"{first}–{last}" if first != last else first
        lines.append(f"ledger: {total} entries ({span}), {len(pack)} from the triage pack")
    # A call that was never made — a skipped lookup, a step after the budget —
    # is not a failed tool; the pack line says "not done" for it, and so does
    # this one by leaving it out.
    failed = [
        f"{_get(row, 'tool')} ({_get(row, 'agent') or PIPELINE})"
        for row in rows
        if _get(row, "ok") is False and not _was_not_made(row)
    ]
    if failed:
        lines.append(
            "tools failed: "
            + ", ".join(failed[:8])
            + (f" (+{len(failed) - 8} more)" if len(failed) > 8 else "")
        )

    budget = []
    if steps_left is not None:
        budget.append(f"{max(0, int(steps_left))} model turns")
    if seconds_left is not None:
        budget.append(f"{max(0, int(seconds_left))} s")
    if budget:
        lines.append("budget remaining: " + ", ".join(budget))
    return lines


def _cut(line: str) -> str:
    return line if len(line) <= _LINE_CHARS else line[: _LINE_CHARS - 1] + "…"


def _get(row: Any, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def _was_not_made(row: Any) -> bool:
    text = str(_get(row, "error") or _get(row, "output") or "")
    return text.startswith(NOT_RUN_PREFIX)
