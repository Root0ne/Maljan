"""The run-state block: what this run is, has done and has left, in a dozen lines.

A long tool loop on one local model server grows its transcript with every
step, and the facts that matter — what the sample is, what has already been
established, what failed, how much budget is left — end up buried under tool
output or dropped when the conversation is cut. This block is the answer to
that: derived from the ledger and the stage results, never written by a model,
rendered fresh on every turn and put in the system turn between two markers.
Regenerating it is what keeps it from accumulating: a prompt carries one block,
the current one, and a trimmed conversation keeps it because the system turn is
the one message trimming never drops.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from maljan.pipeline.triage_pack import PIPELINE, pack_entries, render_pack

__all__ = [
    "RUN_STATE_BEGIN",
    "RUN_STATE_END",
    "render_run_state",
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
    failed = [
        f"{_get(row, 'tool')} ({_get(row, 'agent') or PIPELINE})"
        for row in rows
        if _get(row, "ok") is False
    ]
    if failed:
        lines.append(
            "tools failed: "
            + ", ".join(failed[:8])
            + (f" (+{len(failed) - 8} more)" if len(failed) > 8 else "")
        )

    budget = []
    if steps_left is not None:
        budget.append(f"{max(0, int(steps_left))} steps")
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
