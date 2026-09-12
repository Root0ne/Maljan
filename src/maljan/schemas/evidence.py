"""The citable record of every tool call an analysis made.

A report is only as good as what it can point at. Before the ledger, a tool
result lived exactly as long as the ReAct message stream that produced it: the
model read it, wrote prose about it, and the bytes were gone. Anything the
report then said about a section table or a DNS lookup was the model's memory
of a number, and nothing downstream could check it.

A ``LedgerEntry`` is one tool call written down — which agent asked, which
server answered, the arguments, the timing, whether it worked, and what came
back, parsed when it parsed. Entries carry an id (``ev_0007``) that is
monotonic across the whole job, and that id is the citation: the tool loop
shows it to the model with the result, agents cite it in their findings, report
sections list the ids they were built from, and the API serves the entry those
ids name.

Two bounds keep the ledger from becoming the thing it records. Each output is
trimmed to ``MAX_OUTPUT_CHARS`` on the way in, and each agent gets a byte
budget (``report.evidence_budget_bytes``); past the budget an entry keeps its
arguments, its outcome and its timing but drops its output, and says so with
``truncated``. What was dropped is counted in the truncation ledger, so the
report can state how many entries it is not showing rather than quietly
showing fewer.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from maljan.schemas.tool_evidence import (
    MAX_OUTPUT_CHARS,
    CapturedToolOutput,
    _symbol_from_args,
    trim_output,
)

# The width of the numeric part of an entry id. Four digits holds ten thousand
# tool calls in one job, which is an order of magnitude past the busiest run
# observed, and fixed width means the ids sort lexically in the order they
# were issued.
_ID_DIGITS = 4


def format_entry_id(seq: int) -> str:
    """The citation id for the ``seq``-th tool call of a job (1-based)."""
    return f"ev_{max(1, int(seq)):0{_ID_DIGITS}d}"


class EvidenceCounter:
    """The per-job source of entry ids.

    One counter per job rather than one per agent: an id is a citation, and two
    agents that both issued ``ev_0003`` would give the report two different
    entries under one name. The container owns it for the same reason it owns
    the token and truncation ledgers, and an agent that runs without a
    container falls back to a counter of its own.
    """

    def __init__(self) -> None:
        # Locked because ``parallel_analysts`` runs the analysts on threads
        # against this one counter, and two agents handed the same id would be
        # two different calls answering to one citation — exactly what the
        # counter exists to prevent. ``TruncationLedger`` locks for the same
        # reason.
        self._lock = threading.Lock()
        self._seq = 0

    def next_id(self) -> tuple[str, int]:
        """The next ``(entry_id, seq)`` pair, seq being 1-based."""
        with self._lock:
            self._seq += 1
            return format_entry_id(self._seq), self._seq

    @property
    def issued(self) -> int:
        """How many ids this counter has handed out."""
        with self._lock:
            return self._seq


def parse_structured(output: str) -> dict[str, Any] | list[Any] | None:
    """The tool's output as JSON when it is JSON, else ``None``.

    Only a dict or a list counts. A tool that answered ``"4"`` or ``"null"``
    produced valid JSON and no structure, and storing that as ``structured``
    would give the section builders a shape they cannot read.
    """
    text = (output or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict | list) else None


class LedgerEntry(BaseModel):
    """One tool call and its result, addressable by id."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Citation id, monotonic per job, e.g. 'ev_0007'.")
    stage: str = Field(default="analysis", description="Pipeline stage the call was made in.")
    agent: str = Field(default="", description="Agent that made the call, e.g. 'static'.")
    server: str | None = Field(
        default=None,
        description="Tool server the tool came from; None for an in-process tool.",
    )
    tool: str = Field(default="", description="Tool name, e.g. 'pe_info'.")
    args: dict[str, Any] = Field(default_factory=dict, description="Arguments passed.")
    symbol: str | None = Field(
        default=None, description="Human label for the call target, parsed from the arguments."
    )
    ok: bool = Field(default=True, description="Whether the call returned rather than raised.")
    error: str | None = Field(default=None, description="Failure text when ok is false.")
    output: str = Field(default="", description="Result text, trimmed.")
    structured: dict[str, Any] | list[Any] | None = Field(
        default=None, description="Parsed result when the tool returned JSON."
    )
    truncated: bool = Field(
        default=False, description="Output dropped because the agent's byte budget was spent."
    )
    started_at: float = Field(default=0.0, description="Unix timestamp the call started at.")
    duration_ms: int = Field(default=0, description="Wall-clock duration of the call.")
    seq: int = Field(default=0, description="Call order within the job, 1-based.")

    def to_captured(self) -> CapturedToolOutput:
        """This entry in the shape readers of the previous capture expect."""
        return CapturedToolOutput(
            agent_id=self.agent,
            tool_name=self.tool,
            args=dict(self.args),
            symbol=self.symbol,
            output=self.output,
            seq=max(0, self.seq - 1),
        )

    @classmethod
    def from_captured(
        cls, captured: CapturedToolOutput, *, entry_id: str = "", stage: str = "analysis"
    ) -> LedgerEntry:
        """A ledger entry from a captured output, for a producer without timing."""
        seq = int(captured.seq) + 1
        return cls(
            id=entry_id or format_entry_id(seq),
            stage=stage,
            agent=captured.agent_id,
            server=None,
            tool=captured.tool_name,
            args=dict(captured.args),
            symbol=captured.symbol,
            ok=True,
            output=captured.output,
            structured=parse_structured(captured.output),
            seq=seq,
        )


def build_entry(
    *,
    entry_id: str,
    seq: int,
    agent: str,
    tool: str,
    args: dict[str, Any] | None,
    server: str | None,
    output: str,
    ok: bool = True,
    error: str | None = None,
    started_at: float = 0.0,
    duration_ms: int = 0,
    stage: str = "analysis",
    max_chars: int = MAX_OUTPUT_CHARS,
) -> LedgerEntry:
    """One entry, with the output trimmed and parsed the same way every time."""
    safe_args = dict(args) if isinstance(args, dict) else {}
    text = trim_output(str(output or ""), max_chars)
    return LedgerEntry(
        id=entry_id,
        stage=stage,
        agent=agent,
        server=server or None,
        tool=tool,
        args=safe_args,
        symbol=_symbol_from_args(safe_args),
        ok=ok,
        error=error,
        output=text,
        structured=parse_structured(text),
        started_at=started_at,
        duration_ms=max(0, int(duration_ms)),
        seq=seq,
    )


def apply_budget(
    entries: list[LedgerEntry], budget_bytes: int, *, already_spent: int = 0
) -> tuple[int, int]:
    """Drop the outputs that overrun ``budget_bytes``, in call order.

    Returns ``(trimmed, spent)`` — how many entries lost their output, and how
    many bytes of output are now kept in total. ``already_spent`` carries the
    running total forward, because the budget belongs to the agent and an agent
    that runs two loops must not get the budget twice.

    The entries themselves stay: which tool was called, with what, and whether
    it worked is the cheap half of the record and the half a reader needs in
    order to know something is missing.
    """
    if budget_bytes <= 0:
        return 0, already_spent
    spent = max(0, already_spent)
    trimmed = 0
    for entry in entries:
        size = len(entry.output.encode("utf-8", errors="ignore"))
        if spent + size <= budget_bytes:
            spent += size
            continue
        entry.output = ""
        entry.structured = None
        entry.truncated = True
        trimmed += 1
    return trimmed, spent
