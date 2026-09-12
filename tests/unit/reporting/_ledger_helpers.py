"""Build an evidence ledger the way a run does, for the report tests.

The report is assembled from what the tools returned, so a test that wants a
report about a sandbox run has to make the calls a dynamic analyst would have
made. These helpers do exactly that: they call the real sandbox tools on the
fixture report and record the answers, so the fixtures in this directory keep
describing a sandbox run rather than a hand-written ledger nobody would
produce.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.providers import sandbox_tools
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry
from maljan.schemas.isr_models import AgentISR, Artifact

_SANDBOX_TOOLS = (
    "sandbox_processes",
    "sandbox_network",
    "sandbox_signatures",
    "sandbox_dropped_files",
)


def entry(
    tool: str,
    payload: Any,
    counter: EvidenceCounter,
    *,
    agent: str = "static",
) -> LedgerEntry:
    """One ledger entry holding ``payload`` as the tool's answer."""
    entry_id, seq = counter.next_id()
    return build_entry(
        entry_id=entry_id,
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server=None,
        output=payload if isinstance(payload, str) else json.dumps(payload),
    )


def ledger_from_sandbox(
    report: dict[str, Any] | None, counter: EvidenceCounter | None = None
) -> list[LedgerEntry]:
    """The entries a dynamic analyst leaves behind after reading one report."""
    counter = counter or EvidenceCounter()
    out: list[LedgerEntry] = []
    for tool in _SANDBOX_TOOLS:
        answer = getattr(sandbox_tools, tool)(report)
        if not isinstance(answer, dict) or answer.get("error"):
            continue
        out.append(entry(tool, answer, counter, agent="dynamic"))
    return out


def persistence_isr(rows: list[list[str]], evidence_ids: list[str] | None = None) -> AgentISR:
    """A dynamic analyst that wrote down the persistence it observed."""
    return AgentISR(
        agent_id="dynamic",
        domain="dynamic",
        artifacts=[
            Artifact(
                kind="persistence",
                label="Persistence",
                columns=["Kind", "Target", "Payload"],
                rows=rows,
                evidence_ids=list(evidence_ids or ["ev_0001"]),
                source="dynamic",
            )
        ],
    )
