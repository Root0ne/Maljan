"""Build an evidence ledger the way a run does.

The report is assembled from what the tools returned, so a test that wants a
report about a sandbox run has to make the calls a dynamic analyst would have
made. These helpers do exactly that: they call the real sandbox tools on the
fixture report and record the answers, so a fixture keeps describing a sandbox
run rather than a hand-written ledger nobody would produce.

``sandbox_view`` is the same answers without the ledger wrapper — what the
provider goldens freeze, now that the normalisation contract is "what an agent
sees when it asks" rather than "what an extractor made of the report".
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


def sandbox_view(report: dict[str, Any] | None) -> dict[str, Any]:
    """What the sandbox tools answer for one report, tool by tool."""
    return {tool: getattr(sandbox_tools, tool)(report) for tool in _SANDBOX_TOOLS}


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
