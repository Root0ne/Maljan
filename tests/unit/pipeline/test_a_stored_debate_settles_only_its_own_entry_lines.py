"""The stored debates under the own-entry rule: what is settled, and what is read as before.

haiku11's debate ran five rounds to its limit. Its round-3 mediation blocked on
two lines: the dynamic analyst's claim against a listing, and an analyst's
mutex claim at 0.85 against its own dispute entry at 0.50. The second is
settled by rule, so the round asks the dynamic analyst alone. Its round-4
mediation blocked on a line that set the analyst's "Claim 27" against "its
claim 40": both are now read for that analyst, and nothing is left unplaced.

haiku10's debate held one carried line about a peer's claims: no line of it is
settled, and every mediation asks whom it asked.

The answers in force are rebuilt from the stored transcript, which keeps each
answer's first twelve claims: a claim beyond them is not checked here.
Local runs only: skipped where the stored runs are not on the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.judge_agent import final_contradictions
from maljan.pipeline.debate_facts import analysts_to_revise, read_claim_references, read_marks
from maljan.pipeline.own_entries import settle_own_entry_lines
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark


def _run(name: str) -> Path:
    root = _benchmark()
    if root is None or not (root / name / "report-byjob.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    return root / name


def _isr(row: dict[str, Any]) -> AgentISR:
    return AgentISR(
        agent_id=str(row["speaker"]),
        domain="replay",
        claims=[
            ClaimEvidence(
                claim=str(c.get("claim") or ""),
                evidence_ref=str(c.get("evidence_ref") or ""),
                confidence=float(c.get("confidence") or 0.0),
                technique_id=c.get("technique_id"),
            )
            for c in row.get("claims") or []
        ],
        dissent_items=[str(d) for d in row.get("dissent") or []],
    )


def _mediations(run: Path) -> list[tuple[list[str], dict[str, AgentISR]]]:
    """Per mediation, its blocking lines and the answers in force it read."""
    byjob = json.loads((run / "report-byjob.json").read_text())
    summary = json.loads((run / "run-summary.json").read_text())
    names = list(byjob["agent_reports"])
    in_force: dict[str, AgentISR] = {}
    read: list[dict[str, AgentISR]] = []
    for row in sorted(byjob["transcript"], key=lambda r: r["seq"]):
        if row.get("role") == "negotiator":
            read.append(dict(in_force))
        elif (
            row.get("speaker") in names
            and row.get("claims")
            and (row.get("report") or not row.get("round"))
        ):
            in_force[str(row["speaker"])] = _isr(row)
    out: list[tuple[list[str], dict[str, AgentISR]]] = []
    for answer, isrs in zip(summary["negotiation"]["mediator_answers"], read, strict=False):
        lines = final_contradictions(answer["answer"]) or []
        marks = read_marks(lines)
        out.append(([line for line, m in zip(lines, marks, strict=True) if m.blocking], isrs))
    return out


def test_haiku11_round_3_asks_the_dynamic_analyst_alone() -> None:
    run = _run("haiku11")
    names = list(json.loads((run / "report-byjob.json").read_text())["agent_reports"])
    mediations = _mediations(run)
    lines, isrs = mediations[2]

    settled, held = settle_own_entry_lines(lines, names, isrs)

    assert [s.line for s in settled] == [2]
    [claim] = settled[0].claims
    assert (claim.claim, claim.was, claim.now) == (10, 0.85, 0.5)
    assert held[claim.analyst].claims[10].confidence == 0.5
    rest = [line for line in lines if line not in {s.text for s in settled}]
    assert analysts_to_revise(lines, names)[0] == ["dynamic", claim.analyst]
    assert analysts_to_revise(rest, names)[0] == ["dynamic"]


def test_haiku11_round_4_reads_its_claim_for_the_analyst() -> None:
    run = _run("haiku11")
    names = list(json.loads((run / "report-byjob.json").read_text())["agent_reports"])
    lines, _isrs = _mediations(run)[3]

    refs = read_claim_references(lines[:1], names)

    [(_analyst, claims)] = refs.named.items()
    assert sorted(claims) == [27, 40]
    assert refs.unplaced == ()


@pytest.mark.parametrize("name", ["haiku10", "haiku8", "haiku7"])
def test_a_debate_with_no_own_entry_line_is_read_as_before(name: str) -> None:
    run = _run(name)
    names = list(json.loads((run / "report-byjob.json").read_text())["agent_reports"])
    for lines, isrs in _mediations(run):
        settled, held = settle_own_entry_lines(lines, names, isrs)
        assert settled == [] and held == {}
