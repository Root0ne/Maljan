"""The stored debates' last lines, pinned: the claims a ruling at the round limit is written onto.

Of haiku7 to haiku12, haiku8, haiku10, haiku11 and haiku12 ended at the round
limit with blocking lines (``termination_reason: hard_limit``): each would ask
the mediator one ruling question. What it rules is the model's; which claims
each ruling is written onto is the platform's, read here from the claims in
force each run stored (every line taken as upheld, so every mark shows):

- haiku8: the qu1cksc0pe analyst's claim 4 (its YARA hits against ev_0007);
- haiku10: the reverser's claims 2 and 46 (the 0x1030 loop). The line also
  names qu1cksc0pe claims 6 and 35 and reverser claim 5, whose claims in force
  are about other things and share no ledger id or address with the line:
  stated, never marked;
- haiku11: the reverser's claim 10 (0x72c8) and the triage analyst's claim 27,
  the anti-debug absence ev_0143 contradicts (K3.1);
- haiku12: none. Both lines write "Round-4 claim N", which the platform reads
  for no analyst: each is stated.

haiku7 and haiku9 converged and ask nothing. Local runs only: skipped where the
stored runs are not on the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.judge_agent import final_contradictions
from maljan.pipeline.debate_facts import read_marks
from maljan.pipeline.limit_rulings import Ruling, mark_claims
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

MARKED = {
    "haiku7": None,
    "haiku8": {"all_tools_qu1cksc0pe": [4]},
    "haiku9": None,
    "haiku10": {"all_tools_reverser_ghidra": [2, 46]},
    "haiku11": {"all_tools_reverser_ghidra": [10], "triage": [27]},
    "haiku12": {},
}


def _run(name: str) -> Path:
    root = _benchmark()
    if root is None or not (root / name / "report-byjob.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    return root / name


def _marked(run: Path) -> tuple[dict[str, list[int]] | None, list[str]]:
    summary = json.loads((run / "run-summary.json").read_text())
    byjob = json.loads((run / "report-byjob.json").read_text())
    negotiation = summary["negotiation"]
    if negotiation.get("termination_reason") != "hard_limit":
        return None, []
    answers = negotiation["mediator_answers"]
    lines = final_contradictions(answers[-1]["answer"]) or []
    blocking = [line for line, mark in zip(lines, read_marks(lines), strict=True) if mark.blocking]
    isrs: dict[str, Any] = {
        row["agent_name"]: AgentISR(
            agent_id=row["agent_name"],
            domain=row.get("domain") or row["agent_name"],
            claims=[ClaimEvidence.model_validate(c) for c in row.get("claims") or []],
        )
        for row in byjob["agent_findings"]
    }
    upheld = {n: Ruling(n, True, "r") for n in range(1, len(blocking) + 1)}
    out = mark_claims(blocking, upheld, isrs, list(byjob["agent_reports"]), len(answers))
    marked = {
        name: sorted(
            int(s.split("onto claim ")[1].split(" ")[0])
            for s in out.sentences
            if s.startswith("The ruling on") and f" of the {name} analyst's" in s
        )
        for name in out.isrs
    }
    return marked, out.sentences


@pytest.mark.parametrize("name", sorted(MARKED))
def test_the_stored_last_lines_mark_the_claims_pinned(name: str) -> None:
    marked, sentences = _marked(_run(name))

    assert marked == MARKED[name]
    # Every line is said, marked or not.
    if marked is not None:
        assert sentences


def test_haiku11_s_anti_debug_absence_carries_the_ruling() -> None:
    run = _run("haiku11")
    _marked_rows, sentences = _marked(run)

    assert any("triage analyst's answer in force" in s for s in sentences)
