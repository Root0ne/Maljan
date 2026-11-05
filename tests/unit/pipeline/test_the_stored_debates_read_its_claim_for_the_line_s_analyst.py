"""The stored debates' claim readings, pinned: "its claim N" is read for the line's analyst.

haiku11's round-4 mediation blocked on a line that set the qu1cksc0pe
analyst's "Claim 27" against "its claim 40" and wrote "claim 27" again. Dev
read "claim 40" and the repeated "claim 27" for no analyst, so withdraw-by-rule
could not act on the line and the run logged two "reads no analyst" warnings.
Both are now read for that analyst, and nothing is left unplaced.

Every claim reading of every stored mediation of haiku7 to haiku11 is pinned
(``tests/fixtures/debate/stored_mediation_readings.json``): the claims each
line names, the references left unplaced and the analysts each mediation asks.
Against origin/dev the one difference is haiku11's round-4 line 1, and no
mediation asks other analysts than before. Local runs only: skipped where the
stored runs are not on the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.judge_agent import final_contradictions
from maljan.pipeline.debate_facts import analysts_to_revise, read_claim_references, read_marks
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

GOLDEN = (
    Path(__file__).resolve().parents[2] / "fixtures" / "debate" / "stored_mediation_readings.json"
)
STORED = ("haiku7", "haiku8", "haiku9", "haiku10", "haiku11")


def _run(name: str) -> Path:
    root = _benchmark()
    if root is None or not (root / name / "run-summary.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    return root / name


def _names(run: Path) -> list[str]:
    return list(json.loads((run / "report-byjob.json").read_text())["agent_reports"])


def _lines(run: Path) -> list[list[str]]:
    """Per mediation, the lines of its final block."""
    summary = json.loads((run / "run-summary.json").read_text())
    return [
        final_contradictions(answer["answer"]) or []
        for answer in summary["negotiation"].get("mediator_answers") or []
    ]


def readings(run: Path) -> dict[str, Any]:
    """Per mediation of a stored run: the claims its lines name, the unplaced, and who revises."""
    names = _names(run)
    summary = json.loads((run / "run-summary.json").read_text())
    out: dict[str, Any] = {}
    for answer in summary["negotiation"].get("mediator_answers") or []:
        lines = final_contradictions(answer["answer"]) or []
        refs = read_claim_references(lines, names)
        out[f"M{answer['round']}"] = {
            "named": {
                a: {str(n): [list(r) for r in rows] for n, rows in sorted(c.items())}
                for a, c in sorted(refs.named.items())
            },
            "unplaced": [[u.line, list(u.analysts), u.claims, u.why] for u in refs.unplaced],
            "revise": analysts_to_revise(
                [ln for ln, m in zip(lines, read_marks(lines), strict=True) if m.blocking], names
            )[0],
        }
    return out


def test_haiku11_round_4_reads_its_claim_for_the_analyst() -> None:
    run = _run("haiku11")
    lines = _lines(run)[3]

    refs = read_claim_references(lines[:1], _names(run))

    [(_analyst, claims)] = refs.named.items()
    assert sorted(claims) == [27, 40]
    assert refs.unplaced == ()


@pytest.mark.parametrize("name", STORED)
def test_the_stored_mediations_are_read_as_pinned(name: str) -> None:
    assert readings(_run(name)) == json.loads(GOLDEN.read_text())[name]
