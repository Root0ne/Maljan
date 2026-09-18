"""The alignment gate, measured against what the index actually answered.

The end-to-end audit recorded every weak-alignment correction the gate sent:
the claimed id, the gate score the index gave it, and the candidate ranking the
analyst was asked to consider. Those rankings are the fixture
``tests/fixtures/attck_alignment_recorded.json``, and they are what this file
replays — no index is built here, and none of these numbers was invented.

What they show is why the gate is off by default. The ranking is domain-blind,
so a claim about a Windows PE was answered with Mobile and ICS techniques, and
the index scores a *correct* id near zero often enough that the bare threshold
questioned 81 of the 92 claims in one run and 33 of 33 in another — each batch
a full extra model turn.

Two properties hold here. The ids the audit read as right for their sample draw
no correction, and every correction that is still sent names candidates from
the sample's own domain and platforms, from a tactic other than the claim's
own, beating the claimed id's score by the configured margin. Nothing here
replaces an id.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.pipeline.validation import WEAK_ALIGNMENT_CODE, validate_isr
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "attck_alignment_recorded.json").read_text(
        encoding="utf-8"
    )
)

# What the narrowed gate sends over the audit's own rankings. Zero over the ids
# the audit read as right for their sample; the rest is the measurement
# docs/architecture.md carries.
CHALLENGED_SCOPED = 0
CHALLENGED_OTHER = 5


class _Attck:
    """The catalogue, answered from the fixture rather than from 50MB of STIX."""

    def __init__(self, catalogue: dict[str, dict[str, Any]]) -> None:
        self._catalogue = catalogue

    def catalogue_available(self) -> bool:
        return True

    def attck_validate(self, ids: list[str]) -> dict[str, Any]:
        return {"invalid": [{"id": i} for i in ids if i not in self._catalogue]}

    def attck_scope(self, technique_id: str) -> dict[str, Any]:
        row = self._catalogue.get(technique_id, {})
        return {
            "technique_id": technique_id,
            "domain": row.get("domain", ""),
            "platforms": list(row.get("platforms") or []),
        }

    def attck_lookup(self, technique_id: str) -> dict[str, Any]:
        row = self._catalogue.get(technique_id, {})
        return {
            "valid": technique_id in self._catalogue,
            "technique_id": technique_id,
            "domain": row.get("domain", ""),
            "platforms": list(row.get("platforms") or []),
            "tactics": list(row.get("tactics") or []),
        }


ATTCK = _Attck(FIXTURE["catalogue"])


def _gate(row: dict[str, Any]) -> Any:
    def answer(text: str, technique_id: str, k: int = 5) -> dict[str, Any]:
        return {
            "technique_id": technique_id,
            "gate_score": row["gate_score"],
            "candidates": [dict(c) for c in row["candidates"]],
        }

    return answer


def _claim(row: dict[str, Any]) -> ClaimEvidence:
    return ClaimEvidence(
        claim=row["claim"],
        evidence_ref="[ev_0001] the entry the analyst read it from",
        confidence=0.8,
        technique_id=row["technique_id"],
    )


def _checked(row: dict[str, Any], *, challenge: bool = True) -> tuple[ClaimEvidence, list[str]]:
    """One recorded pair through the gate: the claim, and what it was told."""
    claim = _claim(row)
    isr = AgentISR(agent_id=row["agent"], domain="static", claims=[claim])
    violations = validate_isr(
        isr,
        attck=ATTCK,
        ledger_ids=[],
        sample=row["sample"],
        alignment=_gate(row),
        weak_alignment_challenges=challenge,
    )
    return claim, [v.message for v in violations if v.code == WEAK_ALIGNMENT_CODE]


def _rows(key: str) -> list[dict[str, Any]]:
    return list(FIXTURE[key])


def _named_ids(message: str) -> list[str]:
    import re

    return re.findall(r"\bT\d{4}(?:\.\d{3})?\b", message)


class TestTheIdsTheAuditReadAsRight:
    def test_none_of_them_is_challenged(self) -> None:
        questioned = [
            f"{row['run']}/{row['agent']}: {row['technique_id']}"
            for row in _rows("scoped_claims")
            if _checked(row)[1]
        ]

        assert questioned == [], (
            "the gate questions ids the audit read as right for their sample: "
            + ", ".join(questioned)
        )
        assert len(questioned) == CHALLENGED_SCOPED

    def test_the_ranking_is_still_recorded_on_the_claim(self) -> None:
        row = next(r for r in _rows("scoped_claims") if r["candidates"])
        claim, messages = _checked(row)

        assert messages == []
        assert claim.alignment is not None
        assert claim.alignment["gate_score"] == pytest.approx(row["gate_score"])

    def test_nothing_replaces_the_analyst_id(self) -> None:
        for row in _rows("scoped_claims") + _rows("other_claims"):
            claim, _messages = _checked(row)
            assert claim.technique_id == row["technique_id"]


class TestTheCorrectionsThatAreStillSent:
    def test_the_gate_is_not_dead(self) -> None:
        sent = [row for row in _rows("other_claims") if _checked(row)[1]]

        assert len(sent) == CHALLENGED_OTHER
        assert sent, "a gate that can never question anything is not a gate"

    def test_every_candidate_named_is_in_the_sample_scope(self) -> None:
        from maljan.pipeline.validation import expected_technique_scope

        for row in _rows("other_claims") + _rows("scoped_claims"):
            _claim_out, messages = _checked(row)
            if not messages:
                continue
            domain, platforms = expected_technique_scope(row["sample"])
            for tid in _named_ids(messages[0]):
                if tid == row["technique_id"]:
                    continue
                scope = ATTCK.attck_lookup(tid)
                assert scope["domain"] == domain, f"{row['run']}: {tid} is out of domain"
                declared = [p.lower() for p in scope["platforms"]]
                assert not declared or {p.lower() for p in platforms} & set(declared), (
                    f"{row['run']}: {tid} declares no platform of this sample"
                )

    def test_a_named_candidate_beats_the_claim_by_the_margin(self) -> None:
        from maljan.pipeline.validation import ALIGNMENT_MARGIN

        for row in _rows("other_claims"):
            _claim_out, messages = _checked(row)
            if not messages:
                continue
            best = max(
                c["score_gate"]
                for c in row["candidates"]
                if c["technique_id"] in _named_ids(messages[0])
            )
            assert best - row["gate_score"] >= ALIGNMENT_MARGIN


class TestTheGateThatIsOff:
    def test_it_says_nothing_and_still_ranks(self) -> None:
        for row in _rows("other_claims"):
            claim, messages = _checked(row, challenge=False)
            assert messages == []
            assert claim.alignment is not None

    def test_the_ranking_it_records_carries_no_out_of_scope_candidate(self) -> None:
        for row in _rows("other_claims") + _rows("scoped_claims"):
            claim, _messages = _checked(row, challenge=False)
            for candidate in claim.alignment["candidates"]:
                assert ATTCK.attck_lookup(candidate["technique_id"])["domain"] in {
                    "enterprise" if row["sample"]["platform"] != "android" else "mobile",
                    "",
                }
