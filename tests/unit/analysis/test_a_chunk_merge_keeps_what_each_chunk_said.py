"""A merge of chunk answers keeps what each chunk said, not only its claims.

``merge_chunk_isrs`` built the merged answer from the claims and disputes
alone: a chunk's structured findings and artifacts, the status it reported
for itself, the prose of an answer that parsed into no claim, and the counts
of CLAIM blocks whose confidence was not read all fell away, so the validation
turn never asked about them and the judge never saw them.
"""

from __future__ import annotations

from maljan.analysis.chunk_merger import merge_chunk_isrs
from maljan.schemas.isr_models import AgentISR, Artifact, ClaimEvidence, Finding


def _isr(claims: list[ClaimEvidence] | None = None) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=claims or [])


def _claim(text: str = "it injects", tid: str | None = "T1055") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref="ref", confidence=0.8, technique_id=tid)


def _prose(text: str) -> AgentISR:
    isr = _isr()
    isr.note_parse(unparsed_answer=text)
    isr.status = "no_structured_report"
    isr.status_reason = "the answer parsed into no claim"
    return isr


def test_each_chunks_findings_and_artifacts_are_kept_once() -> None:
    a, b = _isr([_claim()]), _isr([_claim("it persists", "T1547")])
    shared = Finding(title="Injects into explorer", evidence_ids=["ev_0001"])
    a.findings = [shared, Finding(title="Packed with UPX")]
    b.findings = [Finding(title="Injects into explorer", evidence_ids=["ev_0001"])]
    b.artifacts = [Artifact(kind="hashes", value="abc")]
    merged = merge_chunk_isrs([a, b])
    assert [f.title for f in merged.findings] == ["Injects into explorer", "Packed with UPX"]
    assert [x.value for x in merged.artifacts] == ["abc"]


def test_the_confidence_counts_of_every_chunk_are_kept() -> None:
    a, b = _isr([_claim()]), _isr([_claim("it persists", "T1547")])
    a.note_parse(blocks_without_confidence=1, confidence_unreadable=["high"])
    b.note_parse(blocks_without_confidence=2, confidence_unreadable=["very"])
    merged = merge_chunk_isrs([a, b])
    assert merged.blocks_without_confidence == 3
    assert merged.confidence_unreadable == ["high", "very"]


def test_chunks_that_all_answered_in_prose_keep_their_prose_and_status() -> None:
    merged = merge_chunk_isrs([_prose("first part"), _prose("second part")])
    assert merged.claims == []
    assert merged.status == "no_structured_report"
    assert merged.status_reason == "the answer parsed into no claim"
    assert "first part" in merged.unparsed_answer
    assert "second part" in merged.unparsed_answer


def test_a_prose_chunk_beside_claims_is_stated_not_dropped() -> None:
    merged = merge_chunk_isrs([_isr([_claim()]), _prose("second part")])
    # The merged answer has claims: the status of one chunk is not its status,
    # and the prose is not shown as the merged answer.
    assert merged.status is None
    assert merged.unparsed_answer == ""
    assert "1 of 2 parts" in merged.claims_unread_reason
    assert "parsed into no claim" in merged.claims_unread_reason


def test_headings_under_disputes_are_asked_only_when_every_chunk_was_asked() -> None:
    a, b = _isr([_claim()]), _isr([_claim("it persists", "T1547")])
    a.note_claims_under_disputes(2)
    a.note_claims_under_disputes_asked()
    b.note_claims_under_disputes(1)
    assert merge_chunk_isrs([a, b]).claims_under_disputes_asked is False
    b.note_claims_under_disputes_asked()
    merged = merge_chunk_isrs([a, b])
    assert merged.claims_under_disputes == 3
    assert merged.claims_under_disputes_asked is True
