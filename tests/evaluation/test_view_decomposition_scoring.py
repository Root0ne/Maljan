"""Unit tests for the pure scoring helpers of ``eval_view_decomposition``."""

from __future__ import annotations

from maljan.schemas.isr_models import ClaimEvidence
from tests.evaluation.eval_view_decomposition import (
    _cited_tids,
    _grounding_rate,
    _invalid_id_rate,
    _stability,
)


def _claim(claim: str, technique_id: str | None, evidence_ref: str = "") -> ClaimEvidence:
    return ClaimEvidence(
        claim=claim, evidence_ref=evidence_ref, confidence=0.6, technique_id=technique_id
    )


class TestCitedTids:
    def test_collects_field_and_inline(self) -> None:
        claims = [
            _claim("uses process injection (T1055)", "T1055"),
            _claim("also T1071 beaconing", None),
        ]
        assert set(_cited_tids(claims)) == {"T1055", "T1071"}


class TestInvalidIdRate:
    def test_zero_when_all_valid(self) -> None:
        assert _invalid_id_rate(["T1055", "T1071"], lambda t: True) == 0.0

    def test_counts_invalid(self) -> None:
        # T1000 is the §3.2 hallucination example.
        rate = _invalid_id_rate(["T1055", "T1000"], lambda t: t != "T1000")
        assert rate == 0.5

    def test_zero_when_none_cited(self) -> None:
        assert _invalid_id_rate([], lambda t: False) == 0.0


class TestGroundingRate:
    def test_grounded_via_technique_id_in_bundle(self) -> None:
        bundle = "Observed CreateRemoteThread [associated technique: T1055]"
        claims = [_claim("injection", "T1055", evidence_ref="unrelated")]
        assert _grounding_rate(claims, bundle) == 1.0

    def test_grounded_via_evidence_token(self) -> None:
        bundle = "Dropped file stage2.bin under C:/Users/Public"
        claims = [_claim("drops payload", None, evidence_ref="file: stage2.bin written")]
        assert _grounding_rate(claims, bundle) == 1.0

    def test_ungrounded_claim(self) -> None:
        bundle = "Network beaconing to a remote host"
        claims = [_claim("invented ransomware encryption", "T1486", evidence_ref="nope")]
        assert _grounding_rate(claims, bundle) == 0.0

    def test_empty_claims_vacuous(self) -> None:
        assert _grounding_rate([], "anything") == 1.0


class TestStability:
    def test_zero_for_constant_counts(self) -> None:
        assert _stability([4, 4, 4]) == 0.0

    def test_positive_for_volatile_counts(self) -> None:
        # Monolithic's volatile 2<->9 pattern from §3.2.
        assert _stability([2, 9, 2]) > 0.0

    def test_single_sample_zero(self) -> None:
        assert _stability([5]) == 0.0
