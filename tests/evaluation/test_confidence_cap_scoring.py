"""B5's preconditions and rate arithmetic, tested without a sample.

The measurement is a difference between two runs of the same production
function, so most of what can go wrong is in deciding *which* claims were
eligible. Two tests carry the weight:

* **the gated set is re-declared, not imported.** The harness keeps its own copy
  of T1027/T1140/T1055 and 0.40, and a test asserts it matches production. If
  someone widens the cap, the result moves — and it should fail loudly rather
  than quietly report a different number under the same heading.
* **rates come from corpus totals, not from averaged per-sample rates.**
  Averaging per-sample rates weights a one-technique sample the same as a
  twenty-technique one, which is the classic way to make a rare event look
  common.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_confidence_cap import (
    GATED_INJECTION,
    GATED_OBFUSCATION,
    LOW_CONF_CAP,
    SampleResult,
    cap_delta,
    firing_rate,
    is_gated_technique,
    sole_static_layer,
    summarise,
)


class TestTheHarnessMatchesProduction:
    def test_the_gated_technique_sets_match(self) -> None:
        """A silent widening of the cap must break this, not move a result."""
        from maljan.extractors import capability_matrix as prod

        assert GATED_OBFUSCATION == prod._OBFUSCATION_TIDS
        assert GATED_INJECTION == prod._INJECTION_TIDS

    def test_the_cap_value_matches(self) -> None:
        from maljan.extractors import capability_matrix as prod

        assert LOW_CONF_CAP == prod._LOW_CONF_CAP

    def test_cap_off_really_is_off(self) -> None:
        """The whole ablation rests on this: static=None must disable the cap."""
        from maljan.extractors.capability_matrix import _static_evidence_flags

        assert _static_evidence_flags(None) == (True, True)


class TestGatedTechniques:
    @pytest.mark.parametrize("tid", ["T1027", "T1140", "T1055"])
    def test_base_techniques_are_gated(self, tid: str) -> None:
        assert is_gated_technique(tid)

    @pytest.mark.parametrize("tid", ["T1027.002", "T1055.012", "T1140.001"])
    def test_sub_techniques_are_gated(self, tid: str) -> None:
        assert is_gated_technique(tid)

    @pytest.mark.parametrize("tid", ["T1486", "T1071", "T1003", ""])
    def test_everything_else_is_not(self, tid: str) -> None:
        assert not is_gated_technique(tid)

    def test_a_prefix_match_must_be_on_a_dot_boundary(self) -> None:
        """T10275 is not a sub-technique of T1027, and a naive startswith would
        have gated it."""
        assert not is_gated_technique("T10275")

    def test_case_and_whitespace_are_normalised(self) -> None:
        assert is_gated_technique("  t1055.012  ")


class TestSoleStaticLayer:
    def test_static_alone_qualifies(self) -> None:
        assert sole_static_layer(["static"])

    def test_any_corroboration_exempts_the_claim(self) -> None:
        """Deliberate: the cap disciplines LLM-only guesses, not corroborated ones."""
        assert not sole_static_layer(["static", "yara"])
        assert not sole_static_layer(["static", "dynamic"])

    def test_a_different_sole_layer_does_not_qualify(self) -> None:
        assert not sole_static_layer(["yara"])

    def test_empty_layers_do_not_qualify(self) -> None:
        assert not sole_static_layer([])

    def test_case_and_blanks_are_normalised(self) -> None:
        assert sole_static_layer([" Static ", "", "  "])


class TestCapDelta:
    def test_a_capped_claim_reports_the_drop(self) -> None:
        assert cap_delta(0.98, 0.40) == pytest.approx(0.58)

    def test_an_untouched_claim_reports_zero(self) -> None:
        assert cap_delta(0.98, 0.98) == 0.0

    def test_it_does_not_go_negative_silently_when_confidence_rose(self) -> None:
        """The cap can only lower a value, so a negative delta means the arms
        differed by something other than the cap — it must stay visible."""
        assert cap_delta(0.40, 0.98) < 0


class TestFiringRate:
    def test_no_eligible_claims_is_zero_not_a_division_error(self) -> None:
        assert firing_rate(0, 0) == 0.0

    def test_ordinary_rate(self) -> None:
        assert firing_rate(3, 12) == pytest.approx(0.25)

    def test_every_eligible_claim_capped(self) -> None:
        assert firing_rate(7, 7) == 1.0


class TestSummarise:
    def _r(self, total: int, gated: int, sole: int, capped: int) -> SampleResult:
        return SampleResult(
            sample="s",
            total_techniques=total,
            gated_techniques=gated,
            gated_sole_static=sole,
            capped=capped,
            mean_delta=0.58 if capped else 0.0,
        )

    def test_rates_are_computed_from_totals_not_averaged_per_sample(self) -> None:
        """A 1-technique sample where the cap fired and a 19-technique sample
        where it did not is 1/20 = 5%, not (100% + 0%) / 2 = 50%."""
        results = [self._r(1, 1, 1, 1), self._r(19, 0, 0, 0)]
        stats = summarise(results)
        assert stats["capped_share_of_all_techniques"] == pytest.approx(0.05)

    def test_an_empty_corpus_reports_zeros_rather_than_dividing(self) -> None:
        stats = summarise([])
        assert stats["techniques_total"] == 0
        assert stats["capped_share_of_all_techniques"] == 0.0
        assert stats["cap_fire_rate_among_gated"] == 0.0

    def test_samples_with_any_cap_counts_samples_not_claims(self) -> None:
        results = [self._r(10, 3, 3, 2), self._r(10, 2, 2, 0), self._r(10, 1, 1, 1)]
        assert summarise(results)["samples_with_any_cap"] == 2

    def test_the_two_denominators_are_reported_separately(self) -> None:
        """Rate among gated and rate among eligible are different questions:
        the first includes corroborated claims the cap can never touch."""
        stats = summarise([self._r(10, 4, 2, 2)])
        assert stats["cap_fire_rate_among_gated"] == pytest.approx(0.5)
        assert stats["cap_fire_rate_among_eligible"] == pytest.approx(1.0)
