"""The Layer-0 contribution eval answers a question about a shipped default, so its
arithmetic is pinned here.

Three properties carry the result and each can be wrong without looking wrong:

  * ``unique_contribution`` must subtract the union of *all other* sources. Subtracting
    one source at a time would report every technique as unique whenever three sources
    disagree, which is the majority of samples.
  * ``techniques_by_domain`` must merge sources that share a cascade domain.
    ``tool_artifact`` emits ``domain="yara"``, so a source-keyed histogram silently
    overstates how much corroboration the cascade can actually see — the difference
    between "three sources agreed" and "one layer spoke twice".
  * ``corroboration_histogram`` counts *distinct sources per technique*, not claims.
    Counting claims would let one source with two claims for the same technique
    manufacture corroboration on its own — the exact defect the dataless-revision fix
    had to remove elsewhere in the pipeline.

Network-free, model-free, sample-free.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_EVAL_DIR = Path(__file__).resolve().parent
if str(_EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(_EVAL_DIR))

from eval_layer0_contribution import (  # noqa: E402
    corroboration_histogram,
    pairwise_overlap,
    techniques_by_domain,
    unique_contribution,
)


class _Claim:
    def __init__(self, technique_id: str | None) -> None:
        self.technique_id = technique_id


class _ISR:
    def __init__(self, domain: str, technique_ids: list[str | None]) -> None:
        self.domain = domain
        self.claims = [_Claim(t) for t in technique_ids]


class TestUniqueContribution:
    def test_a_technique_only_one_source_found_is_unique_to_it(self) -> None:
        per_source = {"a": {"T1055"}, "b": {"T1027"}}
        assert unique_contribution(per_source) == {"a": {"T1055"}, "b": {"T1027"}}

    def test_a_shared_technique_is_unique_to_nobody(self) -> None:
        per_source = {"a": {"T1055"}, "b": {"T1055"}}
        out = unique_contribution(per_source)
        assert out["a"] == set() and out["b"] == set()

    def test_it_subtracts_all_other_sources_not_just_one(self) -> None:
        """With three sources, a technique held by the other two is not unique."""
        per_source = {"a": {"T1055", "T1027"}, "b": {"T1055"}, "c": {"T1027"}}
        assert unique_contribution(per_source)["a"] == set()

    def test_a_lone_source_owns_everything_it_found(self) -> None:
        assert unique_contribution({"a": {"T1", "T2"}}) == {"a": {"T1", "T2"}}

    def test_no_sources_yields_nothing(self) -> None:
        assert unique_contribution({}) == {}


class TestDomainViewMergesSharedDomains:
    def test_two_sources_sharing_a_domain_become_one_layer(self) -> None:
        """tool_artifact ships domain='yara' — verbatim from the production layer."""
        isrs = {
            "yara_layer": _ISR("yara", ["T1055"]),
            "tool_artifact": _ISR("yara", ["T1027"]),
        }
        by_domain = techniques_by_domain(isrs)
        assert set(by_domain) == {"yara"}
        assert by_domain["yara"] == {"T1055", "T1027"}

    def test_sources_in_different_domains_stay_separate(self) -> None:
        isrs = {
            "yara_layer": _ISR("yara", ["T1055"]),
            "import_capability": _ISR("static", ["T1055"]),
        }
        assert techniques_by_domain(isrs) == {"yara": {"T1055"}, "static": {"T1055"}}

    def test_the_domain_view_can_report_less_corroboration_than_the_source_view(self) -> None:
        """The whole reason both views exist: the cascade only sees the second one."""
        isrs = {
            "yara_layer": _ISR("yara", ["T1055"]),
            "tool_artifact": _ISR("yara", ["T1055"]),
        }
        by_source = {"yara_layer": {"T1055"}, "tool_artifact": {"T1055"}}
        assert corroboration_histogram(by_source) == {2: 1}
        assert corroboration_histogram(techniques_by_domain(isrs)) == {1: 1}

    def test_claims_without_a_technique_id_are_ignored(self) -> None:
        isrs = {"yara_layer": _ISR("yara", ["T1055", None, "NONE", "  "])}
        assert techniques_by_domain(isrs) == {"yara": {"T1055"}}

    def test_technique_ids_are_case_normalised(self) -> None:
        isrs = {"a": _ISR("yara", ["t1055"]), "b": _ISR("static", ["T1055"])}
        assert corroboration_histogram(techniques_by_domain(isrs)) == {2: 1}


class TestCorroborationHistogram:
    def test_it_counts_distinct_sources_per_technique(self) -> None:
        per_source = {"a": {"T1", "T2"}, "b": {"T2"}, "c": {"T2"}}
        assert corroboration_histogram(per_source) == {1: 1, 3: 1}

    def test_one_source_cannot_corroborate_itself(self) -> None:
        """Sets already de-duplicate, and that is load-bearing, not incidental."""
        assert corroboration_histogram({"a": {"T1055"}}) == {1: 1}

    def test_no_evidence_yields_an_empty_histogram(self) -> None:
        assert corroboration_histogram({}) == {}


class TestPairwiseOverlap:
    def test_it_reports_each_unordered_pair_once(self) -> None:
        out = pairwise_overlap({"a": {"T1"}, "b": {"T1"}, "c": set()})
        assert set(out) == {"a|b", "a|c", "b|c"}
        assert out["a|b"] == 1

    def test_disjoint_sources_overlap_at_zero(self) -> None:
        assert pairwise_overlap({"a": {"T1"}, "b": {"T2"}})["a|b"] == 0

    def test_a_single_source_has_no_pairs(self) -> None:
        assert pairwise_overlap({"a": {"T1"}}) == {}


class TestSensitivitySignature:
    def test_the_corroborated_set_ignores_weights_by_construction(self) -> None:
        """Pins the study's central finding at the level of the code that causes it.

        ``is_corroborated`` is ``len(contributing_layers) >= 2`` — it never consults
        LAYER_WEIGHTS. So no weight perturbation can move it, and the measured 0.000
        across every perturbation is structural rather than a property of this corpus.
        If someone later makes corroboration weight-dependent, this test should fail
        and the study's conclusion must be re-run.
        """
        from maljan.analysis.ttp_cascade import CascadeResult

        def _result(layers: list[str], confidence: float) -> CascadeResult:
            return CascadeResult(
                technique_id="T1055",
                contributing_layers=layers,
                layer_contributions=[],
                layer_confidences=dict.fromkeys(layers, confidence),
                raw_weighted_confidence=confidence,
                cross_layer_multiplier=1.0,
                weighted_confidence=confidence,
                total_evidence_count=len(layers),
            )

        # Two layers at *low* confidence corroborate; one layer at near-certainty
        # does not. The label is a function of layer count alone.
        assert _result(["yara", "static"], 0.10).is_corroborated is True
        assert _result(["yara"], 0.99).is_corroborated is False, (
            "a single layer must never read as corroborated, however confident"
        )


@pytest.mark.parametrize(
    ("per_source", "expected_unique_a"),
    [
        ({"a": {"T1"}, "b": set()}, {"T1"}),
        ({"a": set(), "b": {"T1"}}, set()),
        ({"a": {"T1", "T2"}, "b": {"T2", "T3"}}, {"T1"}),
    ],
)
def test_unique_contribution_table(
    per_source: dict[str, set[str]], expected_unique_a: set[str]
) -> None:
    assert unique_contribution(per_source)["a"] == expected_unique_a
