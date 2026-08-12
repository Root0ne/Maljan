"""B3/B4's evidence construction and comparison, tested without an LLM.

The experiment's validity rests on one property: **the arms must differ only in
which Layer-0 source exists.** If an arm accidentally changes the claims, the
confidences, or the assignment, then whatever the judge does afterwards is
uninterpretable. Most of these tests exist to pin that.

The second cluster covers ``bundle_technique_ids``, which has to read both
pydantic SDOs (the extended renderer's output) and plain dicts (the judge's
parsed bundle). A reader that silently handles only one shape would report an
empty technique set for half the arms and make every comparison look like a
total change.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_layer0_verdict import (
    ARMS,
    SOURCES,
    assign_to_sources,
    build_isr_reports,
    bundle_technique_ids,
    jaccard,
    sources_for_arm,
    verdict_changed,
)


class TestAssignment:
    def test_round_robin_is_deterministic(self) -> None:
        tids = ["T1055", "T1071", "T1486", "T1490", "T1140"]
        assert assign_to_sources(tids) == assign_to_sources(tids)

    def test_every_technique_lands_somewhere(self) -> None:
        tids = ["T1055", "T1071", "T1486", "T1490", "T1140"]
        placed = [t for v in assign_to_sources(tids).values() for t in v]
        assert sorted(placed) == sorted(tids)

    def test_no_source_gets_a_systematically_easier_slice(self) -> None:
        """Round-robin rather than a contiguous split: a fixed split would give
        one source the first techniques of every fixture, confounding layer
        identity with whatever those techniques have in common.

        The expected assignment tracks SOURCES, which grew from three to six
        when the sandbox-fed layers were added — so five techniques now land one
        per source rather than wrapping around.
        """
        assignment = assign_to_sources(["T1055", "T1071", "T1486", "T1490", "T1140"])
        assert assignment["yara_layer"] == ["T1055"]
        assert assignment["import_capability_layer"] == ["T1071"]
        assert assignment["tool_artifact_layer"] == ["T1486"]
        assert assignment["sigma_layer"] == ["T1490"]
        assert assignment["lolbin"] == ["T1140"]
        assert assignment["network_dga"] == []

    def test_round_robin_wraps_across_all_six_sources(self) -> None:
        """Seven techniques over six sources: the wrap must land on the first."""
        tids = [f"T10{i}0" for i in range(1, 8)]
        assignment = assign_to_sources(tids)
        assert assignment["yara_layer"] == ["T1010", "T1070"]
        assert [len(v) for v in assignment.values()] == [2, 1, 1, 1, 1, 1]

    def test_ids_are_normalised(self) -> None:
        assert assign_to_sources(["t1055"])["yara_layer"] == ["T1055"]

    def test_an_empty_ground_truth_yields_empty_sources(self) -> None:
        assert all(not v for v in assign_to_sources([]).values())


class TestArms:
    def test_all_keeps_every_source(self) -> None:
        assert sources_for_arm("all") == list(SOURCES)

    @pytest.mark.parametrize("name", [n for n, _ in SOURCES])
    def test_each_removal_arm_drops_exactly_one(self, name: str) -> None:
        kept = sources_for_arm(f"no_{name}")
        assert len(kept) == len(SOURCES) - 1
        assert name not in [n for n, _ in kept]

    def test_an_unknown_arm_falls_back_to_all_rather_than_to_nothing(self) -> None:
        """Silently returning [] would produce an empty-evidence run that then
        'proves' the layer mattered enormously."""
        assert sources_for_arm("no_such_layer_exists") == list(SOURCES)

    def test_the_arm_list_covers_every_source_once_plus_the_baseline(self) -> None:
        assert len(ARMS) == len(SOURCES) + 1
        assert ARMS[0] == "all"


class TestIsrConstruction:
    def test_the_removed_source_is_absent_and_the_others_are_untouched(self) -> None:
        assignment = assign_to_sources(["T1055", "T1071", "T1486", "T1490", "T1140"])
        full = build_isr_reports(assignment, "all")
        ablated = build_isr_reports(assignment, "no_yara_layer")

        assert "yara_layer" in full
        assert "yara_layer" not in ablated
        for name in ablated:
            assert [c.technique_id for c in ablated[name].claims] == [
                c.technique_id for c in full[name].claims
            ]

    def test_confidence_is_identical_across_arms(self) -> None:
        """A varying confidence would confound layer removal with a confidence
        change, and the cascade consumes confidence directly."""
        assignment = assign_to_sources(["T1055", "T1071", "T1486"])
        confidences = {
            c.confidence
            for arm in ARMS
            for isr in build_isr_reports(assignment, arm).values()
            for c in isr.claims
        }
        assert len(confidences) == 1

    def test_tool_artifact_emits_on_yaras_domain(self) -> None:
        """Not a harness choice — it is what the production layer does, and it
        is why §1.10 found that source unable to add corroboration."""
        assignment = assign_to_sources(["T1055", "T1071", "T1486"])
        reports = build_isr_reports(assignment, "all")
        assert reports["tool_artifact_layer"].domain == "yara"
        assert reports["yara_layer"].domain == "yara"
        assert reports["import_capability_layer"].domain == "static"

    def test_a_source_with_no_techniques_is_omitted_not_empty(self) -> None:
        """An ISR with zero claims is the 'dataless analyst' pathology the
        ledger documents; it must not be introduced by the harness itself."""
        reports = build_isr_reports(assign_to_sources(["T1055"]), "all")
        assert set(reports) == {"yara_layer"}


class TestBundleTechniqueIds:
    def test_reads_plain_dict_objects(self) -> None:
        bundle = type(
            "B",
            (),
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1055"}
                        ],
                    }
                ]
            },
        )()
        assert bundle_technique_ids(bundle) == {"T1055"}

    def test_reads_attribute_style_objects(self) -> None:
        ref = type("R", (), {"external_id": "T1071"})()
        obj = type("O", (), {"type": "attack-pattern", "external_references": [ref]})()
        bundle = type("B", (), {"objects": [obj]})()
        assert bundle_technique_ids(bundle) == {"T1071"}

    def test_ignores_non_attack_pattern_objects(self) -> None:
        bundle = type(
            "B",
            (),
            {
                "objects": [
                    {"type": "malware", "external_references": [{"external_id": "T9999"}]},
                    {"type": "attack-pattern", "external_references": [{"external_id": "T1055"}]},
                ]
            },
        )()
        assert bundle_technique_ids(bundle) == {"T1055"}

    def test_ignores_non_attck_external_references(self) -> None:
        """CAPA ids, CVEs and CWEs all live in external_references too."""
        bundle = type(
            "B",
            (),
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "external_references": [
                            {"external_id": "CVE-2024-1234"},
                            {"external_id": "T1055"},
                        ],
                    }
                ]
            },
        )()
        assert bundle_technique_ids(bundle) == {"T1055"}

    def test_an_empty_or_malformed_bundle_is_an_empty_set_not_a_crash(self) -> None:
        assert bundle_technique_ids(type("B", (), {"objects": []})()) == set()
        assert bundle_technique_ids(type("B", (), {"objects": None})()) == set()
        assert bundle_technique_ids(object()) == set()


class TestComparison:
    def test_identical_sets_score_one(self) -> None:
        assert jaccard({"T1055"}, {"T1055"}) == 1.0

    def test_disjoint_sets_score_zero(self) -> None:
        assert jaccard({"T1055"}, {"T1071"}) == 0.0

    def test_partial_overlap(self) -> None:
        assert jaccard({"T1055", "T1071"}, {"T1055"}) == pytest.approx(0.5)

    def test_two_empty_sets_are_identical_not_undefined(self) -> None:
        """Both arms producing nothing is agreement, and scoring it 0 would read
        as a total change caused by the ablation."""
        assert jaccard(set(), set()) == 1.0

    def test_one_empty_set_is_a_total_change(self) -> None:
        assert jaccard(set(), {"T1055"}) == 0.0

    def test_verdict_changed_is_set_equality(self) -> None:
        assert verdict_changed({"T1055"}, {"T1055", "T1071"}) is True
        assert verdict_changed({"T1055"}, {"T1055"}) is False
        assert verdict_changed(set(), set()) is False
