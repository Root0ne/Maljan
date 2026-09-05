"""Four places used to spell the analyst set out as a literal.

They spelled the same three names, so nothing noticed. A profile with four
analysts, or with one, makes each of them wrong in a different way: the judge
reports a missing analyst that was never asked for, the cascade never declares
consensus, the run summary attributes techniques to layers nobody ran.
"""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.analysis.ttp_cascade import CascadeResult
from maljan.core.config import Settings, install_settings, reset_settings_cache


def _install(**agents) -> Settings:
    cfg = Settings(_env_file=None, agents=agents) if agents else Settings(_env_file=None)
    install_settings(cfg)
    return cfg


def teardown_function() -> None:
    reset_settings_cache()


def _score(layers: list[str]) -> CascadeResult:
    return CascadeResult(
        technique_id="T1027",
        contributing_layers=layers,
        layer_contributions=[],
        layer_confidences={},
        raw_weighted_confidence=0.5,
        cross_layer_multiplier=1.0,
        weighted_confidence=0.5,
        total_evidence_count=1,
    )


def test_the_default_profile_still_means_the_three_standard_layers():
    _install()
    assert _score(["static", "dynamic", "network"]).is_consensus is True
    assert _score(["static", "network"]).is_consensus is False


def test_a_reduced_profile_reaches_consensus_on_the_layers_it_actually_runs():
    _install(profiles={"lean": {"analysts": ["static", "network"]}}, profile="lean")
    assert _score(["static", "network"]).is_consensus is True


def test_a_wide_profile_needs_every_one_of_its_analysts_for_consensus():
    _install(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"wide": {"analysts": ["static", "network", "strings"]}},
        profile="wide",
    )
    assert _score(["static", "network"]).is_consensus is False
    assert _score(["static", "network", "strings"]).is_consensus is True


def test_the_run_summary_records_the_default_triple_and_no_custom_agents():
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("default", ["static", "dynamic", "network"], [])
        .build()
    )
    assert summary.to_dict()["profile"] == {
        "name": "default",
        "analysts": ["static", "dynamic", "network"],
        "custom": [],
    }


def test_the_run_summary_records_a_custom_profiles_own_list():
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("wide", ["static", "static_r2", "strings"], ["static_r2", "strings"])
        .build()
    )
    assert summary.to_dict()["profile"]["custom"] == ["static_r2", "strings"]


def test_a_run_summary_built_without_a_profile_still_serialises():
    """Old reports have no profile, and the panel that reads it has a fallback."""
    summary = (
        RunSummaryBuilder(start_time=0.0).set_sample("abc", None).set_verdict("Benign", 0).build()
    )
    assert summary.to_dict()["profile"] is None


def test_every_other_run_summary_key_is_unchanged():
    _install()
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("default", ["static", "dynamic", "network"], [])
        .build()
    )
    keys = set(summary.to_dict())
    assert keys == {
        "file_hash",
        "file_name",
        "final_decision",
        "stix_object_count",
        "elapsed_seconds",
        "timestamp",
        "negotiation",
        "agent_stats",
        "cascade",
        "validation",
        "tokens",
        "degraded_mode",
        "degradation_reasons",
        "failed_analysts",
        "techniques_by_layer",
        "profile",
    }


def test_the_per_layer_attribution_lists_the_profiles_analysts_then_the_rule_layers():
    _install(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"wide": {"analysts": ["network", "strings"]}},
        profile="wide",
    )
    from maljan.analysis.run_summary import _attribution_layers

    assert _attribution_layers() == ["network", "strings", "yara", "sigma"]


def test_the_judges_empty_analyst_check_covers_exactly_the_profile():
    _install(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    from maljan.agents.composition import current_analyst_keys

    assert current_analyst_keys() == ["network"]
