"""Four places used to spell the analyst set out as a literal.

They spelled the same three names, so nothing noticed. A profile with four
analysts, or with one, makes each of them wrong in a different way: the judge
reports a missing analyst that was never asked for, the run summary attributes
techniques to layers nobody ran, and the router declares consensus on a set the
profile does not contain.

The cascade's own `is_consensus` went with the cascade; the routing question it
answered did not, so it is asked of `pipeline/routing.py` — the component that
actually decides whether the negotiation continues — instead.
"""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings, install_settings, reset_settings_cache
from maljan.pipeline.routing import ConsensusRouter


def _install(**agents) -> Settings:
    cfg = Settings(_env_file=None, agents=agents) if agents else Settings(_env_file=None)
    install_settings(cfg)
    return cfg


def teardown_function() -> None:
    reset_settings_cache()


def _routes_to(cfg: Settings, **state) -> str:
    base = {
        "iteration_count": 1,
        "is_consensus": False,
        "sycophancy_detected": False,
        "confidence_history": [],
        "discussion_history": [],
    }
    base.update(state)
    return ConsensusRouter(cfg).should_continue(base)  # type: ignore[arg-type]


class TestTheRouterRespectsWhicheverProfileIsRunning:
    """The consensus question, asked of the component that answers it now."""

    def test_the_default_profile_still_names_the_three_standard_layers(self) -> None:
        assert _install().agents.profiles["default"].analysts == ["static", "dynamic", "network"]

    def test_a_reduced_profile_runs_only_the_analysts_it_names(self) -> None:
        _install(profiles={"lean": {"analysts": ["static", "network"]}}, profile="lean")
        from maljan.agents.composition import current_analyst_keys

        assert current_analyst_keys() == ["static", "network"]

    def test_consensus_ends_the_negotiation_whatever_the_profile(self) -> None:
        cfg = _install(profiles={"lean": {"analysts": ["network"]}}, profile="lean")

        assert _routes_to(cfg, is_consensus=True) == "judge"

    def test_no_consensus_keeps_it_going(self) -> None:
        cfg = _install(profiles={"lean": {"analysts": ["network"]}}, profile="lean")

        assert _routes_to(cfg, is_consensus=False) == "revision"

    def test_sycophancy_overrides_a_premature_consensus(self) -> None:
        cfg = _install()

        assert _routes_to(cfg, is_consensus=True, sycophancy_detected=True) == "revision"

    def test_the_hard_iteration_limit_wins(self) -> None:
        cfg = _install()

        assert (
            _routes_to(cfg, iteration_count=cfg.negotiation.max_iterations, is_consensus=False)
            == "judge"
        )


class TestTheRunSummaryRecordsTheProfileThatRan:
    def test_the_default_triple_and_no_custom_agents(self) -> None:
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

    def test_a_custom_profiles_own_list(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", "s.exe")
            .set_verdict("Malware", 3)
            .set_profile("wide", ["static", "static_r2", "strings"], ["static_r2", "strings"])
            .build()
        )

        assert summary.to_dict()["profile"]["custom"] == ["static_r2", "strings"]

    def test_a_run_summary_built_without_a_profile_still_serialises(self) -> None:
        """Old reports have no profile, and the panel that reads it has a fallback."""
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", None)
            .set_verdict("Benign", 0)
            .build()
        )

        assert summary.to_dict()["profile"] is None

    def test_every_other_run_summary_key_is_unchanged(self) -> None:
        _install()
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", "s.exe")
            .set_verdict("Malware", 3)
            .set_profile("default", ["static", "dynamic", "network"], [])
            .build()
        )

        assert set(summary.to_dict()) == {
            "file_hash",
            "file_name",
            "final_decision",
            "stix_object_count",
            "elapsed_seconds",
            "timestamp",
            "negotiation",
            "agent_stats",
            "corroboration",
            "validation",
            "tokens",
            "degraded_mode",
            "degradation_reasons",
            "failed_analysts",
            "techniques_by_layer",
            "profile",
        }

    def test_the_per_layer_attribution_lists_the_profiles_analysts_then_the_rule_layers(
        self,
    ) -> None:
        _install(
            definitions={"strings": {"role": "generic", "prompt": "p"}},
            profiles={"wide": {"analysts": ["network", "strings"]}},
            profile="wide",
        )
        from maljan.analysis.run_summary import _attribution_layers

        assert _attribution_layers() == ["network", "strings", "yara", "sigma"]

    def test_the_judges_empty_analyst_check_covers_exactly_the_profile(self) -> None:
        _install(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
        from maljan.agents.composition import current_analyst_keys

        assert current_analyst_keys() == ["network"]
