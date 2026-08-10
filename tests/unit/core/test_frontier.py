"""The frontier arm's spend ceiling, tested before it is ever pointed at a real endpoint.

This is the one component in the project that spends the author's money, and the
shape of the thing that spends it — an eval harness looping over 100 samples with
a retry path — is exactly the shape that quietly bills for hours. So the ceiling
is tested the way a safety interlock is tested: not "does it usually work" but
"can it be got round".

The tests that matter most:

* **refusal happens before the call, not after.** A call already made cannot be
  un-billed, so ``check`` must raise on the projection rather than reconcile
  afterwards.
* **projections are pessimistic.** Output is priced at the full cap because a
  degenerate decode produces exactly that, and §3.3 shows this model does.
* **zero pricing disables the arm.** A meter with zero rates can never refuse
  anything; treating that as "free" would turn the ceiling into decoration.
"""

from __future__ import annotations

import pytest

from maljan.core.frontier import (
    CostMeter,
    FrontierBudgetExceeded,
    build_meter,
    charge_from_response,
    frontier_ready,
    usd_for_tokens,
)


class _Cfg:
    """Minimal stand-in for FrontierConfig — the dry run, with no network."""

    def __init__(self, **kw: object) -> None:
        self.enabled = kw.get("enabled", True)
        self.base_url = kw.get("base_url", "https://example.invalid/v1")
        self.api_key = kw.get("api_key", "sk-test")
        self.model = kw.get("model", "frontier-test-model")
        self.max_spend_usd = kw.get("max_spend_usd", 10.0)
        self.input_usd_per_mtok = kw.get("input_usd_per_mtok", 3.0)
        self.output_usd_per_mtok = kw.get("output_usd_per_mtok", 15.0)
        self.free_tier = kw.get("free_tier", False)


class TestUsdForTokens:
    def test_a_million_tokens_costs_the_rate(self) -> None:
        assert usd_for_tokens(1_000_000, 3.0) == pytest.approx(3.0)

    def test_partial_millions_scale_linearly(self) -> None:
        assert usd_for_tokens(250_000, 4.0) == pytest.approx(1.0)

    @pytest.mark.parametrize(("tokens", "rate"), [(0, 3.0), (-5, 3.0), (1000, 0.0), (1000, -1.0)])
    def test_nothing_is_charged_for_nonsense(self, tokens: int, rate: float) -> None:
        assert usd_for_tokens(tokens, rate) == 0.0


class TestProjectionIsPessimistic:
    def test_output_is_priced_at_the_full_cap(self) -> None:
        """Not at an expected value. A runaway decode produces the cap, and that
        is precisely the case an expected-value estimate under-charges."""
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        # 100k input @ $3/Mtok = $0.30; 8k output cap @ $15/Mtok = $0.12
        assert m.project(100_000, 8_000) == pytest.approx(0.42)

    def test_a_projection_does_not_spend_anything(self) -> None:
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        m.project(1_000_000, 1_000_000)
        assert m.spent_usd == 0.0
        assert m.calls == 0


class TestRefusalHappensBeforeTheCall:
    def test_a_call_that_would_cross_the_limit_raises(self) -> None:
        m = CostMeter(limit_usd=0.10, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        with pytest.raises(FrontierBudgetExceeded):
            m.check(100_000, 8_000)  # $0.42 projected against a $0.10 limit

    def test_a_refusal_is_counted_and_nothing_is_spent(self) -> None:
        m = CostMeter(limit_usd=0.10, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        with pytest.raises(FrontierBudgetExceeded):
            m.check(100_000, 8_000)
        assert m.refusals == 1
        assert m.spent_usd == 0.0
        assert m.calls == 0

    def test_a_call_inside_the_limit_passes_silently(self) -> None:
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        m.check(100_000, 8_000)  # must not raise

    def test_the_ceiling_holds_across_accumulated_spend(self) -> None:
        """The failure mode this guards: every individual call is affordable and
        the run still bills past the limit."""
        m = CostMeter(limit_usd=1.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        made = 0
        for _ in range(100):
            try:
                m.check(100_000, 8_000)  # $0.42 each
            except FrontierBudgetExceeded:
                break
            m.charge(100_000, 8_000)
            made += 1
        assert made == 2  # 0.42 + 0.42 = 0.84; a third would reach 1.26 > 1.00
        assert m.spent_usd <= m.limit_usd

    def test_exactly_reaching_the_limit_is_allowed_but_exceeding_is_not(self) -> None:
        """The boundary must not depend on float representation error.

        $0.30 + $0.12 is 0.42000000000000004 in IEEE-754, so a strict `>` refused
        a call that lands exactly on a round limit. The epsilon is a billionth of
        a dollar — it cannot fund a request, and without it the boundary behaves
        arbitrarily depending on how the rates happen to multiply out.
        """
        m = CostMeter(limit_usd=0.42, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        m.check(100_000, 8_000)
        m.charge(100_000, 8_000)
        assert m.exhausted
        with pytest.raises(FrontierBudgetExceeded):
            m.check(1_000, 100)

    def test_the_epsilon_is_not_a_spending_allowance(self) -> None:
        """It must absorb representation error and nothing a caller could use."""
        m = CostMeter(limit_usd=1.0, input_usd_per_mtok=1_000_000.0, output_usd_per_mtok=0.0)
        with pytest.raises(FrontierBudgetExceeded):
            m.check(2, 0)  # 2 tokens at $1/token = $2.00 against a $1.00 limit


class TestCharging:
    def test_charge_returns_and_accumulates_the_cost(self) -> None:
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        assert m.charge(1_000_000, 0) == pytest.approx(3.0)
        assert m.charge(0, 1_000_000) == pytest.approx(15.0)
        assert m.spent_usd == pytest.approx(18.0)
        assert m.calls == 2

    def test_remaining_never_goes_negative(self) -> None:
        m = CostMeter(limit_usd=1.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        m.charge(1_000_000, 1_000_000)
        assert m.remaining_usd == 0.0
        assert m.exhausted

    def test_the_snapshot_reports_what_the_paper_needs(self) -> None:
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        m.charge(500_000, 10_000)
        snap = m.snapshot()
        assert snap["calls"] == 1
        assert snap["input_tokens"] == 500_000
        assert snap["output_tokens"] == 10_000
        assert snap["spent_usd"] > 0


class TestChargeFromResponse:
    def test_real_usage_metadata_is_preferred(self) -> None:
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        response = type(
            "R",
            (),
            {"usage_metadata": {"input_tokens": 1_000_000, "output_tokens": 0}, "content": "x"},
        )()
        assert charge_from_response(m, response) == pytest.approx(3.0)

    def test_a_response_without_usage_is_still_charged(self) -> None:
        """An uncharged call is a hole in the ceiling."""
        m = CostMeter(limit_usd=10.0, input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        response = type("R", (), {"content": "a" * 4000})()
        charged = charge_from_response(m, response, fallback_input=1000)
        assert charged > 0
        assert m.calls == 1


class TestFrontierReady:
    def test_a_complete_config_is_ready(self) -> None:
        ready, reason = frontier_ready(_Cfg())
        assert ready, reason

    def test_disabled_is_not_ready(self) -> None:
        ready, reason = frontier_ready(_Cfg(enabled=False))
        assert not ready
        assert "enabled" in reason

    def test_zero_pricing_disables_the_arm_rather_than_making_it_free(self) -> None:
        """A meter that cannot price a call can never refuse one."""
        ready, reason = frontier_ready(_Cfg(input_usd_per_mtok=0.0, output_usd_per_mtok=0.0))
        assert not ready
        assert "pricing" in reason

    def test_a_declared_free_tier_is_ready_without_pricing(self) -> None:
        """An OpenRouter `:free` model genuinely bills nothing, so requiring
        pricing would block a legitimate arm."""
        ready, reason = frontier_ready(
            _Cfg(free_tier=True, input_usd_per_mtok=0.0, output_usd_per_mtok=0.0)
        )
        assert ready, reason

    def test_free_tier_is_an_explicit_claim_not_an_accident(self) -> None:
        """This is the whole reason free_tier exists as its own flag: an
        unconfigured PAID endpoint also has zero rates, and it must stay
        blocked. Only an operator saying 'this bills nothing' unblocks it."""
        ready, reason = frontier_ready(
            _Cfg(free_tier=False, input_usd_per_mtok=0.0, output_usd_per_mtok=0.0)
        )
        assert not ready
        assert "pricing" in reason

    def test_free_tier_still_requires_a_model_and_an_endpoint(self) -> None:
        """Declaring something free does not make it configured."""
        assert not frontier_ready(_Cfg(free_tier=True, model=""))[0]
        assert not frontier_ready(_Cfg(free_tier=True, base_url=None, api_key=None))[0]

    def test_a_zero_ceiling_is_rejected(self) -> None:
        ready, reason = frontier_ready(_Cfg(max_spend_usd=0.0))
        assert not ready
        assert "max_spend_usd" in reason

    def test_a_missing_model_is_rejected(self) -> None:
        ready, reason = frontier_ready(_Cfg(model=""))
        assert not ready
        assert "model" in reason

    def test_no_endpoint_and_no_key_is_rejected(self) -> None:
        ready, reason = frontier_ready(_Cfg(base_url=None, api_key=None))
        assert not ready


class TestBuildMeterFromConfig:
    def test_the_meter_inherits_the_configured_ceiling_and_rates(self) -> None:
        m = build_meter(_Cfg(max_spend_usd=7.5, input_usd_per_mtok=1.0, output_usd_per_mtok=2.0))
        assert m.limit_usd == pytest.approx(7.5)
        assert m.project(1_000_000, 1_000_000) == pytest.approx(3.0)


class TestTheDefaultConfigCannotSpendAnything:
    def test_the_shipped_default_is_disabled_and_unpriced(self) -> None:
        """A fresh clone, CI, or a deploy must not be one env var away from
        billing someone. Both the switch and the pricing have to be set."""
        from maljan.core.config import FrontierConfig

        cfg = FrontierConfig()
        assert cfg.enabled is False
        ready, _ = frontier_ready(cfg)
        assert not ready
