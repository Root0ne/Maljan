"""Several comparison arms, and the throttle handling that decides whether a
series is real or an artefact of who answered fastest.

The parameter-size series is the point: `arXiv:2606.18166` reports parameter
count as the only significant predictor of ATT&CK-classification F1, and a
single comparison model can only agree or disagree on one point. A series can
test the trend — but only if every arm contributes the same number of samples.

Two ways that goes wrong, and both are tested here rather than discovered in a
run:

* **a half-configured arm silently leaves the series.** Then the correlation is
  computed over whatever survived and reported as though it were the design.
  ``resolve_arms`` drops such an arm *and* the caller can see it is missing.
* **a throttled call is counted as a failure.** This is not hypothetical: B8's
  first attempt did exactly that, finished 9 of 25 arms, and reported a point
  estimate that the completed run later moved by 0.086 — through the local mean
  and out the other side. A 429 is a request to wait, not an answer.
"""

from __future__ import annotations

import pytest

from maljan.core.config import FrontierArm, FrontierConfig
from maljan.core.frontier import (
    PacedCaller,
    arm_provenance,
    is_rate_limited,
    resolve_arms,
)


def _arm(**kw: object) -> FrontierArm:
    base: dict[str, object] = {
        "model": "vendor/model-x",
        "base_url": "https://example.invalid/v1",
        "api_key": "sk-test",
        "free_tier": True,
    }
    base.update(kw)
    return FrontierArm(**base)  # type: ignore[arg-type]


class TestResolveArms:
    def test_the_inherited_endpoint_is_the_default_arm(self) -> None:
        """B8's stored record names no arm. Keeping the inherited fields as
        ``default`` means that record stays readable without being rewritten."""
        cfg = FrontierConfig(
            enabled=True, model="vendor/first", base_url="https://x.invalid", free_tier=True
        )
        assert list(resolve_arms(cfg)) == ["default"]

    def test_named_arms_join_the_default(self) -> None:
        cfg = FrontierConfig(
            enabled=True,
            model="vendor/first",
            base_url="https://x.invalid",
            free_tier=True,
            arms={"glm": _arm(model="z-ai/glm"), "minimax": _arm(model="minimaxai/m3")},
        )
        assert set(resolve_arms(cfg)) == {"default", "glm", "minimax"}

    def test_disabling_the_parent_disables_every_arm(self) -> None:
        """One switch, not one per arm — a second place to be off is a second
        place for a run to silently not happen."""
        cfg = FrontierConfig(enabled=False, arms={"glm": _arm()})
        assert resolve_arms(cfg) == {}

    def test_a_half_configured_arm_is_dropped_rather_than_run(self) -> None:
        cfg = FrontierConfig(enabled=True, arms={"good": _arm(), "nameless": _arm(model="")})
        assert set(resolve_arms(cfg)) == {"good"}

    def test_a_paid_arm_without_pricing_is_dropped(self) -> None:
        """The ceiling is enforced by the rates; an unpriced paid arm has none,
        so it would run uncapped. Dropping it is the same rule the single-arm
        path already applied."""
        cfg = FrontierConfig(enabled=True, arms={"paid": _arm(free_tier=False)})
        assert resolve_arms(cfg) == {}

    def test_an_unconfigured_default_does_not_occupy_a_slot(self) -> None:
        """``enabled`` alone must not manufacture an arm with no model."""
        cfg = FrontierConfig(enabled=True, arms={"glm": _arm()})
        assert list(resolve_arms(cfg)) == ["glm"]


class TestArmProvenance:
    def test_parameter_counts_travel_with_the_scores(self) -> None:
        """The correlation is computed from these fields. If they lived only in
        prose, the number in the paper and the number in the data could differ
        and nothing would notice."""
        p = arm_provenance("glm", _arm(total_params_b=744.0, active_params_b=40.0))
        assert p["total_params_b"] == 744.0
        assert p["active_params_b"] == 40.0
        assert p["arm"] == "glm"

    def test_an_undeclared_size_is_zero_not_absent(self) -> None:
        """A missing key would be dropped by an analysis that filters on
        presence; a zero is visibly wrong and gets fixed."""
        assert arm_provenance("x", _arm())["total_params_b"] == 0.0

    def test_no_key_material_is_emitted(self) -> None:
        blob = str(arm_provenance("x", _arm(api_key="sk-super-secret")))
        assert "sk-super-secret" not in blob


class TestRateLimitDetection:
    def test_a_status_code_attribute_is_read(self) -> None:
        exc = type("E", (Exception,), {"status_code": 429})()
        assert is_rate_limited(exc) is True

    def test_a_nested_response_status_is_read(self) -> None:
        response = type("R", (), {"status_code": 429})()
        exc = type("E", (Exception,), {"response": response})()
        assert is_rate_limited(exc) is True

    def test_the_message_is_read_when_no_structure_is_exposed(self) -> None:
        """The OpenAI SDK, httpx and requests each wrap this differently, and
        which one a harness uses must not decide whether a run survives."""
        assert is_rate_limited(RuntimeError("Error code: 429 - Too Many Requests")) is True
        assert is_rate_limited(RuntimeError("rate limit exceeded")) is True

    def test_other_failures_are_not_throttles(self) -> None:
        assert is_rate_limited(RuntimeError("401 Unauthorized")) is False
        assert is_rate_limited(ValueError("bad prompt")) is False

    def test_a_status_code_of_a_different_number_is_not_a_throttle(self) -> None:
        exc = type("E", (Exception,), {"status_code": 500})()
        assert is_rate_limited(exc) is False


class TestPacedCaller:
    def test_a_throttled_call_is_retried_and_then_counted_as_success(self) -> None:
        calls = {"n": 0}

        def flaky() -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("Error code: 429")
            return "ok"

        caller = PacedCaller(max_retries=5, base_delay_s=0.0, max_delay_s=0.0)
        assert caller.invoke(flaky) == "ok"
        assert caller.calls == 1
        assert caller.retries == 2
        assert caller.throttled_calls == 1

    def test_a_clean_call_records_no_throttle(self) -> None:
        caller = PacedCaller(base_delay_s=0.0)
        assert caller.invoke(lambda: "ok") == "ok"
        assert (caller.calls, caller.retries, caller.throttled_calls) == (1, 0, 0)

    def test_a_non_throttle_error_is_raised_immediately(self) -> None:
        """A bad key or a malformed prompt must surface at once rather than be
        retried into the backoff ceiling — several minutes of sleeping is a
        painful way to learn the request was never going to work."""
        attempts = {"n": 0}

        def broken() -> str:
            attempts["n"] += 1
            raise RuntimeError("401 Unauthorized")

        caller = PacedCaller(max_retries=5, base_delay_s=0.0)
        with pytest.raises(RuntimeError, match="401"):
            caller.invoke(broken)
        assert attempts["n"] == 1

    def test_persistent_throttling_eventually_raises_rather_than_looping(self) -> None:
        caller = PacedCaller(max_retries=2, base_delay_s=0.0, max_delay_s=0.0)
        with pytest.raises(RuntimeError, match="429"):
            caller.invoke(lambda: (_ for _ in ()).throw(RuntimeError("429")))
        assert caller.retries == 2
        assert caller.calls == 0

    def test_backoff_grows_and_is_capped(self) -> None:
        caller = PacedCaller(base_delay_s=5.0, max_delay_s=90.0)
        assert [caller.delay_for(i) for i in range(6)] == [5, 10, 20, 40, 80, 90]

    def test_for_arm_reads_the_endpoints_own_pacing(self) -> None:
        """Throttling is a property of the endpoint, so it is configured with the
        endpoint rather than hard-coded once for every provider."""
        caller = PacedCaller.for_arm(_arm(min_interval_s=7.5, max_retries=9))
        assert caller.min_interval_s == 7.5
        assert caller.max_retries == 9

    def test_the_snapshot_reports_what_the_run_cost_in_waiting(self) -> None:
        """A run that needed 300 retries to finish is a different measurement
        from one that needed none, and the paper reports wall-clock."""
        caller = PacedCaller(base_delay_s=0.0)
        caller.invoke(lambda: "ok")
        assert caller.snapshot()["calls"] == 1
        assert "retries" in caller.snapshot()
