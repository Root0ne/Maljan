"""The frontier arm: a second endpoint, and a spend ceiling that actually stops.

**Why this exists.** Every LLM result in this work comes from one model on one
machine — pitfall **P8**, the surrogate fallacy, and the one this project is most
exposed to. `arXiv:2606.18166` sharpens it: across models on the nearest task,
**parameter size was the only statistically significant predictor** of
ATT&CK-classification F1 (rho=0.85, p=0.014), while prompt strategy,
chain-of-thought and temperature were not. A single-model finding therefore
cannot be read as a property of the architecture, and no amount of careful
writing changes that — only a second, differently-sized model does. That is
queue items **B8** (fixture sanity check) and **C6** (the n=100 cohort).

**Why the ceiling is the interesting part.** This arm spends the author's money.
An eval harness that loops over 100 samples with a retry path is exactly the
shape of thing that quietly bills for hours, so the budget is enforced as a
**precondition on every call**, not reconciled afterwards:

  * the meter refuses a call whose *projected* cost would cross the limit, using
    the caller's own worst-case token estimate — a call that has already been
    made cannot be un-billed;
  * projections are deliberately **pessimistic** (output priced at the full cap,
    because that is what a degenerate decode will actually produce);
  * the real cost is charged from observed usage afterwards, so the meter
    converges on truth rather than drifting on estimates.

``max_spend_usd`` defaults to a small number. Raising it is a deliberate act.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class FrontierBudgetExceeded(RuntimeError):
    """Raised instead of making a call that would cross the spend ceiling."""


# IEEE-754 slack, not a spending allowance. Costs are sums of products of floats,
# so a projection that should land exactly on the limit lands a few ulps above it
# ($0.30 + $0.12 = $0.42000000000000004) and an otherwise-affordable call is
# refused at a round limit. A billionth of a dollar cannot fund a request; the
# alternative — comparing raw floats — makes the boundary behave arbitrarily.
_USD_EPSILON = 1e-9


def usd_for_tokens(tokens: int, usd_per_mtok: float) -> float:
    """Cost of ``tokens`` at a per-million-token rate. Negative inputs cost nothing."""
    if tokens <= 0 or usd_per_mtok <= 0:
        return 0.0
    return (tokens / 1_000_000.0) * usd_per_mtok


@dataclass
class CostMeter:
    """A hard USD ceiling for one frontier run.

    Not thread-safe on purpose: the frontier arm runs sequentially, and a lock
    here would imply a concurrency story this arm does not have. If that changes,
    add the lock — do not assume the counters are safe.
    """

    limit_usd: float
    input_usd_per_mtok: float = 0.0
    output_usd_per_mtok: float = 0.0
    spent_usd: float = 0.0
    calls: int = 0
    refusals: int = 0
    _charges: list[tuple[int, int, float]] = field(default_factory=list)

    # -- projection ---------------------------------------------------------

    def project(self, input_tokens: int, max_output_tokens: int) -> float:
        """Worst-case cost of a call that has not been made yet.

        Output is priced at the **full cap**, not at an expected value. A
        degenerate decode is precisely the case where an expected-value estimate
        under-charges, and §3.3 documents that this model does that.
        """
        return usd_for_tokens(input_tokens, self.input_usd_per_mtok) + usd_for_tokens(
            max_output_tokens, self.output_usd_per_mtok
        )

    def would_exceed(self, input_tokens: int, max_output_tokens: int) -> bool:
        projected = self.spent_usd + self.project(input_tokens, max_output_tokens)
        return projected > self.limit_usd + _USD_EPSILON

    def check(self, input_tokens: int, max_output_tokens: int) -> None:
        """Raise rather than make a call that would cross the ceiling.

        Called *before* the request. Refusing after the fact is not refusing.
        """
        if self.would_exceed(input_tokens, max_output_tokens):
            self.refusals += 1
            projected = self.project(input_tokens, max_output_tokens)
            raise FrontierBudgetExceeded(
                f"frontier spend ceiling reached: ${self.spent_usd:.4f} spent, "
                f"${projected:.4f} projected, limit ${self.limit_usd:.2f} "
                f"after {self.calls} call(s)"
            )

    # -- accounting ---------------------------------------------------------

    def charge(self, input_tokens: int, output_tokens: int) -> float:
        """Record a completed call's actual cost. Returns the amount charged."""
        cost = usd_for_tokens(input_tokens, self.input_usd_per_mtok) + usd_for_tokens(
            output_tokens, self.output_usd_per_mtok
        )
        self.spent_usd += cost
        self.calls += 1
        self._charges.append((max(0, input_tokens), max(0, output_tokens), cost))
        return cost

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.limit_usd - self.spent_usd)

    @property
    def exhausted(self) -> bool:
        return self.remaining_usd <= 0.0

    def snapshot(self) -> dict[str, Any]:
        """Reportable state — the frontier arm's cost goes in the paper."""
        return {
            "limit_usd": round(self.limit_usd, 4),
            "spent_usd": round(self.spent_usd, 6),
            "remaining_usd": round(self.remaining_usd, 6),
            "calls": self.calls,
            "refusals": self.refusals,
            "input_tokens": sum(c[0] for c in self._charges),
            "output_tokens": sum(c[1] for c in self._charges),
        }


def charge_from_response(meter: CostMeter, response: Any, *, fallback_input: int = 0) -> float:
    """Charge a LangChain response's real usage; fall back to an estimate.

    Prefers the provider's ``usage_metadata`` — frontier endpoints report it
    reliably, unlike the local server. When it is absent the call is still
    charged, from ``fallback_input`` and a character estimate of the content:
    an uncharged call is a hole in the ceiling.
    """
    from maljan.core.token_ledger import estimate_tokens

    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict) and usage.get("input_tokens") is not None:
        return meter.charge(
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
        )
    content = getattr(response, "content", response)
    return meter.charge(fallback_input, estimate_tokens(str(content)))


def frontier_ready(cfg: Any) -> tuple[bool, str]:
    """Whether the frontier arm can run, and why not when it cannot.

    Returns ``(ready, reason)``. Priced at zero counts as *not ready*: a meter
    with zero rates can never refuse anything, which would turn the ceiling into
    decoration.
    """
    # A named arm has no ``enabled`` field of its own — ``FrontierConfig.enabled``
    # gates the whole set, and an arm that had to be enabled twice would be a
    # second place for a run to silently not happen. Absent means "the parent
    # already decided"; present and false still refuses.
    enabled = getattr(cfg, "enabled", None)
    if enabled is not None and not enabled:
        return False, "frontier.enabled is false"
    if not getattr(cfg, "model", ""):
        return False, "frontier.model is unset"
    if not getattr(cfg, "base_url", None) and not getattr(cfg, "api_key", None):
        return False, "frontier needs base_url or api_key"
    if getattr(cfg, "free_tier", False):
        # Nothing to price and nothing to refuse. This is deliberately a
        # separate branch rather than a zero-cost special case of the paid path:
        # "the endpoint bills nothing" is a claim the operator makes explicitly
        # and can be checked, whereas "the rates happen to be zero" is what an
        # unconfigured paid endpoint also looks like. Token counting continues.
        return True, ""
    rate_in = float(getattr(cfg, "input_usd_per_mtok", 0.0) or 0.0)
    rate_out = float(getattr(cfg, "output_usd_per_mtok", 0.0) or 0.0)
    if rate_in <= 0 and rate_out <= 0:
        return False, "frontier pricing is unset — the spend ceiling could never fire"
    if float(getattr(cfg, "max_spend_usd", 0.0) or 0.0) <= 0:
        return False, "frontier.max_spend_usd must be > 0"
    return True, ""


def build_meter(cfg: Any) -> CostMeter:
    """A meter from a ``FrontierConfig``. Validate with :func:`frontier_ready` first."""
    return CostMeter(
        limit_usd=float(cfg.max_spend_usd),
        input_usd_per_mtok=float(cfg.input_usd_per_mtok),
        output_usd_per_mtok=float(cfg.output_usd_per_mtok),
    )


def build_frontier_llm(cfg: Any, *, max_tokens: int | None = None) -> Any:
    """A ``ChatOpenAI`` pointed at the frontier endpoint.

    Deliberately built here rather than through ``LLMRegistry``: the frontier arm
    is a comparison endpoint for one experiment, not a provider the pipeline may
    quietly start using. Nothing in ``src/maljan`` outside the eval harnesses
    should call this.
    """
    from langchain_openai import ChatOpenAI

    ready, reason = frontier_ready(cfg)
    if not ready:
        raise FrontierBudgetExceeded(f"frontier arm not configured: {reason}")

    kwargs: dict[str, Any] = {
        "model": cfg.model,
        "temperature": 0,
    }
    if getattr(cfg, "base_url", None):
        kwargs["base_url"] = cfg.base_url
    api_key = getattr(cfg, "api_key", None)
    if api_key is not None:
        # SecretStr in config, a plain string in the eval stubs.
        reveal = getattr(api_key, "get_secret_value", None)
        kwargs["api_key"] = reveal() if callable(reveal) else api_key
    if max_tokens and max_tokens > 0:
        kwargs["max_tokens"] = max_tokens
    return ChatOpenAI(**kwargs)


# ---------------------------------------------------------------------------
# Several arms, and a client that survives their rate limits
# ---------------------------------------------------------------------------


def resolve_arms(cfg: Any) -> dict[str, Any]:
    """The comparison arms this configuration defines, by name.

    The inherited single-endpoint fields are arm ``default`` — that is the arm
    B8 ran, and keeping its name stable means the stored B8 record does not have
    to be rewritten to accommodate the ones added after it. Named arms follow.

    Only arms that pass :func:`frontier_ready` are returned. An arm that is
    half-configured is dropped here rather than failing in the middle of a run,
    because a series that quietly loses a point produces a correlation over
    whatever survived and reports it as though it were the design.
    """
    if not getattr(cfg, "enabled", False):
        return {}

    out: dict[str, Any] = {}
    ready, _why = frontier_ready(cfg)
    if ready:
        out["default"] = cfg
    for name, arm in (getattr(cfg, "arms", None) or {}).items():
        ok, _reason = frontier_ready(arm)
        if ok:
            out[str(name)] = arm
    return out


def arm_provenance(name: str, arm: Any) -> dict[str, Any]:
    """What an arm must declare about itself for the parameter-size analysis.

    Emitted into every result file. The correlation this project reports against
    `arXiv:2606.18166` is computed from these numbers, so they belong next to the
    scores rather than in the prose describing them.
    """
    return {
        "arm": name,
        "model": getattr(arm, "model", ""),
        "base_url": getattr(arm, "base_url", None),
        "total_params_b": float(getattr(arm, "total_params_b", 0.0) or 0.0),
        "active_params_b": float(getattr(arm, "active_params_b", 0.0) or 0.0),
        "quantisation": getattr(arm, "quantisation", "") or "",
        "free_tier": bool(getattr(arm, "free_tier", False)),
    }


def is_rate_limited(exc: BaseException) -> bool:
    """Whether an exception is the endpoint saying "too fast" rather than "no".

    The distinction is the whole point. B8's first attempt counted HTTP 429s as
    failed calls, finished with 9 of 25 arms, and reported a point estimate that
    the completed run later moved by 0.086 — through the local mean and out the
    other side. A throttle is not a result; it is a request to wait.

    Checked structurally where the client exposes a status code and by substring
    otherwise, because the OpenAI SDK, httpx and requests each wrap it
    differently and this must not depend on which one a harness happens to use.
    """
    for attr in ("status_code", "http_status", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and value == 429:
            return True
    response = getattr(exc, "response", None)
    if response is not None and getattr(response, "status_code", None) == 429:
        return True
    text = f"{type(exc).__name__}: {exc}".lower()
    return "429" in text or "too many requests" in text or "rate limit" in text


@dataclass
class PacedCaller:
    """Calls an endpoint no faster than it will answer.

    Two mechanisms, and they address different failures:

    * ``min_interval_s`` spaces calls out so the limit is approached rather than
      hit. Measured on NVIDIA NIM 2026-08-14: two calls four seconds apart
      succeed, the next six return 429.
    * exponential backoff recovers when it is hit anyway. Shared quotas mean no
      fixed interval is safe, so the retry path is not optional.

    ``throttled_calls`` and ``retries`` are recorded rather than swallowed: a run
    that needed 300 retries to finish is a different measurement from one that
    needed none, and the paper reports wall-clock.
    """

    min_interval_s: float = 0.0
    max_retries: int = 6
    base_delay_s: float = 5.0
    max_delay_s: float = 90.0
    calls: int = 0
    retries: int = 0
    throttled_calls: int = 0
    _last_call_at: float = 0.0

    @classmethod
    def for_arm(cls, arm: Any) -> PacedCaller:
        return cls(
            min_interval_s=float(getattr(arm, "min_interval_s", 0.0) or 0.0),
            max_retries=int(getattr(arm, "max_retries", 6) or 6),
        )

    def delay_for(self, attempt: int) -> float:
        """Backoff for retry ``attempt`` (0-based), capped."""
        return float(min(self.base_delay_s * (2.0**attempt), self.max_delay_s))

    def invoke(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run ``fn``, waiting out throttles. Non-throttle errors propagate.

        A failed call is data; a throttled call is not. Anything that is not a
        rate limit is raised immediately so a broken prompt or a bad key surfaces
        at once instead of being retried into the backoff ceiling.
        """
        import time

        if self.min_interval_s > 0 and self._last_call_at:
            wait = self.min_interval_s - (time.monotonic() - self._last_call_at)
            if wait > 0:
                time.sleep(wait)

        was_throttled = False
        for attempt in range(self.max_retries + 1):
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — re-raised unless it is a throttle
                if not is_rate_limited(exc) or attempt >= self.max_retries:
                    self._last_call_at = time.monotonic()
                    raise
                was_throttled = True
                self.retries += 1
                time.sleep(self.delay_for(attempt))
                continue
            self.calls += 1
            self._last_call_at = time.monotonic()
            if was_throttled:
                self.throttled_calls += 1
            return result
        raise FrontierBudgetExceeded("unreachable: retry loop exhausted without raising")

    def snapshot(self) -> dict[str, int | float]:
        return {
            "calls": self.calls,
            "retries": self.retries,
            "throttled_calls": self.throttled_calls,
            "min_interval_s": self.min_interval_s,
        }
