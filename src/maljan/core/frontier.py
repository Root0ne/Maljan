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
    if not getattr(cfg, "enabled", False):
        return False, "frontier.enabled is false"
    if not getattr(cfg, "model", ""):
        return False, "frontier.model is unset"
    if not getattr(cfg, "base_url", None) and not getattr(cfg, "api_key", None):
        return False, "frontier needs base_url or api_key"
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
