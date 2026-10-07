"""An answer ended while it streamed is charged a stated estimate against the spend ceiling.

The provider reports usage on the stream's last chunk, which an ended stream
never reads, so the answer reports none and the token ledger records a call
that reported no usage. The provider still bills the prompt and what it
generated. The answer carries an estimate: its prompt as the admission
measured it, priced as uncached input, and the generated pieces as output.
The spend meter charges it and counts it apart, labelled as an estimate; the
reported figures stay absent.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from maljan.analysis.run_summary import spend_lines
from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger, record_response_usage
from maljan.llm.stream_watch import ENDED_KEY, ESTIMATED_USAGE_KEY, ESTIMATED_USAGE_SOURCE

PRICE = {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 2.0, "cached_input_usd_per_mtok": 0.1}


def _ended(estimate: dict[str, object] | None) -> AIMessage:
    metadata: dict[str, object] = {ENDED_KEY: "its claims repeated"}
    if estimate is not None:
        metadata[ESTIMATED_USAGE_KEY] = estimate
    return AIMessage(content="CLAIM: x\n", response_metadata=metadata)


def _ledger() -> tuple[TokenLedger, SpendMeter]:
    meter = SpendMeter(10.0, {"m": PRICE}, table={})
    return TokenLedger(spend=meter), meter


def test_the_estimate_is_charged_and_counted_apart() -> None:
    ledger, meter = _ledger()
    estimate = {
        "input_tokens": 1_000_000,
        "output_tokens": 500_000,
        "source": ESTIMATED_USAGE_SOURCE,
    }

    record_response_usage(ledger, _ended(estimate), agent="static", model="m")

    # Uncached input at 1.00 and output at 2.00 per million.
    assert meter.spent() == 2.0
    spend = meter.snapshot()
    assert spend is not None
    assert spend["estimated_calls"] == 1
    assert spend["estimated_usd"] == 2.0
    assert spend["estimated_source"] == ESTIMATED_USAGE_SOURCE
    assert "unreported_calls" not in spend


def test_the_reported_figures_stay_absent() -> None:
    ledger, _meter = _ledger()

    record_response_usage(
        ledger,
        _ended({"input_tokens": 10, "output_tokens": 5, "source": ESTIMATED_USAGE_SOURCE}),
        agent="static",
        model="m",
    )

    snapshot = ledger.snapshot()
    assert snapshot["unreported_calls"] == 1
    assert snapshot["input_tokens"] == 0
    assert snapshot["output_tokens"] == 0


def test_an_answer_with_no_estimate_is_unreported_as_before() -> None:
    ledger, meter = _ledger()

    record_response_usage(ledger, _ended(None), agent="static", model="m")

    spend = meter.snapshot()
    assert spend is not None
    assert spend["unreported_calls"] == 1
    assert "estimated_calls" not in spend
    assert meter.spent() == 0.0


def test_the_run_summary_says_what_is_estimated() -> None:
    ledger, meter = _ledger()
    record_response_usage(
        ledger,
        _ended({"input_tokens": 1_000_000, "output_tokens": 0, "source": ESTIMATED_USAGE_SOURCE}),
        agent="static",
        model="m",
    )

    lines = spend_lines(meter.snapshot())

    assert any(
        "1.0000 USD is estimated for 1 call(s)" in line and ESTIMATED_USAGE_SOURCE in line
        for line in lines
    )
