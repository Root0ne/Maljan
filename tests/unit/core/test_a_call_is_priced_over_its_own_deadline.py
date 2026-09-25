"""A call is priced over its own deadline, not a fixed half hour.

A call is reserved at the highest rate in force between its admission and its
deadline, so one sent across a window's edge never settles above what it
reserved. Loop turns, report sections and the verdict passed no deadline, and
every one of them was priced over the client's default 1,800 s: for the half
hour before a peak window opened, every call in flight reserved at peak. Each
is now priced over the whole-call deadline its request is sent with.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from langchain_openai import ChatOpenAI

from maljan.core.spend import SpendMeter, spend_bound

# Seven minutes before a weekday peak window opens at 01:00 UTC.
BEFORE_PEAK = datetime(2026, 9, 25, 0, 53, tzinfo=UTC)


def _meter() -> SpendMeter:
    return SpendMeter(10.0, clock=lambda: BEFORE_PEAK)


def _flash(timeout: float) -> ChatOpenAI:
    return ChatOpenAI(model="deepseek-flash", api_key="k", max_tokens=1_000_000, timeout=timeout)


@pytest.mark.parametrize(("timeout", "reserved"), [(60.0, 0.6), (600.0, 1.2)])
def test_a_report_call_is_priced_over_its_request_s_deadline(
    timeout: float, reserved: float
) -> None:
    meter = _meter()
    slot = object()
    spend_bound(SimpleNamespace(spend=meter), _flash(timeout), 0, 1_000_000, slot=slot)
    # A one-minute request settles before the window opens: the off-peak rate.
    # A ten-minute one may be sent inside it: the peak rate.
    assert meter.committed() == pytest.approx(reserved)


def test_an_agent_s_call_is_priced_over_its_request_s_deadline() -> None:
    from tests.unit.agents.test_a_loop_has_no_default_limit import _analyst, _Model

    from maljan.core.token_ledger import TokenLedger

    meter = _meter()
    seen: list[float | None] = []
    admit = meter.admit

    def _admit(**kwargs: object) -> object:
        seen.append(kwargs.get("deadline_s"))  # type: ignore[arg-type]
        return admit(**kwargs)  # type: ignore[arg-type]

    meter.admit = _admit  # type: ignore[method-assign]
    agent = _analyst(_Model(calls=0, seen=[]), TokenLedger(spend=meter))
    agent._spend_admits("revision", [], model=_flash(90.0))
    assert seen == [90.0]
