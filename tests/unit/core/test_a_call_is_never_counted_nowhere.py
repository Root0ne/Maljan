"""A call's cost is on the ledger before its reservation goes, and a held cap is one it can send.

Two gaps the hard bound had. A finished tool loop let go of its running turns
before the ledger had them, and the verdict and mediation released their
reservation before recording their answer: for a moment a parallel admission
saw neither. And a call to a model that takes no output cap of its own per call
was admitted with a held cap it could not send, so it could spend its whole
configured cap against a smaller reservation.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_ollama import ChatOllama
from tests.unit.agents.test_a_loop_has_no_default_limit import _analyst, _Model, _run

from maljan.core.spend import SpendCeilingStop, SpendMeter, spend_bound
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import model_name_of

PRICE = {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 4.0}


class TestAModelThatTakesNoCapOfItsOwn:
    def test_a_report_call_is_admitted_only_at_its_whole_cap(self) -> None:
        llm = ChatOllama(model="m")
        meter = SpendMeter(1.0, {model_name_of(llm): PRICE}, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, model_name_of(llm))
        ledger = SimpleNamespace(spend=meter)  # 0.96 left: 240,000 output tokens
        with pytest.raises(SpendCeilingStop, match="takes no cap of its own per call"):
            spend_bound(ledger, llm, 0, 393_216)
        slot = object()
        assert spend_bound(ledger, llm, 0, 100_000, slot=slot) is None
        assert meter.remaining() == pytest.approx(0.96 - 0.40)

    def test_an_agent_s_call_to_such_a_model_is_not_held(self) -> None:
        model = _Model(calls=0, seen=[])
        meter = SpendMeter(0.05, {model_name_of(model): PRICE}, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, model_name_of(model))
        agent = _analyst(model, TokenLedger(spend=meter))
        with pytest.raises(SpendCeilingStop, match="takes no cap of its own per call"):
            agent._spend_admits("revision", [], model=ChatOllama(model="m"))


class TestNoMomentCountedNowhere:
    def test_a_finished_loop_is_on_the_ledger_before_the_meter_lets_go(self) -> None:
        model = _Model(calls=2, seen=[])
        meter = SpendMeter(100.0, {model_name_of(model): PRICE}, table={})
        ledger = TokenLedger(spend=meter)
        recorded_at_forget: list[int] = []
        forget = meter.forget_loop

        def _forget(key: object) -> None:
            recorded_at_forget.append(ledger.calls)
            forget(key)

        meter.forget_loop = _forget  # type: ignore[method-assign]
        _run(_analyst(model, ledger))

        # Two tool rounds and the answer: three turns, on the ledger already.
        assert recorded_at_forget and recorded_at_forget[0] >= 3
