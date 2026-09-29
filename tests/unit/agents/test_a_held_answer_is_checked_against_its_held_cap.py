"""An analyst answer held to a smaller cap for one call is checked against that cap.

The spend ceiling can hold one call to fewer output tokens than the model was
built with. ik_llama.cpp reports ``stop`` for an answer it cut at
``n_predict``, so the cut is read from the count reaching the cap. Against the
built cap, an answer cut at its held cap read as whole, and the validation
turn was never told it was cut. The cap in force is the held one where the
call was held, and the model's own otherwise.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from maljan.agents.base_agent import BaseAnalyst, cap_in_force, turn_held_cap
from maljan.llm.context_window import OutputCap, record_built_cap

BUILT = 32768
HELD = 40
TEXT = "CLAIM: The file reads a registry key.\nEVIDENCE: [ev_0001] strings\nCONFIDE"


def _message(tokens: int, text: str = TEXT) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={"input_tokens": 900, "output_tokens": tokens, "total_tokens": 900 + tokens},
        response_metadata={"finish_reason": "stop"},
    )


class _Model:
    """A model that answers every call with one message and keeps the keywords it was given."""

    def __init__(self, answer: AIMessage) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def invoke(self, messages: Any, **kwargs: Any) -> AIMessage:
        self.calls.append(kwargs)
        return self.answer


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")
        record_built_cap(self.llm, OutputCap(BUILT, "a quarter of 131072 (probed)"))

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestTheCapInForce:
    def test_is_the_held_cap_where_the_call_was_held(self) -> None:
        assert cap_in_force(BUILT, HELD) == HELD

    def test_is_the_built_cap_otherwise(self) -> None:
        assert cap_in_force(BUILT, None) == BUILT
        assert cap_in_force(BUILT, 0) == BUILT

    def test_is_the_held_cap_on_a_model_built_uncapped(self) -> None:
        assert cap_in_force(0, HELD) == HELD

    def test_a_hold_above_the_built_cap_does_not_raise_it(self) -> None:
        assert cap_in_force(BUILT, BUILT * 2) == BUILT


class TestTheRecord:
    def test_an_answer_at_its_held_cap_is_cut(self) -> None:
        analyst = _Analyst(MagicMock())
        analyst._record_usage(_message(HELD), held=HELD)
        assert analyst._last_answer_cut == (HELD, TEXT)

    def test_an_answer_short_of_its_held_cap_is_not(self) -> None:
        analyst = _Analyst(MagicMock())
        analyst._record_usage(_message(HELD - 10), held=HELD)
        assert analyst._last_answer_cut is None

    def test_an_unheld_answer_is_checked_against_the_built_cap(self) -> None:
        analyst = _Analyst(MagicMock())
        analyst._record_usage(_message(HELD))
        assert analyst._last_answer_cut is None


class TestAHeldAsk:
    def test_is_sent_its_held_cap_and_checked_against_it(self) -> None:
        model = _Model(_message(HELD))
        analyst = _Analyst(model)
        with patch.object(BaseAnalyst, "_spend_admits", return_value=HELD):
            analyst._invoke_llm_with_timeout([], 30.0, what="salvage")

        assert model.calls == [{"max_tokens": HELD}]
        assert analyst._last_answer_cut == (HELD, TEXT)


class TestALoopTurn:
    def test_the_held_cap_is_read_off_the_loop_binding(self) -> None:
        binding = RunnableLambda(lambda x: x).bind(max_tokens=HELD)
        assert turn_held_cap(binding, MagicMock()) == HELD

    def test_a_turn_sent_at_the_model_s_own_cap_has_none(self) -> None:
        binding = RunnableLambda(lambda x: x).bind()
        assert turn_held_cap(binding, MagicMock()) is None
        assert turn_held_cap(None, MagicMock()) is None
