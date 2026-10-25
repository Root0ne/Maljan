"""A tool loop whose next prompt would cross its model's price tier clears what it already cited.

A provider may price a request by its prompt's length (a price row's
``tiers``: Claude Haiku 5.5 bills every token of a prompt over 100,000 tokens
at five times the rate). Where the next request of a tool loop would be past
the first such boundary, the oldest tool answers whose ledger id the model has
already written in one of its own turns become references carrying that id,
exactly as a clear for the window makes them, and ``read_evidence`` reads them
again. An answer the model has not cited yet is never cleared for the tier, so
no fact it has not used leaves the conversation. A clear is made only where it
brings the request under the boundary (what no tier clear can take is below
it) and where the request it sends costs less at the provider's prices than
the one it replaces; otherwise the loop sends what it always sent. The
boundary is read from the agent's own model's price row, never a constant.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents import tool_answer_clearing as tac
from maljan.agents.base_agent import _message_chars


def _no_report(_messages: list[Any]) -> tuple[int, int]:
    return 0, -1


def _size(messages: list[Any]) -> int:
    return sum(_message_chars(m) for m in messages)


def _loop(turns: int, answer_chars: int, cite: dict[int, list[int]] | None = None) -> list[Any]:
    """A system turn, the task, then ``turns`` model turns with two stamped answers each.

    ``cite`` maps a turn to the entry numbers its text writes.
    """
    out: list[Any] = [SystemMessage(content="s" * 500), HumanMessage(content="Analyse.")]
    entry = 0
    for turn in range(turns):
        calls = [
            {"name": "lookup", "args": {"n": turn * 2 + slot}, "id": f"c{turn}_{slot}"}
            for slot in range(2)
        ]
        text = " ".join(f"ev_{n:04d} shows it." for n in (cite or {}).get(turn, []))
        out.append(AIMessage(content=text, tool_calls=calls))
        for call in calls:
            entry += 1
            out.append(
                ToolMessage(
                    content=f"[ev_{entry:04d}]\n" + "a" * answer_chars, tool_call_id=call["id"]
                )
            )
    return out


def _fit(clearing: tac.ToolAnswerClearing, messages: list[Any]) -> tac.FitResult:
    return clearing.fit(
        messages, extra_chars=0, measure=_message_chars, reported=_no_report, turn=9
    )


def _ids_whole(messages: list[Any]) -> set[str]:
    return {
        found
        for m in messages
        if isinstance(m, ToolMessage) and (found := tac.stamp_of(str(m.content)))
    }


def _ids_cleared(messages: list[Any]) -> set[str]:
    return {
        str(m.content)[len("[cleared ") :].split("]")[0]
        for m in messages
        if isinstance(m, ToolMessage) and str(m.content).startswith("[cleared ")
    }


class TestTheTierPoint:
    def test_only_answers_the_model_cited_are_cleared_oldest_first(self) -> None:
        # Turn 2 cites entries 1 and 3; entries 2 and 4 were never cited.
        messages = _loop(4, 2_000, cite={2: [1, 3]})
        clearing = tac.ToolAnswerClearing(tier_chars=_size(messages) - 1_000)
        fitted = _fit(clearing, messages)
        assert fitted.clearing is not None
        assert fitted.clearing.why == tac.CLEARED_FOR_TIER
        cleared = _ids_cleared(fitted.messages)
        assert cleared and cleared <= {"ev_0001", "ev_0003"}
        assert {"ev_0002", "ev_0004"} <= _ids_whole(fitted.messages)
        # The newest turn's answers stay whole.
        assert {"ev_0007", "ev_0008"} <= _ids_whole(fitted.messages)

    def test_it_clears_down_to_half_the_room_under_the_boundary(self) -> None:
        messages = _loop(6, 3_000, cite={4: [1, 2, 3, 4, 5, 6, 7, 8]})
        tier = _size(messages) - 2_000
        fitted = _fit(tac.ToolAnswerClearing(tier_chars=tier), messages)
        assert fitted.clearing is not None
        assert fitted.clearing.point_chars == tier
        assert fitted.clearing.chars_after <= fitted.clearing.target_chars < tier

    def test_a_request_under_the_boundary_is_the_same_messages(self) -> None:
        messages = _loop(4, 2_000, cite={2: [1, 2, 3]})
        fitted = _fit(tac.ToolAnswerClearing(tier_chars=_size(messages) + 1), messages)
        assert fitted.clearing is None
        assert all(a is b for a, b in zip(fitted.messages, messages, strict=True))

    def test_an_id_named_only_in_a_call_s_arguments_or_a_thought_is_not_cited(self) -> None:
        messages = _loop(4, 2_000)
        # Turn 2 reads ev_0001 again and thinks about ev_0003, and its text
        # writes neither.
        turn = next(i for i, m in enumerate(messages) if isinstance(m, AIMessage)) + 6
        assert isinstance(messages[turn], AIMessage)
        messages[turn] = AIMessage(
            content=[
                {"type": "thinking", "thinking": "ev_0003 holds the key", "signature": "s"},
                {"type": "text", "text": "Reading it again."},
            ],
            tool_calls=[
                {"name": "read_evidence", "args": {"evidence_id": "ev_0001"}, "id": "c2_0"},
                {"name": "lookup", "args": {"n": 5}, "id": "c2_1"},
            ],
        )
        clearing = tac.ToolAnswerClearing(tier_chars=_size(messages) // 2)
        assert not clearing.due(
            messages, extra_chars=0, measure=_message_chars, reported=_no_report
        )
        assert _fit(clearing, messages).clearing is None

    def test_nothing_cited_is_nothing_cleared(self) -> None:
        messages = _loop(4, 2_000)
        clearing = tac.ToolAnswerClearing(tier_chars=_size(messages) // 2)
        assert not clearing.due(
            messages, extra_chars=0, measure=_message_chars, reported=_no_report
        )
        fitted = _fit(clearing, messages)
        assert fitted.clearing is None
        assert all(a is b for a, b in zip(fitted.messages, messages, strict=True))

    def test_a_clear_that_cannot_reach_under_the_boundary_is_not_made(self) -> None:
        # What a tier clear cannot take (the framing, the uncited answers, the
        # newest turn) is already past the boundary: clearing would only lose
        # the cached prefix and keep the higher price.
        messages = _loop(4, 2_000, cite={2: [1]})
        cited_only = 2_000
        tier = _size(messages) - cited_only
        clearing = tac.ToolAnswerClearing(tier_chars=tier)
        assert not clearing.due(
            messages, extra_chars=0, measure=_message_chars, reported=_no_report
        )
        assert _fit(clearing, messages).clearing is None

    def test_a_clear_that_does_not_pay_is_not_made(self) -> None:
        messages = _loop(4, 2_000, cite={2: [1, 2, 3]})
        asked: list[tuple[int, int, int]] = []

        def pays(before: int, cached: int, after: int, _messages: list[Any]) -> bool:
            asked.append((before, cached, after))
            return False

        clearing = tac.ToolAnswerClearing(tier_chars=_size(messages) - 500, tier_pays=pays)
        assert _fit(clearing, messages).clearing is None
        assert asked and asked[0][0] == _size(messages) and asked[0][2] < asked[0][0]

    def test_the_cleared_stay_cleared_under_the_same_text(self) -> None:
        messages = _loop(4, 2_000, cite={2: [1, 3]})
        clearing = tac.ToolAnswerClearing(tier_chars=_size(messages) - 1_000)
        first = _fit(clearing, messages).messages
        again = _fit(clearing, messages).messages
        assert [m.content for m in again] == [m.content for m in first]

    def test_the_window_clear_is_what_it_was(self) -> None:
        # A window clear takes any stamped answer, cited or not, as before.
        messages = _loop(4, 2_000)
        fitted = _fit(tac.ToolAnswerClearing(window_chars=_size(messages) // 2), messages)
        assert fitted.clearing is not None and fitted.clearing.why == tac.CLEARED_FOR_WINDOW


class TestEveryCitationStaysResolvable:
    def test_each_cited_id_is_whole_or_read_again_by_its_reference(self) -> None:
        cite = {1: [1, 2], 2: [3], 3: [4, 5, 6]}
        messages = _loop(5, 2_500, cite=cite)
        stored = {f"ev_{n:04d}": "a" * 2_500 for n in range(1, 11)}
        fitted = _fit(tac.ToolAnswerClearing(tier_chars=_size(messages) // 2), messages)
        assert fitted.clearing is not None
        whole, cleared = _ids_whole(fitted.messages), _ids_cleared(fitted.messages)
        tool = tac.read_evidence_tool(stored.get)
        for wanted in stored:
            assert wanted in whole or wanted in cleared
            if wanted in cleared:
                assert tool.invoke({"evidence_id": wanted}) == stored[wanted]


class TestCitedIds:
    def test_the_ids_a_model_turn_writes_in_its_text(self) -> None:
        messages = [
            HumanMessage(content="ev_0009 is in the task, not a citation"),
            AIMessage(content="See [ev_0001] and EV_0002."),
            AIMessage(
                content=[
                    {"type": "thinking", "thinking": "ev_0003 maybe"},
                    {"type": "text", "text": "ev_0004 holds it"},
                ]
            ),
            ToolMessage(content="[ev_0005]\nev_0006", tool_call_id="x"),
        ]
        assert tac.cited_ids(messages) == {"ev_0001", "ev_0002", "ev_0004"}


class TestTheBoundaryIsTheModelsOwn:
    def test_a_tiered_price_row_gives_its_first_boundary(self) -> None:
        from maljan.core.spend import Price, prompt_tier_tokens

        tiered = Price(0.1, 0.5, tiers=((200_000, Price(0.3, 1.0)), (100_000, Price(0.5, 2.5))))
        assert prompt_tier_tokens(tiered) == 100_000
        assert prompt_tier_tokens(Price(0.1, 0.5)) is None
        assert prompt_tier_tokens(None) is None

    def test_the_vendored_table_s_haiku_row_is_read(self) -> None:
        from maljan.core.spend import SpendMeter, prompt_tier_tokens

        meter = SpendMeter()
        assert prompt_tier_tokens(meter.price_of("claude-haiku-5-5")) == 100_000

    def test_the_agent_s_clearing_carries_its_model_s_boundary(self) -> None:
        from maljan.agents.base_agent import BudgetMeter
        from maljan.core.spend import SpendMeter

        class _Ledger:
            spend = SpendMeter()

        agent = BudgetMeter.__new__(BudgetMeter)
        agent.token_ledger = _Ledger()
        agent._model_label = lambda: "claude-haiku-5-5"  # type: ignore[method-assign]
        agent._own_window_tokens = lambda: None  # type: ignore[method-assign]
        agent._clearing_per_token = lambda: 3  # type: ignore[method-assign]
        clearing = agent._tool_answer_clearing()
        assert clearing.tier_chars == 100_000 * 3
        assert clearing.tier_pays is not None

    def test_an_unpriced_or_flat_model_has_no_tier_point(self) -> None:
        from maljan.agents.base_agent import BudgetMeter
        from maljan.core.spend import SpendMeter

        class _Ledger:
            spend = SpendMeter()

        agent = BudgetMeter.__new__(BudgetMeter)
        agent.token_ledger = _Ledger()
        agent._own_window_tokens = lambda: None  # type: ignore[method-assign]
        agent._clearing_per_token = lambda: 3  # type: ignore[method-assign]
        for label in ("", "a-model-nobody-prices", "deepseek-v4-flash"):
            agent._model_label = lambda label=label: label  # type: ignore[method-assign]
            assert agent._tool_answer_clearing().tier_chars is None


class TestTheCacheLifetimeIsTheModelsOwn:
    def test_the_provider_s_whole_chain_of_classes_states_it(self) -> None:
        from langchain_anthropic import ChatAnthropic

        from maljan.llm.anthropic_history import prompt_cache_seconds, with_preserved_thinking
        from maljan.llm.tool_replies import with_answered_tool_calls
        from maljan.llm.transient import with_transient_retries

        for ttl, seconds in (("5m", 300), ("1h", 3600)):
            built = with_answered_tool_calls(
                with_transient_retries(with_preserved_thinking(ChatAnthropic, ttl)), "anthropic"
            )
            assert prompt_cache_seconds(built) == seconds
            model = built(model_name="claude-haiku-5-5", api_key="unused")
            assert prompt_cache_seconds(model) == seconds
        assert prompt_cache_seconds(ChatAnthropic) is None

    def test_a_binding_or_a_model_list_answers_for_the_models_it_calls(self) -> None:
        from unittest.mock import MagicMock

        from maljan.llm.anthropic_history import CACHE_LIFETIME_ATTR, prompt_cache_seconds

        def stating(seconds: int | None) -> Any:
            class _Model:
                pass

            if seconds is not None:
                setattr(_Model, CACHE_LIFETIME_ATTR, seconds)
            return _Model()

        binding = MagicMock(spec=["bound"])
        binding.bound = stating(300)
        assert prompt_cache_seconds(binding) == 300
        listed = MagicMock(spec=["models"])
        listed.models = [stating(300), stating(3600)]
        assert prompt_cache_seconds(listed) == 300
        listed.models = [stating(300), stating(None)]
        assert prompt_cache_seconds(listed) is None


class TestWhetherAClearPays:
    def test_a_clear_under_the_boundary_pays_when_the_dearer_tier_costs_more(self) -> None:
        from maljan.core.spend import Price

        price = Price(
            0.1,
            0.5,
            0.01,
            cache_write=0.125,
            tiers=((100_000, Price(0.5, 2.5, 0.05, cache_write=0.625)),),
        )
        # 120k tokens, 110k of them cached, against 70k written whole, with a
        # 4k answer: the dearer output and input outweigh the rewrite.
        assert tac.tier_clear_pays(price, 120_000, 110_000, 70_000, 4_000)
        # With no answer to price and the prompt almost all cached, the
        # rewrite costs more than the cheaper tier saves.
        assert not tac.tier_clear_pays(price, 101_000, 100_500, 99_000, 0)

    def test_an_hour_s_cache_writes_are_priced_as_such(self) -> None:
        from maljan.core.spend import SpendMeter

        price = SpendMeter().price_of("claude-haiku-5-5")
        # At five-minute writes the clear pays; written for an hour the
        # cleared request's whole rewrite costs more than it saves.
        assert tac.tier_clear_pays(price, 101_000, 98_000, 60_000, 1_000)
        assert not tac.tier_clear_pays(price, 101_000, 98_000, 60_000, 1_000, hour_writes=True)

    def test_the_agent_prices_writes_at_its_model_s_cache_lifetime(self) -> None:
        from maljan.agents.base_agent import BudgetMeter
        from maljan.core.spend import SpendMeter
        from maljan.llm.anthropic_history import CACHE_LIFETIME_ATTR

        class _Ledger:
            spend = SpendMeter()

        class _HourModel:
            pass

        setattr(_HourModel, CACHE_LIFETIME_ATTR, 3600)
        agent = BudgetMeter.__new__(BudgetMeter)
        agent.token_ledger = _Ledger()
        agent.llm = _HourModel()
        agent._model_label = lambda: "claude-haiku-5-5"  # type: ignore[method-assign]
        agent._own_window_tokens = lambda: None  # type: ignore[method-assign]
        agent._clearing_per_token = lambda: 1  # type: ignore[method-assign]
        pays = agent._tool_answer_clearing().tier_pays
        assert pays is not None
        turn = AIMessage(
            content="",
            usage_metadata={"input_tokens": 1, "output_tokens": 1_000, "total_tokens": 1_001},
        )
        assert not pays(101_000, 98_000, 60_000, [turn])
        setattr(_HourModel, CACHE_LIFETIME_ATTR, 300)
        assert agent._tool_answer_clearing().tier_pays(101_000, 98_000, 60_000, [turn])  # type: ignore[misc]
