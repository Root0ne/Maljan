"""An analyst's model calls are read, while they stream, under the repeated-claims rule.

The rule is the one the check on the finished answer applies
(``pipeline.validation.claims_repeated``): claims keyed by their whole block,
the margin derived from the distinct count, ``validation.claim_repeat_margin``
as the operator's override. The analyst names it for each of its model calls,
which run on the shared agent loop, so the rule is carried across to that
loop's task. An answer the rule ended is the answer the check then reads, and
the check asks its one whole-answer question as it does after any answer.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import BaseAnalyst, _run_coro_blocking, claims_repeat_rule
from maljan.core.config import Settings
from maljan.llm.stream_watch import current_rule, watching
from maljan.pipeline.validation import ANALYST_REPEATED_CODE, claims_repeated


def _block(n: int) -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    )


DISTINCT = "".join(_block(n) for n in (1, 2, 3))
# The three claims, then written again until the derived margin is crossed.
ENDED = DISTINCT + DISTINCT + _block(1)


class _Model:
    """A model whose answer records the rule it was read under."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.rules: list[Any] = []

    async def ainvoke(self, messages: Any, **_kwargs: Any) -> AIMessage:
        self.rules.append(current_rule())
        await asyncio.sleep(0)
        return AIMessage(content=self.text)


class _Analyst(BaseAnalyst):
    def __init__(self, model: Any) -> None:
        super().__init__(llm=model, name="triage")
        self.pack_ledger_ids = ["ev_0001"]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestTheRule:
    def test_it_ends_an_answer_where_the_check_on_the_finished_answer_would_fire(self) -> None:
        rule = claims_repeat_rule(None)

        assert rule(DISTINCT + DISTINCT) is None
        why = rule(ENDED)
        assert why is not None
        assert "7 CLAIM block(s) begun, 3 distinct" in why
        assert claims_repeated(ENDED) is not None

    def test_the_operator_s_margin_is_the_one_read(self) -> None:
        assert claims_repeat_rule(0)(DISTINCT + _block(1)) is not None
        assert claims_repeat_rule(20)(ENDED) is None

    def test_it_reads_the_text_the_check_reads_without_tool_call_scaffolding(self) -> None:
        # The claim parser strips a tool call's scaffolding before it reads
        # claims, so claims inside one are no claims to either reader.
        inside = DISTINCT + "<tool_call>\n" + DISTINCT * 3 + "</tool_call>\n"

        assert claims_repeat_rule(None)(inside) is None


class TestTheRuleReachesTheAgentLoop:
    def test_a_rule_named_by_the_caller_is_carried_to_the_loop_s_task(self) -> None:
        async def _seen() -> Any:
            return current_rule()

        def _rule(_text: str) -> str | None:
            return None

        with watching(_rule):
            assert _run_coro_blocking(_seen(), 5.0, label="test") is _rule
        assert _run_coro_blocking(_seen(), 5.0, label="test") is None

    def test_an_analyst_s_model_call_is_read_under_the_claims_rule(self) -> None:
        model = _Model("no claims")
        analyst = _Analyst(model)

        analyst._invoke_llm_with_timeout([HumanMessage(content="go")], 5.0)

        (rule,) = model.rules
        assert rule is not None
        assert rule(DISTINCT + DISTINCT) is None
        assert rule(ENDED) is not None

    def test_the_operator_s_margin_reaches_the_rule(self) -> None:
        model = _Model("no claims")
        analyst = _Analyst(model)
        settings = Settings(_env_file=None, validation={"claim_repeat_margin": 0})

        with patch("maljan.agents.base_agent.get_settings", return_value=settings):
            analyst._invoke_llm_with_timeout([HumanMessage(content="go")], 5.0)

        (rule,) = model.rules
        assert rule(DISTINCT + _block(1)) is not None

    def test_nothing_outside_an_analyst_call_is_read_under_it(self) -> None:
        model = _Model("no claims")
        _Analyst(model)._invoke_llm_with_timeout([HumanMessage(content="go")], 5.0)

        assert current_rule() is None


class TestTheEndedAnswerIsAskedOnce:
    def test_the_check_asks_its_whole_answer_question_of_the_ended_answer(self) -> None:
        asked: list[list[Any]] = []

        class _Asked(_Analyst):
            def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
                asked.append(list(messages))
                self._record_usage(AIMessage(content=DISTINCT))
                return DISTINCT

        analyst = _Asked(MagicMock())
        isr = analyst._text_to_isr(ENDED, 0)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            kept = analyst._validate_isr(isr, "evidence")

        (turns,) = asked
        assert ANALYST_REPEATED_CODE in str(turns[-1].content)
        shown = [t for t in turns if getattr(t, "type", "") == "ai"]
        # Shown back as written up to its first repeat: nothing before it removed.
        assert [str(t.content) for t in shown] == [DISTINCT.rstrip()]
        assert len(kept.claims) == 3
