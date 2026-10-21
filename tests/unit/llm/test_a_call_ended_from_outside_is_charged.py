"""A model call ended from outside is charged as its provider bills it.

A call cancelled from outside — a fallback list's turn deadline, the spend
cap, the operator's cancel — raises ``CancelledError``, which is not an
``Exception``: the charge for a failed attempt used to be skipped for it, so
the pieces that call had streamed were billed by the provider and never
counted against the spend ceiling. A blocking call a fallback list gives up
on cannot be cancelled at all: it runs to its end in the thread left behind,
and its answer, billed in full, was dropped without a charge.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from maljan.core.token_ledger import TokenLedger
from maljan.llm.fallback import FallbackChatModel
from maljan.llm.generation_rate import note_pieces
from maljan.llm.transient import (
    ABANDONED_ANSWER_ESTIMATE,
    FAILED_ATTEMPT_CALL,
    attach_retry_recorder,
    with_transient_retries,
)

USAGE = {"input_tokens": 40, "output_tokens": 6, "total_tokens": 46}


class _Spend:
    def __init__(self) -> None:
        self.settled: list[tuple[Any, str, str, Any]] = []

    def settle(self, usage: Any, model: str, call: str = "", *, estimated: Any = None) -> None:
        self.settled.append((usage, model, call, estimated))

    def failed_attempts(self) -> list[tuple[Any, str, str, Any]]:
        return [row for row in self.settled if row[2] == FAILED_ATTEMPT_CALL]


class _Hanging(BaseChatModel):
    """Streams nine pieces, then waits until it is cancelled."""

    model_name: str = "hanging"

    @property
    def _llm_type(self) -> str:
        return "hanging"

    def _generate(self, *_a: Any, **_k: Any) -> ChatResult:  # pragma: no cover - async only
        raise NotImplementedError

    async def _agenerate(self, *_a: Any, **_k: Any) -> ChatResult:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as exc:
            # What the generation-rate wrapper puts on the error it sees.
            note_pieces(exc, 9)
            raise
        raise AssertionError("unreachable")  # pragma: no cover


class _Blocking(BaseChatModel):
    """Answers, with usage, once ``release`` is set; ``finished`` once it has answered."""

    model_name: str = "blocking"
    release: Any = None
    finished: Any = None
    usage: dict[str, int] | None = None

    @property
    def _llm_type(self) -> str:
        return "blocking"

    def _generate(self, *_a: Any, **_k: Any) -> ChatResult:
        self.release.wait(5)
        answer = AIMessage(content="late answer " * 20, usage_metadata=self.usage)
        return ChatResult(generations=[ChatGeneration(message=answer)])


class _Quick(BaseChatModel):
    model_name: str = "quick"

    @property
    def _llm_type(self) -> str:
        return "quick"

    def _generate(self, *_a: Any, **_k: Any) -> ChatResult:
        answer = AIMessage(content="from the second", usage_metadata=dict(USAGE))
        return ChatResult(generations=[ChatGeneration(message=answer)])


@pytest.mark.asyncio
async def test_a_call_cancelled_after_pieces_streamed_is_charged() -> None:
    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    llm = attach_retry_recorder(with_transient_retries(_Hanging)(), ledger, "static")

    task = asyncio.create_task(llm.ainvoke("x" * 400))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    ((usage, model, _call, estimated),) = spend.failed_attempts()
    assert usage is None
    assert model == "hanging"
    assert estimated["output_tokens"] == 9
    assert estimated["input_tokens"] > 0


def _stalled_list(usage: dict[str, int] | None) -> tuple[Any, Any, Any, _Spend]:
    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    release, finished = threading.Event(), threading.Event()
    first = with_transient_retries(_Blocking)(release=release, finished=finished, usage=usage)
    second = with_transient_retries(_Quick)()
    models = FallbackChatModel(
        models=[first, second], labels=["a/blocking", "b/quick"], agent="x", turn_deadline=0.05
    )
    attach_retry_recorder(models, ledger, "static")
    return models, release, first, spend


def _wait_for_charge(spend: _Spend) -> None:
    for _ in range(200):
        if spend.failed_attempts():
            return
        threading.Event().wait(0.01)


def test_an_abandoned_blocking_answer_is_charged_its_reported_usage() -> None:
    models, release, _first, spend = _stalled_list(dict(USAGE))

    answer = models.invoke("hi")
    assert answer.content == "from the second"
    assert spend.failed_attempts() == [], "nothing is charged while the request still runs"

    release.set()
    _wait_for_charge(spend)
    ((usage, model, _call, estimated),) = spend.failed_attempts()
    assert usage["input_tokens"] == 40 and usage["output_tokens"] == 6
    assert model == "blocking"
    assert estimated is None


def test_an_abandoned_answer_without_usage_is_charged_a_stated_estimate() -> None:
    models, release, _first, spend = _stalled_list(None)

    models.invoke("y" * 300)
    release.set()
    _wait_for_charge(spend)

    ((usage, _model, _call, estimated),) = spend.failed_attempts()
    assert usage is None
    assert estimated["source"] == ABANDONED_ANSWER_ESTIMATE
    assert estimated["input_tokens"] > 0 and estimated["output_tokens"] > 0


def test_an_answer_within_the_deadline_is_not_charged_as_abandoned() -> None:
    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    release = threading.Event()
    release.set()
    first = with_transient_retries(_Blocking)(
        release=release, finished=threading.Event(), usage=dict(USAGE)
    )
    second = with_transient_retries(_Quick)()
    models = FallbackChatModel(
        models=[first, second], labels=["a/blocking", "b/quick"], agent="x", turn_deadline=5.0
    )
    attach_retry_recorder(models, ledger, "static")

    assert models.invoke("hi").content.startswith("late answer")
    assert spend.failed_attempts() == []


def test_a_charge_landing_after_the_summary_is_sealed_is_marked_and_kept() -> None:
    from maljan.core.token_ledger import LANDED_AFTER_END

    ledger = TokenLedger(spend=_Spend())
    rows: list[dict[str, Any]] = []
    ledger.on_call = rows.append
    ledger.charge_failed_attempt(dict(USAGE), agent="x", model="m", call="c")
    assert LANDED_AFTER_END not in rows[0] and ledger.late_charges() == []
    before = ledger.snapshot()

    ledger.end()  # the summary's token block is taken; the container is not closed yet
    ledger.end()  # idempotent
    ledger.charge_failed_attempt(dict(USAGE), agent="x", model="m", call="c")

    assert rows[1][LANDED_AFTER_END] is True
    assert ledger.late_charges() == [rows[1]]
    assert ledger.snapshot() == before, "the sealed figures are never rewritten"


def test_a_call_added_after_the_seal_is_late_and_in_no_total() -> None:
    from maljan.core.token_ledger import LANDED_AFTER_END

    spend = _Spend()
    ledger = TokenLedger(spend=spend)
    rows: list[dict[str, Any]] = []
    ledger.on_call = rows.append
    ledger.add(dict(USAGE), agent="x", model="m", call="c")
    before = (ledger.snapshot(), ledger.calls, ledger.total_tokens, ledger.by_call())

    ledger.end()
    ledger.add(dict(USAGE), agent="x", model="m", call="c", fallback="f", retries=["r"])

    assert (ledger.snapshot(), ledger.calls, ledger.total_tokens, ledger.by_call()) == before
    assert rows[1][LANDED_AFTER_END] is True and ledger.late_charges() == [rows[1]]
    assert len(spend.settled) == 2, "a late answer is still billed on the spend meter"


def test_closing_the_container_ends_the_ledger() -> None:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer
    from maljan.core.token_ledger import LANDED_AFTER_END

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    ledger = container.get_token_ledger()
    rows: list[dict[str, Any]] = []
    ledger.on_call = rows.append
    ledger.charge_failed_attempt(dict(USAGE), agent="x", model="m", call="c")
    assert LANDED_AFTER_END not in rows[0]

    asyncio.run(container.aclose())
    ledger.charge_failed_attempt(dict(USAGE), agent="x", model="m", call="c")

    assert rows[1][LANDED_AFTER_END] is True
