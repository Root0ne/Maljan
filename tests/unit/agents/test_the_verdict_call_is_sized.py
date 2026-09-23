"""The verdict call runs on its own sized clock, and says when its cap ended it.

The judge's verdict call is sized from the model's measured pace (a slow model
is given the time ``judge_max_tokens`` takes), but a model list's turn deadline
is a share of the clock the list was last started on — mediation's. Left there,
the primary was declared stalled long before the sized wait. And a verdict the
token cap cut reads as malformed JSON unless the cut is counted.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm.generation_rate import TIMEOUT_CEILING_SECONDS, GenerationRates, model_name_of

BUNDLE = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332200",
        "objects": [
            {
                "type": "malware",
                "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                "name": "sample",
                "is_family": False,
            }
        ],
        "x_maljan_assessment": {
            "verdict": "Malware",
            "severity": {"rating": "High", "rationale": "it does harm"},
            "malware_category": "loader",
        },
    }
)


class _Llm:
    """Answers every verdict call with the bundle, stopped by its length cap."""

    model_name = "slow-model"

    async def ainvoke(self, _messages: list[Any]) -> Any:
        return AIMessage(content=BUNDLE, response_metadata={"done_reason": "length"})


def _verdict(judge: JudgeAgent) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def _restart(model: Any, **kwargs: Any) -> None:
        seen.append(kwargs)

    with patch("maljan.llm.fallback.restart_models", _restart):
        asyncio.run(judge.give_verdict(reports={"static": "It loads a payload."}, history=[]))
    return seen


def test_the_model_list_starts_on_the_sized_verdict_clock() -> None:
    llm = _Llm()
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    rates = GenerationRates()
    rates.observe(model_name_of(llm), 380, 100.0, "ollama eval_count/eval_duration")
    judge.generation_rates = rates

    restarts = _verdict(judge)

    assert restarts, "the list was started for the verdict call"
    applied = rates.snapshot()["timeouts"]["judge:verdict"]["applied_s"]
    assert applied == TIMEOUT_CEILING_SECONDS
    assert restarts[-1]["loop_seconds"] == applied


def test_a_verdict_its_cap_cut_is_counted() -> None:
    judge = JudgeAgent(llm=_Llm())  # type: ignore[arg-type]
    ledger = TruncationLedger()
    judge.truncation_ledger = ledger

    _verdict(judge)

    snap = ledger.snapshot()
    assert snap["judge_invocations"] >= 1
    assert snap["judge_token_cap_hits"] >= 1, "Ollama's done_reason length is a cut"
