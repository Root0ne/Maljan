"""Through the real tool loop: the map rides the run-state block, the ledger answers.

The analyst sees its function map on every turn, beside the run-state lines it
already read; a decompile of a function it already read is answered from the
entry that holds the listing; the loop's record counts what was answered so;
and what one loop read is on the map of the next loop of the same job, not of
the next job.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.function_map import FUNCTION_MAP_HEAD, function_artefacts
from maljan.schemas.evidence import LedgerEntry

LISTING = "void FUN_1360bc0904c(void)\n{\n  lookup(0x1);\n}\n"
REPORT = (
    "CLAIM: FUN_1360bc0904c looks a name up by a stored value.\n"
    "EVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
)


class _Args(BaseModel):
    address: str | None = None
    program: str | None = None


def _decompiler(calls: list[dict[str, Any]]) -> StructuredTool:
    def _run(**kwargs: Any) -> str:
        calls.append(kwargs)
        return LISTING

    return StructuredTool.from_function(
        func=_run,
        name="decompile_function",
        description="Decompile one function.",
        args_schema=_Args,
        infer_schema=False,
        metadata={"maljan_server": "ghidra"},
    )


class _Model(BaseChatModel):
    """Asks for the given addresses one turn each, then answers."""

    seen: list = []
    asks: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        made = sum(1 for m in sent if isinstance(m, ToolMessage))
        if made < len(self.asks):
            turn = AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "decompile_function",
                        "args": {"address": self.asks[made]},
                        "id": f"c{made}",
                    }
                ],
            )
        else:
            turn = AIMessage(content=REPORT)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:
        return self.execute_tool_loop([("system", "s"), ("human", data)])

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


@pytest.fixture(autouse=True)
def _no_suggestions(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.tools import knowledge

    monkeypatch.setattr(knowledge, "resolve_technique", lambda *a, **k: {"candidates": []})


def _analyst(asks: list[str], calls: list[dict[str, Any]]) -> tuple[_Analyst, _Model]:
    model = _Model()
    model.seen = []
    model.asks = asks
    analyst = _Analyst(llm=model, name="reverser")
    analyst.logger = logging.getLogger("test.function_map")
    analyst.tools = [_decompiler(calls)]
    analyst.run_state_block = "sample: test"
    analyst._job_id = "job-1"
    return analyst, model


def _run(analyst: _Analyst) -> None:
    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
        analyst.safe_analyze_isr("the task")


def test_a_second_spelling_is_answered_from_the_ledger_and_the_map_is_shown() -> None:
    calls: list[dict[str, Any]] = []
    analyst, model = _analyst(["0x1360bc0904c", "1360bc0904c"], calls)

    _run(analyst)

    assert len(calls) == 1
    last = [str(m.content) for m in model.seen[2] if isinstance(m, ToolMessage)][-1]
    assert last.startswith(f"[ev_0001]\n{LISTING}")
    assert "was already decompiled in [ev_0001]" in last
    assert FUNCTION_MAP_HEAD in last
    assert "- 0x1360bc0904c (FUN_1360bc0904c): decompiled in ev_0001" in last
    records = analyst.drain_budget_records()
    assert records[0]["ledger_answers"] == {"decompile": 1}


def test_a_loop_that_answered_nothing_from_the_ledger_records_nothing_of_it() -> None:
    calls: list[dict[str, Any]] = []
    analyst, _model = _analyst(["0x1360bc0904c"], calls)

    _run(analyst)

    assert "ledger_answers" not in analyst.drain_budget_records()[0]


def test_the_next_loop_of_the_job_reads_the_map_and_the_claims_of_the_last() -> None:
    calls: list[dict[str, Any]] = []
    analyst, model = _analyst(["0x1360bc0904c"], calls)
    _run(analyst)
    model.seen = []
    model.asks = ["1360bc0904c"]

    _run(analyst)

    assert len(calls) == 1, "the earlier loop's listing answers the second loop's call"
    first = str(model.seen[0][-1].content)
    assert FUNCTION_MAP_HEAD in first
    assert "summary: FUN_1360bc0904c looks a name up by a stored value." in first


def test_a_new_job_starts_with_an_empty_map() -> None:
    calls: list[dict[str, Any]] = []
    analyst, model = _analyst(["0x1360bc0904c"], calls)
    _run(analyst)
    analyst._job_id = "job-2"
    model.seen = []
    model.asks = ["1360bc0904c"]

    _run(analyst)

    assert len(calls) == 2
    assert FUNCTION_MAP_HEAD not in str(model.seen[0][-1].content)


def test_the_pack_s_artefacts_join_the_function_the_analyst_read() -> None:
    hashes = LedgerEntry(
        id="ev_0000",
        tool="resolve_api_hashes",
        server="pipeline",
        output=json.dumps(
            {
                "image_base": "0x1360bc00000",
                "hits": [
                    {
                        "readings": [{"set": "exports", "name": "OpenThing"}],
                        "occurrences": [{"rva": "0x9057", "function": "0x904c"}],
                    }
                ],
            }
        ),
    )
    calls: list[dict[str, Any]] = []
    analyst, model = _analyst(["0x1360bc0904c"], calls)
    analyst.pack_function_artefacts = function_artefacts([hashes])

    _run(analyst)

    after = [str(m.content) for m in model.seen[1] if isinstance(m, ToolMessage)][-1]
    assert "reaches 1 resolved name (ev_0000)" in after


def test_an_agent_with_no_run_state_block_is_sent_no_map() -> None:
    calls: list[dict[str, Any]] = []
    analyst, model = _analyst(["0x1360bc0904c"], calls)
    analyst.run_state_block = ""

    _run(analyst)

    assert all(FUNCTION_MAP_HEAD not in str(m.content) for sent in model.seen for m in sent)


def test_the_node_briefs_the_artefacts_and_an_ask_hands_them_on() -> None:
    from maljan.agents.delegation import _brief_callee
    from maljan.pipeline import nodes

    hashes = {
        "id": "ev_0000",
        "agent": "pipeline",
        "tool": "resolve_api_hashes",
        "server": "pipeline",
        "output": json.dumps(
            {
                "hits": [
                    {
                        "readings": [{"set": "exports", "name": "OpenThing"}],
                        "occurrences": [{"function": "0x904c"}],
                    }
                ]
            }
        ),
    }
    calls: list[dict[str, Any]] = []
    caller, _ = _analyst([], calls)
    callee, _ = _analyst([], calls)
    with patch.object(nodes, "pack_text", return_value=""):
        nodes.brief_agent(caller, {"evidence_ledger": [hashes]}, object())  # type: ignore[arg-type]

    _brief_callee(caller, callee, stage="reversing", round_index=0)

    assert 0x904C in caller.pack_function_artefacts.by_function
    assert callee.pack_function_artefacts is caller.pack_function_artefacts
