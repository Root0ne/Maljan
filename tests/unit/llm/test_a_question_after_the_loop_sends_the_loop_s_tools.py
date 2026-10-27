"""On Claude, a question asked after a loop sends the loop's own tool definitions, byte for byte.

A validation retry, the drops question and the whole-answer question now run
the analyst's tool loop over their own conversation. Their requests carry
the ``tools`` the loop's requests carried, the same bytes in the same order,
beside the same system prompt, so the provider reads one tool list for the
whole analysis. What the earlier change kept stays: the retry's first turn
is sent as one listed block with a breakpoint, every thinking block a
request sends back is valid against the stand-in API's checks, and a call
the model makes in the retry is answered in the same conversation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import ANALYST_TOOLS_ATTACHED, Violation
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

from .anthropic_wire import Wire, install, message
from .test_a_replayed_thinking_block_stays_valid import (
    REPORT,
    USAGE,
    _calls_allowed,
    _lookup,
    _model,
    _results,
    _thinking,
)

SYSTEM = "You are a static analyst."
TOLD = [Violation(code="isr.ungrounded_technique", message="cite the entry that holds it")]


def _is_retry(body: dict[str, Any]) -> bool:
    return ANALYST_TOOLS_ATTACHED in json.dumps(body["messages"], ensure_ascii=False)


def _answer(body: dict[str, Any]) -> dict[str, Any]:
    """The loop calls once then reports; the retry calls once more then fixes its claim."""
    done = _results(body)
    wanted = 2 if _is_retry(body) else 1
    if _calls_allowed(body) and done < wanted:
        call = {"type": "tool_use", "id": f"toolu_{done}", "name": "lookup", "input": {"what": "x"}}
        return message([_thinking(done), call], stop="tool_use", usage=USAGE)
    text = {"type": "text", "text": REPORT}
    return message([_thinking(100 + len(body["messages"])), text], stop="end_turn", usage=USAGE)


class _Analyst(BaseAnalyst):
    def _system_prompt(self, fallback: Any, tools: Any = None) -> str:
        # As a container's composition does: one prompt for the loop's tools.
        return SYSTEM if tools is None else f"{SYSTEM} No tools are attached."

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> tuple[Wire, list[dict[str, Any]]]:
    from maljan.agents import base_agent

    wire = Wire(_answer)
    install(monkeypatch, wire)
    monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 20))
    agent = _Analyst(llm=_model(), name="static")
    agent.run_state_block = "sample: c"
    agent.tools = [_lookup()]
    agent.execute_tool_loop([("system", SYSTEM), ("human", "Analyse.")])
    loop = list(wire.bodies)
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="c", evidence_ref="x", confidence=0.5, technique_id="T1005")],
    )
    answers = iter([TOLD, TOLD, []])
    with patch("maljan.pipeline.validation.validate_isr", lambda *_a, **_k: next(answers, [])):
        agent._validate_isr(isr, "the raw data")
    return wire, loop


class TestTheRetrySendsTheLoopsTools:
    def test_its_tools_and_system_prompt_are_the_loop_s_byte_for_byte(self, sent: Any) -> None:
        wire, loop = sent
        retry = [body for body in wire.bodies if _is_retry(body)]
        assert len(retry) == 3
        for body in retry:
            assert json.dumps(body["tools"]) == json.dumps(loop[0]["tools"])
            assert body["system"] == loop[0]["system"]

    def test_every_request_passes_the_api_s_checks(self, sent: Any) -> None:
        wire, _loop = sent
        assert wire.refused == []

    def test_the_retry_s_first_turn_is_listed_with_a_breakpoint(self, sent: Any) -> None:
        wire, _loop = sent
        first = next(body for body in wire.bodies if _is_retry(body))
        evidence = first["messages"][0]["content"]
        assert isinstance(evidence, list) and len(evidence) == 1
        assert evidence[0].get("cache_control")

    def test_the_call_it_made_is_answered_in_its_own_conversation(self, sent: Any) -> None:
        wire, _loop = sent
        last = [body for body in wire.bodies if _is_retry(body)][-1]
        assert _results(last) == 2
        assert last["messages"][-1]["role"] == "user"
