"""A cleared tool answer leaves every earlier turn's DeepSeek reasoning on its turn.

DeepSeek refuses a request with tools that drops an earlier assistant turn's
``reasoning_content`` (its thinking-mode guide), so a loop that clears old tool
answers (``agents.tool_answer_clearing``) clears the tool turns only: every
request after a clear still carries every earlier turn's reasoning, byte for
byte, and the read-again tool rides the request's tools from that clear on.

Through the real provider model and the analyst's real loop, over a stand-in
transport: the bodies read are the bodies the SDK would have sent.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

from langchain_core.tools import StructuredTool

from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.llm import context_window as cw

from . import test_deepseek_reasoning_is_sent_back as sent_back
from .test_deepseek_reasoning_is_sent_back import THOUGHT, _Analyst, _DeepSeek, _model, _What


def _counted(request: Any, payload: dict[str, Any]) -> Any:
    """The stand-in's answer, its usage counting the request as a server would (3 chars a token)."""
    payload["usage"]["prompt_tokens"] = len(request.content) // 3
    return _reply(request, payload)


_reply = sent_back.reply


class _Container:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None
        self.budget = cw.ContextBudget(cw.WindowFact(1_000_000, cw.DECLARED, "test"))

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


def test_every_request_after_a_clear_carries_every_reasoning() -> None:
    wire = _DeepSeek(calls=8)
    agent = _Analyst(_model(wire))
    agent.logger = logging.getLogger("test.deepseek_clear")
    agent.run_state_block = "sample: c"
    agent._container = _Container()
    agent.tools = [
        StructuredTool.from_function(
            func=lambda what="": f"answer for {what} " + "a" * 6_000,
            name="lookup",
            description="Look it up.",
            args_schema=_What,
        )
    ]
    with (
        patch.object(sent_back, "reply", _counted),
        patch("maljan.agents.base_agent.get_settings") as settings,
    ):
        cfg = settings.return_value
        cfg.react_agent_timeout = None
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = None
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 100
        cfg.react_agent_clear_tool_answers_at = 6_000
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
    assert len(wire.bodies) == 9
    cleared_from = None
    for index, body in enumerate(wire.bodies):
        tools = [t["function"]["name"] for t in body.get("tools") or []]
        tool_turns = [m for m in body["messages"] if m["role"] == "tool"]
        cleared = [m for m in tool_turns if str(m["content"]).startswith("[cleared ")]
        if cleared and cleared_from is None:
            cleared_from = index
        assert (READ_EVIDENCE_TOOL in tools) == (cleared_from is not None)
        thoughts = [
            m.get("reasoning_content") for m in body["messages"] if m["role"] == "assistant"
        ]
        assert thoughts == [f"{THOUGHT} ({n})" for n in range(len(thoughts))]
    assert cleared_from is not None
