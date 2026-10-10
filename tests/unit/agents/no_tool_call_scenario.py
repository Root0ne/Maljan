"""One analyst loop over a learned window whose first answer calls no tool, as the wire sees it.

The model answers in prose first, so the loop asks it the no-tool-call
question; it then calls ``lookup`` twice and writes its report. Every request
is returned as the provider receives it (OpenAI chat messages) with the names
of the tools it offered. Written against nothing but what ``origin/dev``
already has, so the same function produces the golden on dev
(``tests/fixtures/clearing/no_tool_call_requests_dev.json``) and the run it is
compared with on a branch:

    PYTHONPATH=<dev export>/src:<repo> python -c \
        "import json; from tests.unit.agents.no_tool_call_scenario import requests; \
         print(json.dumps(requests(), indent=1))"
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, convert_to_openai_messages
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.llm import context_window as cw

PROSE = "The file looks like a loader; it reads its configuration from a resource."
REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"


class _FirstProse(BaseChatModel):
    """Prose first; after the question, two ``lookup`` calls; then the report."""

    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        sent = list(messages)
        tools = [t["function"]["name"] for t in kwargs.get("tools") or []]
        self.seen.append((sent, tools))
        asked = sum(1 for m in sent if isinstance(m, HumanMessage)) > 1
        made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
        if not asked:
            turn = AIMessage(content=PROSE)
        elif made < 2:
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "lookup", "args": {"what": f"w{made}"}, "id": f"c{made}"}],
            )
        else:
            turn = AIMessage(content=REPORT)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "first-prose"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self.bind(tools=[convert_to_openai_tool(t) for t in tools])


class _What(BaseModel):
    what: str = ""


class _Container:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None
        self.budget = cw.ContextBudget(cw.WindowFact(200_000, cw.DECLARED, "scenario"))

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


@contextlib.contextmanager
def _settings() -> Iterator[None]:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = None
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = None
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 100
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def requests() -> list[dict[str, Any]]:
    """Each request of the loop: its messages as sent and the tools it offered."""
    model = _FirstProse(seen=[])
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.no_tool_call_scenario")
    agent.run_state_block = "sample: c"
    agent._container = _Container()
    agent.tools = [
        StructuredTool.from_function(
            func=lambda what="": f"answer for {what} " + "a" * 400,
            name="lookup",
            description="Look it up.",
            args_schema=_What,
        )
    ]
    with _settings():
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
    return [
        {
            "messages": [
                json.loads(json.dumps(m, sort_keys=True, default=str))
                for m in convert_to_openai_messages(sent)
            ],
            "tools": tools,
        }
        for sent, tools in model.seen
    ]
