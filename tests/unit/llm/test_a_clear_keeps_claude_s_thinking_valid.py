"""A loop on Claude that is refused as over its window clears, resends and salvages, all valid.

Claude Haiku 5.5's thinking blocks are bound to everything before them. A clear
of old tool answers (``agents.tool_answer_clearing``) changes that history and
the tool list, so the provider asks the API to drop the blocks it made stale
(``anthropic_history``). Driven here on the real provider model against the
stand-in API (``anthropic_wire.Wire``), which refuses what the API refuses:
the only refusal is the planned one for the prompt's length, every request
after the clear is accepted, and so is the salvage after the loop, with the
read-again tool in its tool list as in the loop's last request.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL

from .anthropic_wire import Wire, install, message
from .test_a_replayed_thinking_block_stays_valid import _model

LIMIT = 30_000
USAGE = {"input_tokens": 10, "output_tokens": 5}


class _LengthWire(Wire):
    """The stand-in, refusing a request longer than ``LIMIT`` characters as the API words it."""

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else {}
        size = len(json.dumps(body.get("messages") or []))
        if size > LIMIT:
            self.bodies.append(body)
            refused = f"prompt is too long: {size} tokens > {LIMIT} maximum"
            self.refused.append(refused)
            return httpx2.Response(
                400,
                json={
                    "type": "error",
                    "error": {"type": "invalid_request_error", "message": refused},
                },
            )
        return super().__call__(request)


def _results(body: dict[str, Any]) -> int:
    return sum(
        1
        for m in body["messages"]
        if m["role"] == "user" and isinstance(m["content"], list)
        for b in m["content"]
        if b.get("type") == "tool_result"
    )


def _answer(body: dict[str, Any]) -> dict[str, Any]:
    done = _results(body)
    thinking = {
        "type": "thinking",
        "thinking": "",
        "signature": f"sig-{len(body['messages'])}-" + "A" * 40,
    }
    if body.get("tools") and (body.get("tool_choice") or {}).get("type") != "none":
        call = {
            "type": "tool_use",
            "id": f"toolu_{done}",
            "name": "lookup",
            "input": {"what": str(done)},
        }
        return message([thinking, call], stop="tool_use", usage=USAGE)
    text = {"type": "text", "text": "CLAIM: it reads a file\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\n"}
    return message([thinking, text], stop="end_turn", usage=USAGE)


class _What(BaseModel):
    what: str = ""


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def test_a_refusal_clears_resends_and_the_salvage_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents import base_agent

    wire = _LengthWire(_answer)
    install(monkeypatch, wire)
    # Steps run out while tools are still called: the salvage writes the answer.
    monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 16))
    agent = _Analyst(llm=_model(), name="static")
    agent.run_state_block = "sample: c"
    agent.tools = [
        StructuredTool.from_function(
            func=lambda what="": f"answer {what} " + "a" * 4_000,
            name="lookup",
            description="Look it up.",
            args_schema=_What,
        )
    ]
    answer = agent.execute_tool_loop(
        [("system", "You are a static analyst."), ("human", "Analyse.")]
    )
    length = [r for r in wire.refused if r.startswith("prompt is too long")]
    assert length, "the loop must have reached the planned refusal"
    assert [r for r in wire.refused if not r.startswith("prompt is too long")] == []
    accepted = [b for b in wire.bodies if len(json.dumps(b.get("messages") or [])) <= LIMIT]
    cleared = [b for b in accepted if "[cleared ev_" in json.dumps(b.get("messages") or [])]
    assert cleared, "a request after the refusal carries the cleared answers"
    # The salvage: tools withheld, the read-again tool bound as the loop last bound it.
    salvage = accepted[-1]
    assert (salvage.get("tool_choice") or {}).get("type") == "none"
    assert READ_EVIDENCE_TOOL in [t.get("name") for t in salvage.get("tools") or []]
    assert answer.strip().startswith("CLAIM:")
