"""A job's three kinds of call reach Claude Haiku 5.5 as the API takes them.

Through the real provider class and the real ``ChatAnthropic``, with HTTP
answered by a stand-in (``anthropic_wire``): one analyst tool loop with two
tool calls, run by the analysts' own loop; one judge call; one report-composer
section through structured output. Every body is read as the SDK sent it.

What the Anthropic documentation says these requests must be, and what is
asserted of each body:

* no ``temperature``, ``top_p`` or ``top_k`` (a non-default value is a 400 on
  Claude Haiku 5.5: the model page's "Good to know");
* the configured effort as ``output_config.effort``, and no ``thinking``
  field, so no ``budget_tokens``;
* the top-level automatic ``cache_control``;
* streamed when the output cap is past what the SDK sends unstreamed;
* every ``thinking`` block replayed exactly as it was received, and every
  request of the loop the one before it plus its new turns (preserved
  thinking: an edited prefix is a 400);
* every ``tool_use`` answered by a ``tool_result`` in the next user turn, and
  no request ending on an assistant turn (a prefill);
* no forced ``tool_choice``.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.core.config import Settings
from maljan.core.token_ledger import turn_usage
from maljan.llm import anthropic_history
from maljan.llm.anthropic_provider import AnthropicProvider

from .anthropic_wire import MODEL, Wire, install, message

REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
USAGE = {
    "input_tokens": 40,
    "output_tokens": 30,
    "cache_creation_input_tokens": 1200,
    "cache_read_input_tokens": 3000,
}


def _thinking(turn: int) -> dict[str, Any]:
    # ``display`` defaults to ``omitted`` on Claude Haiku 5.5: the text is
    # empty and the signature carries the reasoning.
    return {"type": "thinking", "thinking": "", "signature": f"EoBsig{turn}/+=" * 8}


def _analyst_answer(body: dict[str, Any]) -> dict[str, Any]:
    done = sum(
        1
        for m in body["messages"]
        if m["role"] == "user" and isinstance(m["content"], list)
        for b in m["content"]
        if b.get("type") == "tool_result"
    )
    if done < 2:
        return message(
            [
                _thinking(done),
                {
                    "type": "tool_use",
                    "id": f"toolu_{done}",
                    "name": "lookup",
                    "input": {"what": f"w{done}"},
                },
            ],
            stop="tool_use",
            usage=USAGE,
        )
    return message(
        [_thinking(done), {"type": "text", "text": REPORT}], stop="end_turn", usage=USAGE
    )


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _settings(**anthropic: Any) -> Settings:
    return Settings(
        _env_file=None,
        llm={
            "provider": "anthropic",
            "anthropic": {
                "api_key": "test-anthropic-key",
                "expert_model": MODEL,
                "judge_model": MODEL,
                **anthropic,
            },
        },
    )


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    anthropic_history.forget()
    yield
    anthropic_history.forget()


def _no_sampling(body: dict[str, Any]) -> None:
    for key in ("temperature", "top_p", "top_k"):
        assert key not in body, key
    assert "thinking" not in body


def _every_call_answered(body: dict[str, Any]) -> None:
    messages = body["messages"]
    assert messages[-1]["role"] == "user"
    for index, turn in enumerate(messages):
        if turn["role"] != "assistant" or not isinstance(turn["content"], list):
            continue
        calls = [b["id"] for b in turn["content"] if b.get("type") == "tool_use"]
        if not calls:
            continue
        following = messages[index + 1]
        answered = [
            b["tool_use_id"] for b in following["content"] if b.get("type") == "tool_result"
        ]
        assert answered[: len(calls)] == calls


class TestTheAnalystsLoop:
    def _run(self, monkeypatch: pytest.MonkeyPatch, **anthropic: Any) -> Wire:
        wire = Wire(_analyst_answer)
        install(monkeypatch, wire)
        llm = AnthropicProvider(_settings(**anthropic)).build_model(MODEL, 0.1, max_tokens=128000)
        agent = _Analyst(llm)
        agent.run_state_block = "sample: c"
        agent.tools = [_lookup()]
        self.answer = agent.execute_tool_loop(
            [("system", "You are a static analyst."), ("human", "Analyse.")]
        )
        return wire

    def test_three_requests_as_the_api_takes_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wire = self._run(monkeypatch, effort="max")
        assert len(wire.bodies) == 3
        assert set(wire.paths) == {"/v1/messages"}
        for body in wire.bodies:
            _no_sampling(body)
            assert body["model"] == MODEL
            assert body["output_config"] == {"effort": "max"}
            assert body["cache_control"] == {"type": "ephemeral"}
            assert body["stream"] is True
            assert body["max_tokens"] == 128000
            assert "tool_choice" not in body
            _every_call_answered(body)

    def test_each_request_is_the_one_before_it_plus_its_new_turns(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire = self._run(monkeypatch)
        for earlier, later in zip(wire.bodies, wire.bodies[1:], strict=False):
            assert later["system"] == earlier["system"]
            assert later["tools"] == earlier["tools"]
            assert later["messages"][: len(earlier["messages"])] == earlier["messages"]

    def test_the_thinking_blocks_go_back_exactly_as_they_came(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire = self._run(monkeypatch)
        last = wire.bodies[-1]["messages"]
        sent = [
            block
            for m in last
            if m["role"] == "assistant"
            for block in m["content"]
            if block.get("type") == "thinking"
        ]
        assert sent == [_thinking(0), _thinking(1)]

    def test_the_answer_is_read_as_its_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The thinking block stays on the turn and out of the answer the analyst reads."""
        wire = self._run(monkeypatch)
        assert wire.refused == []
        assert "CLAIM: it reads a file" in self.answer
        assert "signature" not in self.answer

    def test_an_unset_effort_sends_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wire = self._run(monkeypatch)
        assert all("output_config" not in body for body in wire.bodies)


class TestTheJudgeAndTheComposer:
    def test_the_judge_s_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.llm.registry import LLMProviderRegistry

        wire = Wire(
            lambda _body: message([{"type": "text", "text": "{}"}], stop="end_turn", usage=USAGE)
        )
        install(monkeypatch, wire)
        judge = LLMProviderRegistry(_settings(effort="high")).build_model(
            role="judge", max_tokens=8192
        )
        answer = judge.invoke([SystemMessage(content="You judge."), HumanMessage(content="Rule.")])
        body = wire.bodies[0]
        _no_sampling(body)
        assert body["output_config"] == {"effort": "high"}
        assert body["cache_control"] == {"type": "ephemeral"}
        assert "stream" not in body
        assert answer.content == "{}"
        usage = turn_usage(answer)
        assert usage is not None
        assert usage["cached_input_tokens"] == 3000
        assert usage["cache_write_input_tokens"] == 1200
        assert usage["input_tokens"] == 40 + 1200 + 3000

    def test_a_composer_section_asks_for_its_schema_without_forcing_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Section(BaseModel):
            summary: str

        wire = Wire(
            lambda _body: message(
                [
                    _thinking(9),
                    {
                        "type": "tool_use",
                        "id": "toolu_s",
                        "name": "Section",
                        "input": {"summary": "s"},
                    },
                ],
                stop="tool_use",
                usage=USAGE,
            )
        )
        install(monkeypatch, wire)
        llm = AnthropicProvider(_settings(prompt_cache_ttl="1h")).build_model(
            MODEL, 0.1, max_tokens=64000
        )
        result = llm.with_structured_output(Section, include_raw=True).invoke(
            [SystemMessage(content="Write the section."), HumanMessage(content="Facts.")]
        )
        body = wire.bodies[0]
        _no_sampling(body)
        assert body["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
        assert body["stream"] is True
        assert [tool["name"] for tool in body["tools"]] == ["Section"]
        assert body.get("tool_choice", {"type": "auto"})["type"] == "auto"
        assert result["parsed"] == Section(summary="s")
