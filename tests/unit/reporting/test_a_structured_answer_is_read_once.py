"""Every structured answer is read once: recorded, announced, and read through its schema.

The one shared reader (``core.token_ledger.read_structured_reply``) is where a
structured answer is first seen. Its usage goes on the ledger there, and a
model list's switch carried on it is announced there, once, whatever becomes
of the answer: a kept answer is the validation loop's first answer and is
never sent, so nothing after the reader sees it come back. A parser that hands
back a plain dict is read through the schema the request asked for: an object
that does not fit is kept as the loop's first answer, so the retry carries its
findings, rather than being thrown away and asked again from the start.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from pydantic import BaseModel

from maljan.core.token_ledger import TokenLedger, read_structured_reply
from maljan.llm.fallback import FALLBACK_KEY, MODEL_KEY
from maljan.pipeline.events import MODEL_FALLBACK
from maljan.pipeline.validation import FEEDBACK_PREAMBLE
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _answer,
    _isr,
    _report,
    _section_of,
)

FACTS = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable"
SWITCH = "anthropic/haiku: the provider timed out; answered by anthropic/sonnet"


def _raw(text: str, *, switched: bool = False) -> AIMessage:
    metadata = {MODEL_KEY: "anthropic/sonnet", FALLBACK_KEY: SWITCH} if switched else {}
    return AIMessage(
        content=text,
        response_metadata=metadata,
        usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    )


class _Structured:
    def __init__(self, llm: _Model, schema: type[BaseModel]) -> None:
        self.llm = llm
        self.schema = schema

    async def ainvoke(self, turns: list[BaseMessage], **_: Any) -> dict[str, Any]:
        self.llm.asked.append(("structured", list(turns)))
        raw, parsed = self.llm.answer(self.schema, list(turns))
        return {"raw": raw, "parsed": parsed, "parsing_error": None}


class _Model:
    """A provider whose structured requests answer ``answer(schema, turns)``: (raw, parsed)."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.asked: list[tuple[str, list[BaseMessage]]] = []

    def with_structured_output(self, schema: type[BaseModel], **_: Any) -> _Structured:
        return _Structured(self, schema)

    async def ainvoke(self, turns: list[BaseMessage], **_: Any) -> AIMessage:
        self.asked.append(("plain", list(turns)))
        return _raw(json.dumps(_answer(_section_of(turns))))


def _compose(answer: Any) -> tuple[_Model, ReportComposer, list[tuple[str, dict[str, Any]]]]:
    llm = _Model(answer)
    events: list[tuple[str, dict[str, Any]]] = []
    composer = ReportComposer(llm=llm, per_section_timeout=60, token_ledger=TokenLedger())  # type: ignore[arg-type]
    composer.event_sink = lambda kind, data: events.append((kind, data))
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=True):
        asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))
    return llm, composer, events


def _switches(events: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [data for kind, data in events if kind == MODEL_FALLBACK]


def _parsed(schema: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    """What a parser makes of ``payload``: the keys its schema declares."""
    return schema.model_validate({k: v for k, v in payload.items() if k in schema.model_fields})


class TestAModelSwitchOnAStructuredAnswer:
    def test_a_kept_answer_is_announced_once_and_recorded_once(self) -> None:
        def answer(schema: type[BaseModel], turns: list[BaseMessage]) -> tuple[Any, Any]:
            # The first answer of each section writes its object as text, the
            # answer the list moved on for; a retry is the next model's own.
            first = len(turns) == 2
            return _raw(json.dumps(_answer(_section_of(turns))), switched=first), None

        llm, composer, events = _compose(answer)
        asked = [kind for kind, _turns in llm.asked]
        assert asked.count("structured") == len(asked), "no section is asked again"
        firsts = sum(1 for _kind, turns in llm.asked if len(turns) == 2)
        assert firsts == len(COMPOSED_SECTIONS)
        switches = _switches(events)
        assert len(switches) == firsts, "one announcement per answer that carried the switch"
        assert all(s["agent"] == "reporter" and s["stage"] == "report" for s in switches)
        assert composer.token_ledger.calls == len(asked), "each answer recorded once"
        assert len(composer.token_ledger.snapshot()["fallbacks"]) == firsts

    def test_a_parsed_answer_is_announced(self) -> None:
        def answer(schema: type[BaseModel], turns: list[BaseMessage]) -> tuple[Any, Any]:
            payload = _answer(_section_of(turns))
            return _raw(json.dumps(payload), switched=True), _parsed(schema, payload)

        llm, composer, events = _compose(answer)
        assert len(llm.asked) == len(COMPOSED_SECTIONS)
        assert len(_switches(events)) == len(COMPOSED_SECTIONS)
        assert composer.token_ledger.calls == len(COMPOSED_SECTIONS)

    def test_the_narrative_round_announces_its_kept_answer_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import narrative_agent
        from tests.unit.reporting.test_narrative_agent import _make_report, _valid_narrative

        text = _valid_narrative().model_dump_json()

        def answer(schema: type[BaseModel], turns: list[BaseMessage]) -> tuple[Any, Any]:
            return _raw(text, switched=len(turns) == 2), None

        llm = _Model(answer)
        events: list[tuple[str, dict[str, Any]]] = []
        agent = narrative_agent.NarrativeAgent(llm=llm, token_ledger=TokenLedger())  # type: ignore[arg-type]
        agent.event_sink = lambda kind, data: events.append((kind, data))
        monkeypatch.setattr(narrative_agent, "structured_output_supported_for_llm", lambda _l: True)
        assert asyncio.run(agent.generate(_make_report())) is not None
        assert [kind for kind, _turns in llm.asked].count("plain") == 0
        assert len(_switches(events)) == 1
        assert agent.token_ledger.calls == len(llm.asked)

    def test_the_judge_announces_its_structured_answers(self) -> None:
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.runnables import RunnableLambda

        from maljan.agents.judge_agent import JudgeAgent
        from maljan.pipeline.mediation_models import MediatorVerdict

        verdict = MediatorVerdict(contradictions=[], resolution_summary="Agreed.", confidence=0.9)

        class _Judged:
            def with_structured_output(self, schema: Any, **_: Any) -> Any:
                raw = _raw(verdict.model_dump_json(), switched=True)
                return RunnableLambda(lambda _: {"raw": raw, "parsed": verdict})

        events: list[tuple[str, dict[str, Any]]] = []
        judge = JudgeAgent(llm=_Judged())  # type: ignore[arg-type]
        judge.token_ledger = TokenLedger()
        judge._event_sink = lambda: lambda kind, data: events.append((kind, data))  # type: ignore[method-assign]
        judge._supports_structured_output = lambda: True  # type: ignore[method-assign]
        prompt = ChatPromptTemplate.from_messages([("human", "Extract: {reasoning_log}")])
        got = asyncio.run(judge._extract_mediator_verdict(prompt, "All agree.", base_delay=0))
        assert got.resolution_summary == "Agreed."
        assert [(s["agent"], s["model"]) for s in _switches(events)] == [
            ("judge", "anthropic/sonnet")
        ]
        assert judge.token_ledger.calls == 1


class _Section(BaseModel):
    body: str
    evidence_refs: list[str] = []


class TestADictTheSchemaRefuses:
    def test_the_reader_reads_a_dict_through_the_schema(self) -> None:
        fits = read_structured_reply(
            {"raw": _raw('{"body": "x"}'), "parsed": {"body": "x"}}, None, schema=_Section
        )
        assert isinstance(fits.parsed, _Section) and fits.kept is None
        raw = _raw('{"body": "x", "evidence_refs": "ev_0001"}')
        refused = read_structured_reply(
            {"raw": raw, "parsed": {"body": "x", "evidence_refs": "ev_0001"}},
            None,
            schema=_Section,
        )
        assert refused.parsed is None and refused.kept is raw
        assert refused.unread == "carries an object that does not fit the schema (ValidationError)"
        unread = read_structured_reply({"raw": raw, "parsed": {"evidence_refs": 1}}, None)
        assert unread.parsed == {"evidence_refs": 1}, "no schema named: the dict as it came"

    def test_a_composer_section_keeps_it_as_its_first_answer(self) -> None:
        refused = {"body": "The packed loader.", "evidence_refs": "ev_0001"}

        def answer(schema: type[BaseModel], turns: list[BaseMessage]) -> tuple[Any, Any]:
            payload = _answer(_section_of(turns))
            if schema.__name__ != "_ProseOut":
                return _raw(json.dumps(payload)), _parsed(schema, payload)
            if len(turns) == 2:
                return _raw(json.dumps(refused)), dict(refused)
            return _raw(json.dumps(payload)), None

        llm, composer, _events = _compose(answer)
        assert [kind for kind, _turns in llm.asked].count("plain") == 0, "never asked fresh"
        retries = [turns for _kind, turns in llm.asked if len(turns) > 2]
        assert len(retries) == 7, "each prose section's retry"
        for turns in retries:
            assert turns[2].content == json.dumps(refused), "the kept answer is followed"
            assert isinstance(turns[3], HumanMessage)
            assert str(turns[3].content).startswith(FEEDBACK_PREAMBLE)
            assert "[composer.schema] (evidence_refs)" in str(turns[3].content)
        assert composer.validation_tally.by_code.get("composer.schema") == 7

    def test_the_narrative_keeps_it_as_its_first_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import narrative_agent
        from tests.unit.reporting.test_narrative_agent import _make_report, _valid_narrative

        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]

        def answer(schema: type[BaseModel], turns: list[BaseMessage]) -> tuple[Any, Any]:
            if len(turns) == 2:
                return _raw(json.dumps(thin)), dict(thin)
            return _raw(_valid_narrative().model_dump_json()), None

        llm = _Model(answer)
        monkeypatch.setattr(narrative_agent, "structured_output_supported_for_llm", lambda _l: True)
        out = asyncio.run(narrative_agent.NarrativeAgent(llm=llm).generate(_make_report()))  # type: ignore[arg-type]
        assert out is not None and len(out.key_findings) >= 2
        assert [kind for kind, _turns in llm.asked] == ["structured", "structured"]
        retry = llm.asked[1][1]
        assert retry[2].content == json.dumps(thin)
        assert "[narrative.schema] (key_findings)" in str(retry[3].content)
