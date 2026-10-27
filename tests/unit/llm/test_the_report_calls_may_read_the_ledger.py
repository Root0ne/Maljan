"""The report's calls may read the run's ledger by id, from their first turn.

The composer's sections, the narrative, and the reporter's further rounds (the
question round and the section agreement round, both through
``NarrativeAgent.ask``) were each one call with no tool beside the schema: an
entry the prompt shortened, or one a section cites and is not shown, could not
be read. Each now offers ``read_evidence`` beside what it offered, answered
from the run's ledger. Sent over the Anthropic wire, so a read keeps every
thinking block valid and every tool call answered. A call that reads nothing
writes the report it always wrote, and its cached header is the same bytes; a
model that cannot bind the tool is asked as before and the report says so once.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from maljan.agents.ledger_reads import LedgerReads, not_bound_reason
from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.llm.answer_text import answer_text
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from maljan.reporting.narrative_agent import NarrativeAgent
from maljan.schemas.evidence import LedgerEntry
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _isr,
    _report,
)

from .anthropic_wire import Wire, install, message
from .test_a_structured_answer_in_text_is_kept import (
    _LEAD,
    FACTS,
    USAGE,
    _by_section,
    _in_text,
    _model,
    _section,
    _text_of,
    _thinking,
)

HELD = "the configuration block decoded at 0x4010"
LEDGER = [LedgerEntry(id="ev_0001", agent="static", tool="decode", output=HELD)]
_CALLS = itertools.count(1)


def _read_call(entry_id: str = "ev_0001") -> dict[str, Any]:
    call = {"type": "tool_use", "id": f"toolu_read{next(_CALLS)}", "name": READ_EVIDENCE_TOOL}
    return message(
        [_thinking(), {**call, "input": {"evidence_id": entry_id}}], stop="tool_use", usage=USAGE
    )


def _read_result(body: dict[str, Any]) -> str:
    """The text of the newest tool result the request carries, or ``""``."""
    last = body["messages"][-1]
    content = last.get("content") if isinstance(last.get("content"), list) else []
    for block in content:
        if block.get("type") == "tool_result":
            inner = block.get("content")
            if isinstance(inner, list):
                return "".join(part.get("text", "") for part in inner)
            return str(inner)
    return ""


def _reads_first(sections: set[str]) -> Any:
    """Each named section reads ``ev_0001`` first, then answers in text."""

    def answer(body: dict[str, Any]) -> dict[str, Any]:
        if _LEAD in _text_of(body) and _section(body) in sections and not _read_result(body):
            return _read_call()
        return _in_text(body)

    return answer


def _compose(
    monkeypatch: pytest.MonkeyPatch,
    answer: Any,
    *,
    reads: LedgerReads | None,
    structured: bool = True,
) -> tuple[Wire, Any, ReportComposer]:
    wire = Wire(answer)
    install(monkeypatch, wire)
    report = _report()
    composer = ReportComposer(llm=_model(), per_section_timeout=60)
    composer.ledger_reads = reads
    with patch(
        "maljan.reporting.composer.structured_output_supported_for_llm", return_value=structured
    ):
        asyncio.run(composer.compose(report, _isr(), facts_block=FACTS, concurrent=False))
    return wire, report, composer


def _tool_names(body: dict[str, Any]) -> list[str]:
    return [str(tool.get("name")) for tool in body.get("tools") or []]


def _unbindable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: LedgerReads, llm: Any, tools: Any = (), **kwargs: Any) -> Any:
        raise NotImplementedError("this model binds no tools")

    monkeypatch.setattr(LedgerReads, "bind", refuse)


class TestTheComposersSections:
    @pytest.mark.parametrize("structured", [True, False])
    def test_every_section_call_carries_read_evidence_from_its_first_turn(
        self, monkeypatch: pytest.MonkeyPatch, structured: bool
    ) -> None:
        wire, _report_, _composer = _compose(
            monkeypatch, _in_text, reads=LedgerReads(LEDGER), structured=structured
        )

        by_section = _by_section(wire)
        assert set(by_section) == set(COMPOSED_SECTIONS)
        for section, bodies in by_section.items():
            for body in bodies:
                names = _tool_names(body)
                assert names[-1] == READ_EVIDENCE_TOOL, section
                assert len(names) == (2 if structured else 1), section

    def test_the_cached_header_and_the_system_prompt_are_the_same_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reading, _r1, _c1 = _compose(monkeypatch, _in_text, reads=LedgerReads(LEDGER))
        plain, _r2, _c2 = _compose(monkeypatch, _in_text, reads=None)

        for section, bodies in _by_section(reading).items():
            before = _by_section(plain)[section]
            # Every request's first turn, the shared header and the section's ask.
            assert [b["messages"][0] for b in bodies] == [b["messages"][0] for b in before], section
            assert [b["system"] for b in bodies] == [b["system"] for b in before], section
            # The definitions the sections share are one byte string.
            read_tool = [t for t in bodies[0]["tools"] if t["name"] == READ_EVIDENCE_TOOL]
            assert json.dumps(read_tool) == json.dumps(
                [t for t in reading.bodies[0]["tools"] if t["name"] == READ_EVIDENCE_TOOL]
            )

    def test_a_read_reaches_the_ledger_and_the_section_is_written_after_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, report, _composer = _compose(
            monkeypatch, _reads_first({"configuration"}), reads=LedgerReads(LEDGER)
        )

        bodies = _by_section(wire)["configuration"]
        assert "tool_use" in json.dumps(bodies[1]["messages"][1])
        said = _read_result(bodies[1])
        assert said.startswith("[ev_0001]\n") and HELD in said
        assert _tool_names(bodies[1]) == _tool_names(bodies[0])
        assert wire.refused == [] and wire.dropped == []
        assert report.technical_analysis is not None
        assert report.technical_analysis.configuration

    def test_the_report_is_unchanged_when_no_tool_is_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _w1, with_reads, reading = _compose(monkeypatch, _in_text, reads=LedgerReads(LEDGER))
        _w2, without, plain = _compose(monkeypatch, _in_text, reads=None)

        def body(report: Any) -> Any:
            return report.model_dump(mode="json", exclude={"generated_at"})

        assert body(with_reads) == body(without)
        assert reading.validation_tally.by_code == plain.validation_tally.by_code
        assert reading.degradations == plain.degradations

    def test_a_model_that_cannot_bind_it_writes_as_before_and_the_report_is_told_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unbindable(monkeypatch)

        wire, _report_, composer = _compose(monkeypatch, _in_text, reads=LedgerReads(LEDGER))

        for section, bodies in _by_section(wire).items():
            assert READ_EVIDENCE_TOOL not in _tool_names(bodies[0]), section
        assert composer.degradations.count(not_bound_reason("reporter")) == 1


class TestTheNarrative:
    @staticmethod
    def _generate(
        monkeypatch: pytest.MonkeyPatch, answer: Any, reads: LedgerReads | None
    ) -> tuple[Wire, Any, NarrativeAgent]:
        from maljan.reporting import narrative_agent
        from tests.unit.reporting.test_narrative_agent import _make_report, _valid_narrative

        text = _valid_narrative().model_dump_json()

        def reply(body: dict[str, Any]) -> dict[str, Any]:
            return answer(body, text)

        wire = Wire(reply)
        install(monkeypatch, wire)
        monkeypatch.setattr(narrative_agent, "structured_output_supported_for_llm", lambda _l: True)
        agent = narrative_agent.NarrativeAgent(llm=_model())
        agent.ledger_reads = reads
        out = asyncio.run(agent.generate(_make_report()))
        return wire, out, agent

    @staticmethod
    def _in_text(body: dict[str, Any], text: str) -> dict[str, Any]:
        return message([_thinking(), {"type": "text", "text": text}], stop="end_turn", usage=USAGE)

    def test_the_narrative_carries_read_evidence_beside_its_schema(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, out, _agent = self._generate(monkeypatch, self._in_text, LedgerReads(LEDGER))

        assert _tool_names(wire.bodies[0]) == ["NarrativeOutput", READ_EVIDENCE_TOOL]
        assert out is not None

    def test_a_read_reaches_the_ledger_and_the_narrative_is_written_after_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def reads_first(body: dict[str, Any], text: str) -> dict[str, Any]:
            if not _read_result(body):
                return _read_call()
            return self._in_text(body, text)

        wire, out, _agent = self._generate(monkeypatch, reads_first, LedgerReads(LEDGER))

        assert HELD in _read_result(wire.bodies[1])
        assert wire.refused == [] and wire.dropped == []
        assert out is not None and len(out.key_findings) >= 2

    def test_the_narrative_is_unchanged_when_no_tool_is_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reading, with_reads, _a = self._generate(monkeypatch, self._in_text, LedgerReads(LEDGER))
        plain, without, _b = self._generate(monkeypatch, self._in_text, None)

        assert with_reads == without
        assert reading.bodies[0]["messages"] == plain.bodies[0]["messages"]
        assert reading.bodies[0]["system"] == plain.bodies[0]["system"]

    def test_a_model_that_cannot_bind_it_is_asked_as_before_and_the_report_is_told(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unbindable(monkeypatch)

        wire, out, agent = self._generate(monkeypatch, self._in_text, LedgerReads(LEDGER))

        assert _tool_names(wire.bodies[0]) == ["NarrativeOutput"]
        assert agent.degradations == [not_bound_reason("reporter")]
        assert out is not None


class TestAnOpenAIShapedSchemaCall:
    """On OpenAI and Gemini a structured call that reads is function calling: schema tool and read.

    Its answer, a call of the schema's tool, is parsed as the provider's own
    function-calling structured output parses it.
    """

    @staticmethod
    def _message(args: dict[str, Any], *, read_first: bool = False) -> Any:
        from langchain_openai.chat_models.base import _convert_dict_to_message

        calls = [
            {
                "id": "call_schema",
                "type": "function",
                "function": {"name": "NarrativeOutput", "arguments": json.dumps(args)},
            }
        ]
        if read_first:
            read = {"name": READ_EVIDENCE_TOOL, "arguments": '{"evidence_id": "ev_0001"}'}
            calls.insert(0, {"id": "call_read", "type": "function", "function": read})
        return _convert_dict_to_message({"role": "assistant", "content": None, "tool_calls": calls})

    def test_the_schema_call_is_parsed_as_function_calling_parses_it(self) -> None:
        from langchain_core.output_parsers.openai_tools import PydanticToolsParser

        from maljan.agents.ledger_reads import structured_reply
        from maljan.reporting.narrative_agent import NarrativeOutput
        from tests.unit.reporting.test_narrative_agent import _valid_narrative

        args = _valid_narrative().model_dump(mode="json")
        message = self._message(args)

        read = structured_reply(message, NarrativeOutput)
        parsed = PydanticToolsParser(tools=[NarrativeOutput], first_tool_only=True).invoke(message)

        assert read["raw"] is message and read["parsing_error"] is None
        assert read["parsed"] == parsed == _valid_narrative()

    def test_a_read_beside_the_schema_call_does_not_change_what_is_parsed(self) -> None:
        from maljan.agents.ledger_reads import structured_reply
        from maljan.reporting.narrative_agent import NarrativeOutput
        from tests.unit.reporting.test_narrative_agent import _valid_narrative

        args = _valid_narrative().model_dump(mode="json")

        read = structured_reply(self._message(args, read_first=True), NarrativeOutput)

        assert read["parsed"] == _valid_narrative()

    def test_arguments_the_schema_refuses_are_no_parse_with_the_error_kept(self) -> None:
        from maljan.agents.ledger_reads import structured_reply
        from maljan.reporting.narrative_agent import NarrativeOutput

        read = structured_reply(self._message({"key_findings": "not a list"}), NarrativeOutput)

        assert read["parsed"] is None and read["parsing_error"] is not None


class TestTheReportersFurtherRounds:
    """``NarrativeAgent.ask``: the question round's and the section agreement round's call."""

    TURNS = (SystemMessage(content="You answer questions."), HumanMessage(content="Which entry?"))

    @staticmethod
    def _ask(
        monkeypatch: pytest.MonkeyPatch, answer: Any, reads: LedgerReads | None
    ) -> tuple[Wire, Any, NarrativeAgent]:
        wire = Wire(answer)
        install(monkeypatch, wire)
        agent = NarrativeAgent(llm=_model())
        agent.ledger_reads = reads
        reply = asyncio.run(
            agent.ask(list(TestTheReportersFurtherRounds.TURNS), call="question round", what="q")
        )
        return wire, reply, agent

    @staticmethod
    def _text(body: dict[str, Any]) -> dict[str, Any]:
        text = '{"answers": []}'
        return message([_thinking(), {"type": "text", "text": text}], stop="end_turn", usage=USAGE)

    def test_the_call_carries_read_evidence_from_its_first_turn(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, _reply, _agent = self._ask(monkeypatch, self._text, LedgerReads(LEDGER))

        assert _tool_names(wire.bodies[0]) == [READ_EVIDENCE_TOOL]

    def test_a_read_reaches_the_ledger_and_the_reply_after_it_is_the_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def reads_first(body: dict[str, Any]) -> dict[str, Any]:
            return self._text(body) if _read_result(body) else _read_call()

        wire, reply, _agent = self._ask(monkeypatch, reads_first, LedgerReads(LEDGER))

        assert HELD in _read_result(wire.bodies[1])
        assert wire.refused == []
        assert answer_text(reply.content) == '{"answers": []}'

    def test_the_call_is_unchanged_when_no_tool_is_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reading, with_reads, _a = self._ask(monkeypatch, self._text, LedgerReads(LEDGER))
        plain, without, _b = self._ask(monkeypatch, self._text, None)

        assert reading.bodies[0]["messages"] == plain.bodies[0]["messages"]
        assert "tools" not in plain.bodies[0]
        assert with_reads.content[-1] == without.content[-1]

    def test_a_model_that_cannot_bind_it_is_asked_as_before_and_the_report_is_told(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unbindable(monkeypatch)

        wire, _reply, agent = self._ask(monkeypatch, self._text, LedgerReads(LEDGER))

        assert "tools" not in wire.bodies[0]
        assert agent.degradations == [not_bound_reason("reporter")]

    def test_a_follow_up_question_may_read_the_stored_ledger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import follow_up
        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import _run

        offered: list[Any] = []

        async def asked(reporter: Any, *args: Any, **kwargs: Any) -> Any:
            offered.append(reporter.ledger_reads)
            return None

        monkeypatch.setattr(follow_up, "answer_questions", asked)
        agent = NarrativeAgent(llm=_model())
        run = _run()

        asyncio.run(follow_up.answer_follow_up(agent, run, "Does it beacon?"))

        (reads,) = offered
        assert isinstance(reads, LedgerReads)
        held = run.ledger[0]
        assert reads.read({"evidence_id": held.id}).startswith(f"[{held.id}]")

    def test_the_agreement_round_never_raises_over_a_read_that_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting.section_agreement import ask_section_agreement
        from tests.unit.reporting.test_a_passage_written_without_the_code_is_asked_against_section_5 import (  # noqa: E501
            _DEBATE,
            CITABLE,
        )
        from tests.unit.reporting.test_a_passage_written_without_the_code_is_asked_against_section_5 import (  # noqa: E501
            _report as _agreement_report,
        )

        async def broken(self: LedgerReads, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("the store went away")

        monkeypatch.setattr(LedgerReads, "answer", broken)
        wire = Wire(self._text)
        install(monkeypatch, wire)
        agent = NarrativeAgent(llm=_model())
        agent.ledger_reads = LedgerReads(LEDGER)

        round_ = asyncio.run(
            ask_section_agreement(
                agent, _agreement_report(), discussion=_DEBATE, citable_ids=CITABLE
            )
        )

        assert round_.degradations
        assert "section agreement question was not answered" in round_.degradations[-1]
