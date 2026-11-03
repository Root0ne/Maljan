"""A model that writes a schema offered beside ``read_evidence`` as text is asked in text.

No tool choice is sent for a schema on Anthropic, and a model that thinks by
default cannot be made to call one: offered beside ``read_evidence``, Claude
Haiku 5.5 wrote the JSON as text in every structured call of haiku7 (17) and
haiku8 (22), each logged as "carries no object the schema reads". The
provider says so (``schema_tool_answered_as_text``), and says it asks for no
JSON-schema answer natively (``native_json_schema_output``): the pinned
langchain-anthropic's ``json_schema`` method replaces the tools a model has
bound and its parser refuses a reply that reads. So the composer's sections,
the narrative and the judge's technique question are asked for their JSON in
text from the first call, with no schema tool, each model saying so once;
the answer is read by the parser that already read it from the text.
A schema offered alone (the mediation's extraction) keeps its tool.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage
from pydantic import BaseModel

from maljan.agents.ledger_reads import LedgerReads
from maljan.agents.tool_answer_clearing import READ_EVIDENCE_TOOL
from maljan.core.config import Settings
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.llm.registry import schema_tool_worth_offering
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from maljan.reporting.narrative_agent import NarrativeAgent
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import _isr, _report

from .anthropic_wire import MODEL, Wire, install
from .test_a_structured_answer_in_text_is_kept import FACTS, _by_section, _in_text
from .test_the_report_calls_may_read_the_ledger import LEDGER


def _built(model: str) -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )
    return AnthropicProvider(settings).build_model(model, 0.1, max_tokens=4096)


class TestTheProviderSaysSo:
    def test_a_model_that_thinks_by_default_writes_the_schema_as_text(self) -> None:
        llm = _built(MODEL)
        assert AnthropicProvider.schema_tool_answered_as_text(llm) is True
        assert AnthropicProvider.native_json_schema_output(llm) is False

    def test_an_older_model_keeps_the_tool(self) -> None:
        llm = _built("claude-3-5-haiku-20241022")
        assert AnthropicProvider.schema_tool_answered_as_text(llm) is False
        assert schema_tool_worth_offering(llm) is True

    def test_it_is_said_once_per_model(self, caplog: pytest.LogCaptureFixture) -> None:
        llm = _built(MODEL)
        with caplog.at_level(logging.INFO, logger="maljan"):
            assert schema_tool_worth_offering(llm) is False
            assert schema_tool_worth_offering(llm) is False
        said = [r for r in caplog.records if "writes a schema offered beside" in r.getMessage()]
        assert len(said) == 1

    def test_another_provider_s_model_keeps_the_tool(self) -> None:
        class _Other:
            _llm_type = "openai-chat"
            model_name = "gpt-4o"

        assert schema_tool_worth_offering(_Other()) is True

    def test_it_is_read_from_its_own_vendored_fact(self) -> None:
        from maljan.llm.anthropic_provider import thinks_by_default_source

        assert "adaptive thinking is on by default" in thinks_by_default_source(MODEL)
        assert thinks_by_default_source("claude-3-5-haiku-20241022") == ""

    def test_a_model_built_with_thinking_off_keeps_the_tool(self) -> None:
        llm = _built(MODEL).model_copy(update={"thinking": {"type": "disabled"}})
        assert AnthropicProvider.schema_tool_answered_as_text(llm) is False

    def test_a_fallback_list_takes_the_text_path_only_when_every_model_would(self) -> None:
        class _List:
            _llm_type = "maljan-fallback"

            def __init__(self, models: list[Any]) -> None:
                self.models = models

        thinking, older = _built(MODEL), _built("claude-3-5-haiku-20241022")
        assert schema_tool_worth_offering(_List([older, thinking])) is True
        assert schema_tool_worth_offering(_List([thinking, older])) is True
        assert schema_tool_worth_offering(_List([thinking, _built(MODEL)])) is False


class TestThePinnedClientHasNoNativePathWithReadsBound:
    """Why ``native_json_schema_output`` is ``False``: checked on the pinned client itself."""

    class _Out(BaseModel):
        summary: str

    @staticmethod
    def read_evidence(evidence_id: str) -> str:
        """Read a ledger entry."""
        return ""

    def test_the_json_schema_method_drops_the_bound_tool(self) -> None:
        from langchain_anthropic import ChatAnthropic

        llm = ChatAnthropic(model_name=MODEL, api_key="test-anthropic-key")
        bound = llm.bind_tools([self.read_evidence])
        asked = bound.with_structured_output(self._Out, method="json_schema")
        assert "tools" not in asked.first.kwargs

    def test_its_parser_refuses_a_reply_that_reads(self) -> None:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.exceptions import OutputParserException

        llm = ChatAnthropic(model_name=MODEL, api_key="test-anthropic-key")
        asked = llm.with_structured_output(self._Out, method="json_schema")
        read = {"name": READ_EVIDENCE_TOOL, "args": {"evidence_id": "ev_0001"}, "id": "t1"}
        with pytest.raises(OutputParserException):
            asked.last.invoke(AIMessage(content="", tool_calls=[read]))


class TestTheCallsAreAskedInText:
    def test_every_section_sends_read_evidence_alone_and_is_written(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire = Wire(_in_text)
        install(monkeypatch, wire)
        report = _report()
        composer = ReportComposer(llm=_built(MODEL), per_section_timeout=60)
        composer.ledger_reads = LedgerReads(LEDGER)
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=True
        ):
            asyncio.run(composer.compose(report, _isr(), facts_block=FACTS, concurrent=False))
        by_section = _by_section(wire)
        assert set(by_section) == set(COMPOSED_SECTIONS)
        for section, bodies in by_section.items():
            for body in bodies:
                assert [tool["name"] for tool in body["tools"]] == [READ_EVIDENCE_TOOL], section
        # Nothing parsed is lost: every section was written from its text.
        assert not [d for d in composer.degradations if "missing" in d]

    def test_a_model_that_does_not_think_by_default_is_offered_the_schema_beside_the_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire = Wire(_in_text)
        install(monkeypatch, wire)
        composer = ReportComposer(llm=_built("claude-3-5-haiku-20241022"), per_section_timeout=60)
        composer.ledger_reads = LedgerReads(LEDGER)
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=True
        ):
            asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=False))
        firsts = [b for b in wire.bodies if len(b["messages"]) == 1]
        assert firsts
        for body in firsts:
            names = [tool["name"] for tool in body["tools"]]
            assert len(names) == 2 and names[-1] == READ_EVIDENCE_TOOL, names

    def test_the_narrative_takes_the_text_path_from_its_first_call(self) -> None:
        agent = NarrativeAgent.__new__(NarrativeAgent)
        agent.llm = _built(MODEL)
        agent.ledger_reads = LedgerReads(LEDGER)
        with patch(
            "maljan.reporting.narrative_agent.structured_output_supported_for_llm",
            return_value=True,
        ):
            assert agent._structured_path() is False
            agent.ledger_reads = None
            assert agent._structured_path() is True
