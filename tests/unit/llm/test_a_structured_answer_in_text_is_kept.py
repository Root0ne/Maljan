"""A composer section's structured answer written as text is its answer, and is not asked again.

The structured path offers the section's schema as a tool and leaves the model
free to call it (``tool_choice`` is never forced), and the prompt itself asks
for the JSON object. A model that writes the object as text has answered: the
text is the validation loop's first answer. A retry goes the way that answer
went, with the same tools, so the request only appends to the one answered and
every thinking block it sends back stays valid (the Preserved thinking page).
An answer with nothing in it is asked again on the manual path, as before, and
the log says why.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from typing import Any
from unittest.mock import patch

import pytest

from maljan.core.config import Settings
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _answer,
    _isr,
    _report,
)

from .anthropic_wire import MODEL, Wire, _unmarked, install, message

USAGE = {"input_tokens": 10, "output_tokens": 5}
FACTS = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable"
_LEAD = "The evidence for the "
_SIGNATURES = itertools.count(1)


def _text_of(body: dict[str, Any]) -> str:
    content = body["messages"][0]["content"]
    if isinstance(content, str):
        return content
    return "".join(block["text"] for block in content)


def _section(body: dict[str, Any]) -> str:
    text = _text_of(body)
    start = text.index(_LEAD) + len(_LEAD)
    return text[start : text.index(" section follows.", start)]


def _thinking() -> dict[str, Any]:
    return {"type": "thinking", "thinking": "", "signature": f"sig-{next(_SIGNATURES)}"}


def _in_text(body: dict[str, Any]) -> dict[str, Any]:
    """Every answer thinks first and writes the object as text, as the prompt asks."""
    answer = _answer(_section(body)) if _LEAD in _text_of(body) else {}
    return message(
        [_thinking(), {"type": "text", "text": json.dumps(answer)}], stop="end_turn", usage=USAGE
    )


def _model() -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _compose(monkeypatch: pytest.MonkeyPatch, answer: Any) -> tuple[Wire, Any]:
    wire = Wire(answer)
    install(monkeypatch, wire)
    report = _report()
    composer = ReportComposer(llm=_model(), per_section_timeout=60)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=True):
        asyncio.run(composer.compose(report, _isr(), facts_block=FACTS, concurrent=True))
    return wire, report


def _by_section(wire: Wire) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = {}
    for body in wire.bodies:
        if _LEAD in _text_of(body):
            found.setdefault(_section(body), []).append(body)
    return found


class TestAnAnswerInText:
    def test_no_section_is_asked_again_without_its_tool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, _report_ = _compose(monkeypatch, _in_text)
        by_section = _by_section(wire)
        assert set(by_section) == set(COMPOSED_SECTIONS)
        for section, bodies in by_section.items():
            assert all(body.get("tools") for body in bodies), section
            # The first request and at most the one retry its findings ask for.
            assert len(bodies) <= 2, section
            assert len(bodies[0]["messages"]) == 1, section

    def test_the_sections_are_written_from_the_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _wire, report = _compose(monkeypatch, _in_text)
        analysis = report.technical_analysis
        assert analysis is not None
        assert analysis.packing_obfuscation is not None
        assert analysis.configuration

    def test_a_retry_only_appends_to_the_request_answered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, _report_ = _compose(monkeypatch, _in_text)
        retried = [bodies for bodies in _by_section(wire).values() if len(bodies) == 2]
        assert retried, "the recorded answers leave findings a retry is asked about"
        for first, retry in retried:
            assert retry["tools"] == first["tools"]
            assert retry["system"] == first["system"]
            first_turn = _unmarked(first["messages"][0]["content"])
            assert _unmarked(retry["messages"][0]["content"]) == first_turn
            assert [m["role"] for m in retry["messages"]] == ["user", "assistant", "user"]
            kinds = [b["type"] for b in retry["messages"][1]["content"]]
            assert kinds[0] == "thinking", "the answer goes back as it was received"
        assert wire.refused == []
        assert wire.dropped == [], "every thinking block sent back stays valid"


class TestAToolCallTheSchemaDoesNotTake:
    """A call of the schema's tool with arguments the schema refuses is read like text.

    The correction then describes the call, and its answer is the section's.
    """

    @staticmethod
    def _answers() -> Any:
        asked: set[str] = set()

        def answer(body: dict[str, Any]) -> dict[str, Any]:
            section = _section(body) if _LEAD in _text_of(body) else ""
            if not body.get("tools") or section in asked:
                return _in_text(body)
            asked.add(section)
            name = body["tools"][0]["name"]
            args = {**_answer(section), "evidence_refs": "ev_0001"}
            call = {"type": "tool_use", "id": f"toolu_{next(_SIGNATURES)}", "name": name}
            return message([_thinking(), {**call, "input": args}], stop="tool_use", usage=USAGE)

        return answer

    def test_the_prose_sections_are_not_asked_again_without_their_tool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, report = _compose(monkeypatch, self._answers())
        for section, bodies in _by_section(wire).items():
            assert all(body.get("tools") for body in bodies), section
        assert wire.refused == []
        assert report.technical_analysis is not None
        assert report.technical_analysis.packing_obfuscation is not None


class TestAnAnswerWithNothingInIt:
    @staticmethod
    def _answer(body: dict[str, Any]) -> dict[str, Any]:
        if body.get("tools"):
            return message([], stop="end_turn", usage=USAGE)
        return _in_text(body)

    def test_it_is_asked_again_without_the_tool_and_the_log_says_why(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import composer

        said: list[str] = []
        monkeypatch.setattr(
            composer.logger, "warning", lambda message, *args: said.append(message % args)
        )
        wire, _report_ = _compose(monkeypatch, self._answer)
        for section, bodies in _by_section(wire).items():
            assert bodies[0].get("tools"), section
            assert not bodies[1].get("tools"), section
        assert len([line for line in said if "holds no text" in line]) == len(COMPOSED_SECTIONS)
