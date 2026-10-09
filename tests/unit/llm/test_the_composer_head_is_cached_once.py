"""On Claude, the head every composer section repeats is one cached prefix.

Each section's first user turn goes out as two text blocks: the shared head
with a cache breakpoint, then the rest. Joined, the two are the turn's text
character for character, so the model reads what it read before. The first
section with evidence is sent alone, and the others follow once its answer
has begun: Anthropic makes a cached prefix readable only from then on
(https://platform.claude.com/docs/en/build-with-claude/prompt-caching).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from maljan.core.config import Settings
from maljan.llm import anthropic_history
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _answer,
    _isr,
    _report,
)

from .anthropic_wire import MODEL, Wire, install, message

USAGE = {"input_tokens": 10, "output_tokens": 5}
FACTS = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable"
_LEAD = "The evidence for the "


def _text_of(body: dict[str, Any]) -> str:
    content = body["messages"][0]["content"]
    if isinstance(content, str):
        return content
    return "".join(block["text"] for block in content)


def _section(body: dict[str, Any]) -> str:
    text = _text_of(body)
    start = text.index(_LEAD) + len(_LEAD)
    return text[start : text.index(" section follows.", start)]


def _reply(body: dict[str, Any]) -> dict[str, Any]:
    said = json.dumps(_answer(_section(body))) if _LEAD in _text_of(body) else "{}"
    text = {"type": "text", "text": said}
    return message([text], stop="end_turn", usage=USAGE)


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Wire:
    found = Wire(_reply)
    install(monkeypatch, found)
    return found


def _model() -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _compose(model: Any) -> None:
    composer = ReportComposer(llm=model, per_section_timeout=60)
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))


class TestTheHeadIsCachedOnce:
    def test_every_section_sends_the_head_as_one_cached_block(self, wire: Wire) -> None:
        _compose(_model())
        firsts = [b for b in wire.bodies if len(b["messages"]) == 1]
        assert {_section(b) for b in firsts} == set(COMPOSED_SECTIONS)
        heads = set()
        for body in firsts:
            head, rest = body["messages"][0]["content"]
            assert head["cache_control"]["type"] == "ephemeral"
            assert "cache_control" not in rest
            heads.add(head["text"])
        assert heads == {FACTS + "\n\n"}, "one prefix, the same on every section"
        assert len({json.dumps(b.get("system"), sort_keys=True) for b in wire.bodies}) == 1

    def test_the_lead_section_is_sent_before_the_others(self, wire: Wire) -> None:
        _compose(_model())
        assert _section(wire.bodies[0]) == "introduction"
        assert [_section(b) for b in wire.bodies[1:]].count("introduction") <= 1

    def test_the_joined_blocks_are_the_turn_s_text(self) -> None:
        text = FACTS + "\n\nWrite the introduction.\n\nThe evidence follows."
        turn = HumanMessage(
            content=text, response_metadata={anthropic_history.SHARED_HEAD: len(FACTS) + 2}
        )
        payload = {"messages": [{"role": "user", "content": text}], "system": "S"}
        marker = {"type": "ephemeral"}
        heads = {text: len(FACTS) + 2}
        sent = anthropic_history.prepared(
            payload,
            anthropic_history.Memory(),
            bound=False,
            cache_marker=marker,
            heads=heads,
        )
        blocks = sent["messages"][0]["content"]
        assert "".join(block["text"] for block in blocks) == text
        assert blocks[0] == {"type": "text", "text": FACTS + "\n\n", "cache_control": marker}
        assert turn.content == text

    def test_a_turn_with_no_note_is_sent_as_it_was(self) -> None:
        payload = {"messages": [{"role": "user", "content": "plain"}]}
        sent = anthropic_history.prepared(
            payload, anthropic_history.Memory(), bound=False, cache_marker={"type": "ephemeral"}
        )
        assert sent["messages"] == [{"role": "user", "content": "plain"}]

    def test_the_note_never_reaches_a_request_body(self, wire: Wire) -> None:
        model = _model()
        turn = HumanMessage(
            content="HEAD\n\nrest", response_metadata={anthropic_history.SHARED_HEAD: 6}
        )
        model.invoke([SystemMessage(content="S"), turn])
        assert anthropic_history.SHARED_HEAD not in json.dumps(wire.bodies[-1])
