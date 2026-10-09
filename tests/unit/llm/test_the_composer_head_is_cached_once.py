"""On Claude, the head the composer's sections repeat is cached once per shared prefix.

Anthropic's prefix is the tools, then the system prompt, then the messages.
On the manual path no section sends a tool, so every section shares one
prefix up to the end of its head; on the structured path each section sends
its own schema as a tool, so only the sections answering with one schema (the
seven prose subsections) share one. A section of such a group sends its first
user turn as two text blocks — the head with a cache breakpoint, then the
rest, joined the turn's text character for character — and the group's first
section is sent alone, the others once its answer has begun: Anthropic makes
a cached prefix readable only from then on
(https://platform.claude.com/docs/en/build-with-claude/prompt-caching). A
section that shares its prefix with no other is sent as it was, at once.
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
    answer = _answer(_section(body)) if _LEAD in _text_of(body) else {}
    if body.get("tools"):
        name = body["tools"][0]["name"]
        call = {"type": "tool_use", "id": "toolu_1", "name": name, "input": answer}
        return message([call], stop="tool_use", usage=USAGE)
    return message([{"type": "text", "text": json.dumps(answer)}], stop="end_turn", usage=USAGE)


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


def _prefix(body: dict[str, Any]) -> str:
    """The body's tools, system and cached head block, or ``""`` where no head is marked."""
    content = body["messages"][0]["content"]
    if isinstance(content, str) or "cache_control" not in content[0]:
        return ""
    return json.dumps([body.get("tools"), body.get("system"), content[0]], sort_keys=True)


PROSE = (
    "packing_obfuscation",
    "string_resolution",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "command_and_control",
    "payloads",
)


class TestOnTheStructuredPath:
    """Each section sends its schema as a tool: only the prose subsections share a prefix."""

    def _bodies(self, wire: Wire) -> list[dict[str, Any]]:
        # What an ``anthropic`` provider's settings answer (``registry``).
        composer = ReportComposer(llm=_model(), per_section_timeout=60)
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=True
        ):
            asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))
        # A section whose structured answer does not parse is asked again by
        # the manual path, with no tool; those requests are not the ones here.
        return [b for b in wire.bodies if len(b["messages"]) == 1 and b.get("tools")]

    def test_the_prose_sections_share_one_cached_prefix_and_no_other_is_marked(
        self, wire: Wire
    ) -> None:
        firsts = self._bodies(wire)
        by_section = {_section(b): b for b in firsts}
        assert set(by_section) == set(COMPOSED_SECTIONS)
        prose = {_prefix(by_section[name]) for name in PROSE}
        assert len(prose) == 1 and "" not in prose, "one byte-identical prefix"
        for name in set(COMPOSED_SECTIONS) - set(PROSE):
            assert isinstance(by_section[name]["messages"][0]["content"], str), name

    def test_only_the_prose_group_waits_for_its_lead(self, wire: Wire) -> None:
        order = [_section(b) for b in self._bodies(wire)]
        first_prose = min(order.index(name) for name in PROSE)
        assert order[first_prose] == "packing_obfuscation"
        assert order.index("introduction") < order.index("string_resolution")


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

    def test_on_the_manual_path_the_lead_section_is_sent_before_the_others(
        self, wire: Wire
    ) -> None:
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
