"""Which tools reached the evidence corpus with rows missing.

The grounding rule does not move: ``_apply_output_guardrail`` returns one
string, and that one string is both what the model reads and what
``recorder.record`` stores, so a value in neither is a value the model never
saw. What the judge lacked was the other half of the picture — that one of the
answers it searched was handed over short, and which call it was.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.output_shortening import BOOKKEEPING_KEY, shorten_json_document
from maljan.pipeline.nodes import _tools_that_were_shortened
from maljan.schemas.evidence import LedgerEntry


def _entry(tool: str, output: str) -> LedgerEntry:
    from maljan.schemas.evidence import parse_structured

    return LedgerEntry(
        id="ev_0001",
        agent="static",
        server="analysis",
        tool=tool,
        args={},
        ok=True,
        output=output,
        structured=parse_structured(output),
        duration_ms=1,
    )


def _shortened_answer() -> str:
    """A real sidecar-shaped answer put through the real shortener."""
    document: dict[str, Any] = {
        "read_path": "/staging/sample.bin",
        "total": 3876,
        "strings": [f"a string number {index:04d} of the answer" for index in range(300)],
    }
    text = json.dumps(document)
    attempt = shorten_json_document(text, 6000)
    assert attempt.shortened, "the fixture must exercise the real shortening path"
    return attempt.text


class TestTheLedgerSaysWhichAnswersWereShort:
    def test_a_shortened_answer_names_its_tool(self) -> None:
        entries = [_entry("strings", _shortened_answer())]

        assert _tools_that_were_shortened(entries) == {"strings"}

    def test_a_whole_answer_names_nothing(self) -> None:
        entries = [_entry("strings", json.dumps({"read_path": "/staging/s", "strings": ["a"]}))]

        assert _tools_that_were_shortened(entries) == set()

    def test_prose_names_nothing(self) -> None:
        entries = [_entry("decompile", "a function that does something" * 10)]

        assert _tools_that_were_shortened(entries) == set()

    def test_a_tool_that_owns_the_word_is_not_mistaken_for_one(self) -> None:
        """The reserved key is recognised by its shape, not by its spelling."""
        entries = [_entry("strings", json.dumps({BOOKKEEPING_KEY: "a value of the tool's own"}))]

        assert _tools_that_were_shortened(entries) == set()

    def test_nothing_at_all_names_nothing(self) -> None:
        assert _tools_that_were_shortened(None) == set()
        assert _tools_that_were_shortened([]) == set()


class TestTheModelAndTheLedgerReadTheSameAnswer:
    """The premise the grounding rule rests on, driven rather than assumed.

    ``_apply_output_guardrail`` returns one string. The tool wrapper hands that
    string to the model and passes the same one to ``recorder.record``, which
    parses ``structured`` out of it. So the document the ledger holds is the
    document the model read, and a value in neither is one the model never saw.
    """

    def test_the_guardrail_hands_back_one_string_both_sides_read(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.schemas.evidence import parse_structured

        toolkit = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
        toolkit._max_output_chars = 6000
        toolkit._output_guardrail = None
        toolkit._truncation_ledger = None

        document = {
            "read_path": "/staging/sample.bin",
            "total": 3876,
            "strings": [f"a string number {index:04d} of the answer" for index in range(300)],
        }
        answer = toolkit._apply_output_guardrail(json.dumps(document))

        # One string: what the model reads parses, and what the ledger stores
        # is parsed from that same string.
        model_read = json.loads(answer)
        stored = parse_structured(answer)
        assert stored == model_read
        assert len(answer) <= 6000
        assert model_read["read_path"] == "/staging/sample.bin"
        assert len(model_read["strings"]) < 300
        assert _tools_that_were_shortened([_entry("strings", answer)]) == {"strings"}

    def test_a_value_the_shortener_dropped_is_in_neither(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit
        from maljan.schemas.evidence import parse_structured

        toolkit = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
        toolkit._max_output_chars = 2000
        toolkit._output_guardrail = None
        toolkit._truncation_ledger = None

        document = {"strings": [f"marker_{index:04d}" for index in range(400)]}
        answer = toolkit._apply_output_guardrail(json.dumps(document))
        kept = json.loads(answer)["strings"]
        dropped = next(
            name for name in (f"marker_{index:04d}" for index in range(400)) if name not in kept
        )

        assert dropped not in answer
        assert dropped not in json.dumps(parse_structured(answer))
