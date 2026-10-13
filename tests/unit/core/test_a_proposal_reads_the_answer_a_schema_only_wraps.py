"""A proposal reads the confirmed answer when the tool's outputSchema only wraps a text.

An MCP server describes a tool that returns a string with an outputSchema of
one string field (``{"result": <the text>}``). Such a schema says nothing of
the answer's shape; when the confirmed probe answer's text is JSON, that JSON is
what the run reads (the text's JSON wins over a structure that only wraps it),
and it is what the proposal reads too. Any schema that says more is read as
before, and so is a wrapped answer whose text is not JSON.
"""

from __future__ import annotations

import asyncio
import json
import runpy
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.mcp_client import StructuredAnswer
from maljan.core.declaration_proposals import ProbeCall, propose, propose_tool

ROOT = Path(__file__).resolve().parents[3]
REP_STUB = ROOT / "tests" / "fixtures" / "validation" / "rep_stub.py"

RECORD = {
    "data": {
        "attributes": {
            "stats": {"malicious": 3, "total": 60},
            "label": "some.family",
            "first_seen": "2026-01-01",
        }
    }
}


def _wrapper(field: str = "result") -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {field: {"title": field.title(), "type": "string"}},
        "required": [field],
    }


def _definition(output_schema: Any) -> dict[str, Any]:
    return {
        "name": "lookup_hash",
        "description": "Look up a file by its SHA-256 and answer the service's record for it.",
        "inputSchema": {
            "type": "object",
            "properties": {"sha256": {"type": "string"}},
            "required": ["sha256"],
        },
        "outputSchema": output_schema,
        "annotations": {"readOnlyHint": True},
    }


def _reputation(proposal: Any) -> dict[str, Any]:
    return dict(proposal.facts.get("reputation") or {})


def _stub_definition() -> Any:
    server = runpy.run_path(str(REP_STUB))["server"]
    return next(t for t in asyncio.run(server.list_tools()) if t.name == "lookup_hash")


class TestAWrappedAnswerIsRead:
    def test_the_shipped_sdk_s_wrapper_is_read_through(self) -> None:
        definition = _stub_definition()
        assert set((definition.outputSchema or {}).get("properties") or {}) == {"result"}
        proposal = propose_tool(definition, answer={"result": json.dumps(RECORD)})
        assert proposal is not None
        assert proposal.facts.get("kind") == "reputation"
        rep = _reputation(proposal)
        assert rep.get("malicious") == "/data/attributes/stats/malicious"
        assert rep.get("total") == "/data/attributes/stats/total"

    @pytest.mark.parametrize("field", ["result", "text", "answer"])
    def test_whatever_the_one_field_is_called(self, field: str) -> None:
        proposal = propose_tool(_definition(_wrapper(field)), answer={field: json.dumps(RECORD)})
        assert proposal is not None and proposal.facts.get("kind") == "reputation"
        evidence = proposal.fields["reputation"].evidence
        assert any("wraps" in text for text in evidence), evidence

    def test_the_text_or_its_json_is_read_the_same(self) -> None:
        held = [
            propose_tool(_definition(_wrapper()), answer=answer)
            for answer in ({"result": json.dumps(RECORD)}, json.dumps(RECORD), RECORD)
        ]
        assert all(p is not None for p in held)
        assert len({json.dumps(p.as_dict(), sort_keys=True) for p in held if p}) == 1

    def test_through_the_probe_s_own_answer(self) -> None:
        raw = StructuredAnswer(json.dumps(RECORD))
        raw.structured_content = {"result": json.dumps(RECORD)}
        call = ProbeCall(tool="lookup_hash", arguments={"sha256": "0" * 64}, remote=False)
        out = propose([_definition(_wrapper())], answers={"lookup_hash": (call, raw)})
        assert out["tools"]["lookup_hash"]["facts"].get("kind") == "reputation"


class TestEverythingElseIsReadAsBefore:
    def _before(self, schema: Any, answer: Any) -> dict[str, Any]:
        with_answer = propose_tool(_definition(schema), answer=answer)
        without = propose_tool(_definition(schema))
        assert with_answer is not None and without is not None
        assert with_answer.as_dict() == without.as_dict()
        return with_answer.as_dict()

    def test_a_wrapped_text_that_is_not_json(self) -> None:
        held = self._before(_wrapper(), {"result": "not found"})
        assert "reputation" not in held["facts"]

    @pytest.mark.parametrize(
        "schema",
        [
            # Two fields: the schema says something.
            {
                "type": "object",
                "properties": {"result": {"type": "string"}, "status": {"type": "string"}},
            },
            # One field that is not a text.
            {"type": "object", "properties": {"result": {"type": "object"}}},
            {"type": "object", "properties": {"count": {"type": "integer"}}},
            # One text field with a structure of its own.
            {"type": "object", "properties": {"result": {"type": "string", "anyOf": []}}},
        ],
        ids=["two-fields", "an-object-field", "an-integer-field", "a-composed-field"],
    )
    def test_a_schema_that_says_more(self, schema: dict[str, Any]) -> None:
        self._before(schema, {"result": json.dumps(RECORD)})

    def test_no_answer_reads_the_wrapper_as_before(self) -> None:
        proposal = propose_tool(_definition(_wrapper()))
        assert proposal is not None and "reputation" not in proposal.facts


def test_a_large_wrapped_answer_is_read_in_linear_time() -> None:
    import time

    def _timed(n: int) -> float:
        answer = {"result": json.dumps({**RECORD, "rows": [{"name": "x"}] * n})}
        start = time.perf_counter()
        propose_tool(_definition(_wrapper()), answer=answer)
        return time.perf_counter() - start

    small, large = _timed(2_000), _timed(20_000)
    assert large < max(small * 30, 0.5)
