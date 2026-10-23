"""An answer the guardrail cut, or a structure the entry cannot keep, is kept whole.

The tool-output guardrail decides how much of an answer the model reads, and
the entry keeps exactly that. Where the job has a store, the answer as the tool
gave it is kept there too and the entry references it: when the guardrail cut,
shortened or summarised it, or the conversation had no room for it. A
structured answer the server returned beside a prose text that the entry does
not keep (too large for the call, or the answer was cut) is kept the same way.
What the model is handed is byte-identical with and without a store.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.mcp_client import MCPLangChainToolkit, with_structured_content
from maljan.llm.context_window import (
    note_answer_not_shown,
    note_answer_structure,
    note_answer_whole,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.evidence_spill import EvidenceSpill

LISTING = "void FUN_00401000(void) {\n  int counter = 0;\n  return;\n}\n" * 400
DOCUMENT = json.dumps({"rows": [{"index": i, "value": "v" * 30} for i in range(400)]})


class _Store:
    def __init__(self, *, fails: bool = False) -> None:
        self.objects: dict[str, bytes] = {}
        self.fails = fails

    def put(self, sha256: str, blob: bytes, content_type: str) -> str:
        if self.fails:
            raise TimeoutError("the store did not answer")
        self.objects[f"evidence/job/{sha256}"] = blob
        return f"evidence/job/{sha256}"


def _ghidra(limit: int) -> Any:
    from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

    client = GhidraHTTPClient.__new__(GhidraHTTPClient)
    client._max_output_chars = limit
    client._output_guardrail = None
    client._truncation_ledger = None
    client._context_budget = None
    return client


def _toolkit(limit: int) -> MCPLangChainToolkit:
    return MCPLangChainToolkit(None, max_output_chars=limit)


def _recorded(answer: Any, store: _Store | None) -> tuple[str, LedgerEntry]:
    def lookup(target: str) -> str:
        """Look a target up."""
        return answer()

    tool = StructuredTool.from_function(func=lookup, name="lookup")
    recorder = EvidenceRecorder(
        "analyst", spill=EvidenceSpill(store.put) if store is not None else None
    )
    (wrapped,) = record_tools([tool], recorder)
    handed = wrapped.invoke({"target": "x"})
    (entry,) = recorder.entries
    return str(handed), entry


def _both(answer: Any) -> tuple[_Store, str, LedgerEntry, str, LedgerEntry]:
    store = _Store()
    handed, entry = _recorded(answer, store)
    bare_handed, bare = _recorded(answer, None)
    return store, handed, entry, bare_handed, bare


def _same_but_the_reference(entry: LedgerEntry, bare: LedgerEntry) -> None:
    kept = entry.model_dump(mode="json")
    plain = bare.model_dump(mode="json")
    kept.pop("spilled", None)
    for row in (kept, plain):
        row.pop("started_at"), row.pop("duration_ms")
    assert kept == plain, "the entry keeps exactly what it kept"
    assert "spilled" not in plain


class TestTheAnswer:
    def test_a_character_cut_keeps_the_whole_answer(self) -> None:
        client = _ghidra(4000)

        store, handed, entry, bare_handed, bare = _both(
            lambda: client._apply_output_guardrail(LISTING)
        )

        assert handed == bare_handed, "the model is handed the same text"
        (ref,) = entry.spilled or []
        assert ref["part"] == "answer"
        assert store.objects[ref["key"]] == LISTING.encode()
        assert ref["bytes"] == len(LISTING.encode())
        assert ref["sha256"] == hashlib.sha256(LISTING.encode()).hexdigest()
        assert entry.truncated is True and entry.chars_dropped > 0
        _same_but_the_reference(entry, bare)

    def test_a_shortened_document_keeps_the_whole_document(self) -> None:
        toolkit = _toolkit(3000)

        store, handed, entry, bare_handed, bare = _both(
            lambda: toolkit._apply_output_guardrail(DOCUMENT)
        )

        assert handed == bare_handed
        (ref,) = entry.spilled or []
        assert store.objects[ref["key"]] == DOCUMENT.encode()
        _same_but_the_reference(entry, bare)

    def test_an_answer_with_no_room_keeps_the_whole_answer(self) -> None:
        def no_room() -> str:
            note_answer_whole(LISTING)
            note_answer_not_shown(len(LISTING))
            return "There is no room left in this conversation for the answer."

        store, handed, entry, bare_handed, bare = _both(no_room)

        assert handed == bare_handed
        (ref,) = entry.spilled or []
        assert ref["part"] == "answer"
        assert store.objects[ref["key"]] == LISTING.encode()
        _same_but_the_reference(entry, bare)

    def test_an_answer_that_fits_or_is_only_compacted_keeps_nothing(self) -> None:
        spaced = json.dumps({"rows": list(range(300))}, indent=4)
        compact = len(json.dumps({"rows": list(range(300))}, separators=(",", ":")))

        for answer in (
            lambda: _ghidra(len(LISTING) * 2)._apply_output_guardrail(LISTING),
            lambda: _toolkit(compact + 200)._apply_output_guardrail(spaced),
        ):
            store, _handed, entry, _bare_handed, _bare = _both(answer)
            assert entry.spilled is None
            assert store.objects == {}
            assert entry.chars_dropped == 0

    def test_a_failed_upload_is_stated_and_the_call_goes_on(self) -> None:
        client = _ghidra(4000)

        handed, entry = _recorded(
            lambda: client._apply_output_guardrail(LISTING), _Store(fails=True)
        )

        (ref,) = entry.spilled or []
        assert ref["error"] == "upload_failed (TimeoutError)"
        assert "key" not in ref
        assert entry.output in handed


class TestTheServersStructure:
    CONTENT = {"matches": [{"offset": i, "name": "n" * 20} for i in range(50)]}

    def _answer(self, limit: int) -> Any:
        def answer() -> str:
            note_answer_structure(self.CONTENT)
            return with_structured_content("three matches found", self.CONTENT, limit)

        return answer

    def test_a_structure_too_large_for_the_call_is_kept_whole(self) -> None:
        store, handed, entry, bare_handed, bare = _both(self._answer(100))

        assert handed == bare_handed
        assert entry.structured is None
        (ref,) = entry.spilled or []
        assert ref["part"] == "structured_content"
        assert json.loads(store.objects[ref["key"]]) == self.CONTENT
        _same_but_the_reference(entry, bare)

    def test_a_structure_the_entry_keeps_is_not_kept_twice(self) -> None:
        store, _handed, entry, _bare_handed, _bare = _both(self._answer(100_000))

        assert entry.structured == self.CONTENT
        assert entry.spilled is None
        assert store.objects == {}

    def test_a_structure_that_only_repeats_a_json_text_is_not_kept(self) -> None:
        def answer() -> str:
            note_answer_structure({"rows": [1, 2]})
            return json.dumps({"rows": [1, 2]})

        store, _handed, entry, _bare_handed, _bare = _both(answer)

        assert entry.spilled is None and store.objects == {}
