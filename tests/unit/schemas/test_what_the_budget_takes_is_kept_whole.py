"""What the byte budget or the structure eviction takes from an entry is kept whole.

The budget blanks an agent's later outputs once its kept bytes pass the budget,
and the eviction drops structures a server returned beside a prose answer. Both
decisions are unchanged; before either takes a part, the part is handed to the
job's store and the entry references it with the key, the byte length and the
SHA-256. A run with no store keeps nothing and its entries dump as before. An
upload that fails is stated on the reference and the run goes on.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.schemas.evidence import LedgerEntry, apply_budget, fit_structures_to_budget
from maljan.schemas.evidence_spill import EvidenceSpill


class _Store:
    def __init__(self, *, fails: bool = False) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.fails = fails

    def put(self, sha256: str, blob: bytes, content_type: str) -> str:
        if self.fails:
            raise ConnectionError("the store refused the connection")
        key = f"evidence/job/{sha256}"
        self.objects[key] = (blob, content_type)
        return key


def _recorder(store: _Store | None) -> EvidenceRecorder:
    return EvidenceRecorder("static", spill=EvidenceSpill(store.put) if store else None)


def _entry(recorder: EvidenceRecorder, output: str, *, beside: dict | None = None) -> LedgerEntry:
    return recorder.record(
        tool="strings", args={}, server="s", output=output, structured_content=beside
    )


class TestTheBudget:
    def test_a_blanked_output_is_kept_whole_and_referenced(self) -> None:
        store = _Store()
        recorder = _recorder(store)
        first, second = _entry(recorder, "a" * 60), _entry(recorder, "b" * 60)

        trimmed, _spent = apply_budget([first, second], 100)

        assert trimmed == 1
        assert second.output == "" and second.truncated is True
        (ref,) = second.spilled or []
        blob = ("b" * 60).encode()
        assert ref == {
            "part": "output",
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "key": f"evidence/job/{hashlib.sha256(blob).hexdigest()}",
        }
        assert store.objects[ref["key"]] == (blob, "text/plain; charset=utf-8")
        assert first.spilled is None, "an entry the budget left alone references nothing"

    def test_a_structure_the_server_gave_is_its_own_part_and_a_parsed_one_is_not(self) -> None:
        store = _Store()
        recorder = _recorder(store)
        keep = _entry(recorder, "x" * 90)
        beside = _entry(recorder, "plain prose answer", beside={"rows": [1, 2, 3]})
        parsed = _entry(recorder, json.dumps({"k": "v" * 40}))

        apply_budget([keep, beside, parsed], 95)

        assert {ref["part"] for ref in beside.spilled or []} == {"output", "structured"}
        structured = next(ref for ref in beside.spilled or [] if ref["part"] == "structured")
        assert store.objects[structured["key"]][0] == b'{"rows": [1, 2, 3]}'
        assert store.objects[structured["key"]][1] == "application/json"
        assert [ref["part"] for ref in parsed.spilled or []] == ["output"]

    def test_a_failed_upload_is_stated_and_the_budget_still_applies(self) -> None:
        recorder = _recorder(_Store(fails=True))
        first, second = _entry(recorder, "a" * 60), _entry(recorder, "b" * 60)

        apply_budget([first, second], 100)

        assert second.output == "" and second.truncated is True
        (ref,) = second.spilled or []
        assert "key" not in ref
        assert ref["error"] == "ConnectionError: the store refused the connection"
        assert ref["bytes"] == 60 and len(ref["sha256"]) == 64

    def test_without_a_store_nothing_is_kept_and_the_dump_is_unchanged(self) -> None:
        recorder = _recorder(None)
        first, second = _entry(recorder, "a" * 60), _entry(recorder, "b" * 60)

        apply_budget([first, second], 100)

        assert second.spilled is None
        assert "spilled" not in second.model_dump(mode="json")

    def test_an_entry_copied_with_its_store_shares_the_store(self) -> None:
        store = _Store()
        entry = _entry(_recorder(store), "a")

        copied = copy.deepcopy(entry)

        assert copied._spill is entry._spill
        assert "spilled" not in entry.model_dump(mode="json")


class TestTheEviction:
    @pytest.mark.parametrize("as_dump", [False, True])
    def test_an_evicted_structure_is_kept_whole(self, as_dump: bool) -> None:
        store = _Store()
        recorder = _recorder(store if not as_dump else None)
        text = _entry(recorder, "y" * 80)
        beside = _entry(recorder, "prose", beside={"wide": "z" * 40})
        entries: list[Any] = [text, beside]
        if as_dump:
            entries = [entry.model_dump(mode="json") for entry in entries]

        dropped = fit_structures_to_budget(entries, 100, spill=EvidenceSpill(store.put))

        assert dropped == 1
        held = entries[1]["spilled"] if as_dump else entries[1].spilled
        (ref,) = held
        assert ref["part"] == "structured"
        assert json.loads(store.objects[ref["key"]][0]) == {"wide": "z" * 40}
        output = entries[1]["output"] if as_dump else entries[1].output
        assert output == "prose", "the eviction never touches a text"

    def test_with_no_store_an_eviction_over_dumps_is_unchanged(self) -> None:
        recorder = _recorder(None)
        entries = [
            _entry(recorder, "y" * 80).model_dump(mode="json"),
            _entry(recorder, "prose", beside={"wide": "z" * 40}).model_dump(mode="json"),
        ]

        fit_structures_to_budget(entries, 100)

        assert entries[1]["structured"] is None
        assert "spilled" not in entries[1]
