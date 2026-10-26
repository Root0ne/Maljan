"""A report section is shown what the ledger holds of each thing its text calls absent.

A stored run's body said a routine's body was "absent from the evidence I hold"
and that three indirect slots "remain unresolved", while the ledger held the
routine's decompile and an index object naming each slot. The writers of the
key findings, the flow and the background work from the analysts' claims, which
carried those absences as each analyst's own view, and the one question asked
named the entry without showing what it held, so the writer could only reword.

Now the check reads a routine's body, code or listing said to be absent as the
routine not read, reads past an aside in the subject, and reads an address
called unresolved against the objects that pair it with a name. Its question
shows the routine's code or the naming object; the finding recorded is the
message alone. A claim shown to a writer carries the platform's note of what
the ledger holds of anything it calls absent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from maljan.pipeline.validation import (
    ABSENCE_CONTRADICTS_LEDGER_CODE,
    ABSENCE_HELD_LEAD,
    EntryTexts,
    absence_holders_note,
    feedback_text,
    ledger_absence_contradictions,
)
from maljan.reporting.composer import _bundle_text
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.narrative_agent import NarrativeAgent, build_prompt_text
from maljan.reporting.question_round import question_prompt_text
from maljan.schemas.evidence import build_entry
from tests.linear_cost import TIME_RATIO_LIMIT, cpu_seconds

APPEND = "void FUN_0000b984(long *param_1,long param_2)\n{\n  FUN_0000b9cc(param_1,param_2);\n}"
MAPPER = "long FUN_0000b670(long *param_1)\n{\n  return (*_DAT_00010dd0)(param_1);\n}"


def _entry(number: int, tool: str, args: dict[str, Any], output: str, ok: bool = True) -> Any:
    entry = build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="reverser",
        server="ghidra",
        tool=tool,
        args=args,
        output=output,
    )
    return entry if ok else entry.model_copy(update={"ok": False})


def _entries(*extra: Any) -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry(
                10,
                "batch_decompile",
                {"functions": "0xb984,0xb670"},
                json.dumps({"0xb984": APPEND, "0xb670": MAPPER}),
            ),
            _entry(
                11,
                "function_index",
                {},
                json.dumps(
                    {
                        "rows": [
                            {"function": "0x3868", "slot_names": {"0x10c60": "CreateMutexW"}},
                            {"function": "0x5750", "calls_unnamed": {"0x10de8": 2}},
                        ]
                    }
                ),
            ),
            *extra,
        ]
    )


def _found(text: str, entries: EntryTexts | None = None) -> list[Any]:
    return ledger_absence_contradictions({"body": text}, entries or _entries())


class TestARoutinesBodyCalledAbsent:
    def test_a_body_not_in_the_evidence_is_a_routine_not_read(self) -> None:
        (found,) = _found("The body of 0xb670 is not in the evidence, so its use is not known.")

        assert found.code == ABSENCE_CONTRADICTS_LEDGER_CODE
        assert "0xb670 was not read" in found.message
        assert "ev_0010" in found.message

    def test_an_aside_in_the_subject_is_read_past(self) -> None:
        (found,) = _found(
            "The body of routine 0xb984, which the claims say appends the host fields to the "
            "request body, is absent from the evidence I hold."
        )

        assert "0xb984 was not read" in found.message

    def test_the_question_shows_the_routines_code_and_the_finding_does_not(self) -> None:
        (found,) = _found("The body of 0xb670 is not in the evidence.")
        asked = feedback_text([found])

        assert "holds the code of 0xb670" in asked
        assert "_DAT_00010dd0" in asked
        assert "_DAT_00010dd0" not in found.message
        assert "_DAT_00010dd0" not in json.dumps(found.to_dict())

    def test_a_routine_no_entry_decompiled_is_not_judged(self) -> None:
        assert _found("The body of 0xc19c is not in the evidence.") == []

    def test_a_decompile_that_failed_holds_nothing(self) -> None:
        failed = EntryTexts.from_ledger(
            [_entry(10, "batch_decompile", {}, json.dumps({"0xb670": MAPPER}), ok=False)]
        )

        assert _found("The body of 0xb670 is not in the evidence.", failed) == []

    def test_my_rows_are_the_ledger(self) -> None:
        (found,) = _found("Routine 0xb984 is not in my rows.")

        assert "0xb984 is not in the ledger" in found.message


class TestAnAddressCalledUnresolved:
    def test_an_object_that_pairs_the_address_with_a_name_contradicts_it(self) -> None:
        (found,) = _found("The indirect slots 0x10c60 and 0x10de8 remain unresolved.")

        assert "0x10c60 is unresolved" in found.message
        assert "0x10de8" not in found.message.split("(")[0]
        asked = feedback_text([found])
        assert "names 0x10c60" in asked
        assert "CreateMutexW" in asked
        assert "CreateMutexW" not in found.message

    def test_an_address_no_object_names_is_not_judged(self) -> None:
        assert _found("Slot 0x10de8 is unresolved.") == []

    def test_a_decompilers_generic_name_is_no_name(self) -> None:
        generic = EntryTexts.from_ledger(
            [_entry(12, "function_index", {}, json.dumps({"slot": "0x10e00", "name": "FUN_10e00"}))]
        )

        assert _found("Slot 0x10e00 is unresolved.", generic) == []

    def test_a_statement_with_no_address_is_not_judged(self) -> None:
        assert _found("The sleep constants are not established, and the slot is unresolved.") == []


class TestAClaimShownToAWriter:
    def test_a_claim_calling_a_decompiled_routine_unread_carries_the_note(self) -> None:
        note = absence_holders_note("Routine 0xb984 has not been read.", _entries())

        assert note.startswith(f" ({ABSENCE_HELD_LEAD}")
        assert "a decompile of 0xb984 is in ev_0010" in note
        # A describing word before the routine may name another object.
        assert (
            absence_holders_note("The append routine 0xb984 has not been read.", _entries()) == ""
        )

    def test_a_claim_calling_a_named_slot_unresolved_carries_the_naming_object(self) -> None:
        note = absence_holders_note("Slots 0x10c60 and 0x10de8 are unresolved.", _entries())

        assert "names 0x10c60" in note
        assert "CreateMutexW" in note
        assert "0x10de8" not in note

    def test_a_claim_the_ledger_does_not_contradict_carries_none(self) -> None:
        assert absence_holders_note("Routine 0xb984 appends a field.", _entries()) == ""
        assert absence_holders_note("Routine 0xb984 has not been read.", None) == ""

    def test_a_sections_claims_carry_it(self) -> None:
        bundle = {
            "claims": [
                {"claim": "Routine 0xb984 has not been read.", "evidence_ref": "ev_0011"},
                {"claim": "Routine 0xb670 maps a view.", "evidence_ref": "ev_0010"},
            ]
        }
        text = _bundle_text("payloads", bundle, _entries())
        lines = [line for line in text.splitlines() if line.startswith("- ")]

        assert ABSENCE_HELD_LEAD in lines[0]
        assert ABSENCE_HELD_LEAD not in lines[1]

    def test_the_narratives_claims_carry_it_when_it_is_handed_the_entries(self) -> None:
        claim = SimpleNamespace(
            claim="Routine 0xb984 has not been read.", evidence_ref="ev_0011", confidence=0.8
        )
        isrs = {"reverser": SimpleNamespace(agent_id="reverser", claims=[claim])}
        report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))

        assert ABSENCE_HELD_LEAD in build_prompt_text(report, isrs, _entries())
        assert ABSENCE_HELD_LEAD not in build_prompt_text(report, isrs)


def _index_entry(number: int, tool: str, payload: Any) -> Any:
    return _entry(number, tool, {}, json.dumps(payload))


def _unresolved(sentence: str, *entries: Any) -> list[Any]:
    return _found(sentence, EntryTexts.from_ledger(list(entries)))


class TestWhatNamesAnAddress:
    def test_one_address_beside_one_name_field_names_it(self) -> None:
        index = _index_entry(
            12, "function_index", {"rows": [{"name": "wsprintfA", "slot": "0x10df0"}]}
        )

        (found,) = _unresolved("Slot 0x10df0 is unresolved.", index)
        assert "wsprintfA" in feedback_text([found])

    def test_an_object_of_two_addresses_names_neither(self) -> None:
        index = _index_entry(
            12, "function_index", {"name": "CreateMutexW", "slot": "0x10c60", "named_at": "0x9af6"}
        )

        assert _unresolved("Slot 0x10c60 is unresolved.", index) == []

    def test_a_threads_start_beside_the_api_that_starts_it_names_nothing(self) -> None:
        index = _index_entry(12, "function_index", {"started": "0xb670", "through": "CreateThread"})

        assert _unresolved("Routine 0xb670 remains unidentified.", index) == []
        assert absence_holders_note("Routine 0xb670 remains unidentified.", _entries(index)) == ""

    def test_a_decoded_string_beside_its_offset_names_nothing(self) -> None:
        index = _index_entry(12, "floss", {"strings": [{"string": "AppData", "offset": "0x7b98"}]})

        assert _unresolved("Routine 0x7b98 remains unidentified.", index) == []

    def test_a_string_the_sample_made_is_no_name_whatever_its_key_ends_with(self) -> None:
        index = _index_entry(
            12, "function_index", {"offset": "0x4050a0", "task_name": "Updater_v2"}
        )

        assert _unresolved("Address 0x4050a0 is unresolved.", index) == []

    def test_the_api_a_hash_resolves_to_names_it(self) -> None:
        index = _index_entry(
            12, "emulate_hash_batch", {"api_name": "MessageBoxA", "computed_hash": "0x572d5d8e"}
        )

        assert len(_unresolved("Value 0x572d5d8e is unresolved.", index)) == 1

    def test_the_question_shows_one_object_per_holder(self) -> None:
        rows = [{"name": "CreateMutexW", "slot": "0x10c60", "row": n} for n in range(50)]
        index = _index_entry(12, "function_index", {"rows": rows, "map": {"0x10c60": "X"}})
        other = _index_entry(13, "function_index", {"0x10c60": "CreateMutexW"})

        (found,) = _unresolved("Slot 0x10c60 is unresolved.", index, other)
        assert found.shown.count(" names 0x10c60: ") == 2

    def test_an_answers_own_fields_beside_an_address_name_nothing(self) -> None:
        index = _index_entry(
            12, "decode_string_blobs", {"tool": "decode_string_blobs", "image_base": "0x10000"}
        )
        mixed = _index_entry(13, "decode_string_blobs", {"tool": "Blobs_v2", "0x10c60": "Blobs_v2"})

        assert _unresolved("Address 0x10000 is unresolved.", index) == []
        # Not a table keyed by address: a key that is no address is in it.
        assert _unresolved("Slot 0x10c60 is unresolved.", mixed) == []

    def test_the_holders_are_in_ledger_order_whatever_the_hash_seed(self) -> None:
        script = (
            "import json\n"
            "from maljan.pipeline.validation import EntryTexts, ledger_absence_contradictions\n"
            "from maljan.schemas.evidence import build_entry\n"
            "ids = [f'ev_{n:04d}' for n in (40, 7, 23, 3, 31, 12, 18, 5)]\n"
            "ledger = [build_entry(entry_id=i, seq=n, agent='a', server='s', tool='function_index',"
            " args={}, output=json.dumps({'0x10c60': 'CreateMutexW'}))\n"
            "    for n, i in enumerate(ids)]\n"
            "(found,) = ledger_absence_contradictions({'body': 'Slot 0x10c60 is unresolved.'},"
            " EntryTexts.from_ledger(ledger))\n"
            "print(found.message)\n"
        )
        root = Path(__file__).resolve().parents[3]
        said = set()
        for seed in ("0", "1", "2", "3"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            env["PYTHONPATH"] = os.pathsep.join(
                [str(root / "src"), str(root), env.get("PYTHONPATH", "")]
            )
            done = subprocess.run(
                [sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True
            )
            said.add(done.stdout)
        (message,) = said
        assert "ev_0040 (function_index), ev_0007 (function_index), ev_0023" in message

    def test_reading_the_names_is_linear_in_the_ledger(self) -> None:
        def ledger(objects: int) -> EntryTexts:
            rows = [{"name": f"Api{n}W", "slot": hex(0x20000 + 8 * n)} for n in range(objects)]
            return EntryTexts.from_ledger(
                [_index_entry(n, "function_index", {"rows": rows[n::8]}) for n in range(8)]
            )

        def cost(objects: int) -> float:
            entries = ledger(objects)
            return cpu_seconds(
                lambda: _found(f"Slot {hex(0x20000)} is unresolved.", replace_holds(entries)),
                repeats=3,
            )

        size = 5_000
        small = cost(size)
        assert cost(size * 4) < max(small, 0.01) * TIME_RATIO_LIMIT


def replace_holds(entries: EntryTexts) -> EntryTexts:
    """The same texts with the holdings not yet read, so each call reads them."""
    entries._holds.clear()
    return entries


class TestARoutineADescribingWordMayNameAnotherObject:
    def test_a_described_routine_is_not_judged(self) -> None:
        assert _found("The unpacked routine 0xb670 was not read.") == []
        assert _found("The dropped child routine 0xb984 is not in the evidence.") == []

    def test_a_described_slot_still_is(self) -> None:
        assert len(_found("The indirect slots 0x10c60 remain unresolved.")) == 1


class TestTheOtherPromptsCarryTheNote:
    def test_the_question_rounds_claims_carry_it(self) -> None:
        claim = SimpleNamespace(
            claim="Routine 0xb984 has not been read.", evidence_ref="ev_0011", confidence=0.8
        )
        isrs = {"reverser": SimpleNamespace(agent_id="reverser", claims=[claim])}
        report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
        ledger = list(_entries().entries.values())
        evidence = SimpleNamespace(open_questions=[])

        assert ABSENCE_HELD_LEAD in question_prompt_text(report, ["Q?"], evidence, ledger, isrs)

    def test_the_narrative_measures_the_prompt_it_sends(self) -> None:
        claim = SimpleNamespace(
            claim="Routine 0xb984 has not been read.", evidence_ref="ev_0011", confidence=0.8
        )
        isrs = {"reverser": SimpleNamespace(agent_id="reverser", claims=[claim])}
        report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
        agent = NarrativeAgent.__new__(NarrativeAgent)
        entries = _entries()
        sent = agent._build_prompt(report, "", "", isrs, entries)

        assert agent.prompt_chars(report, "", "", isrs, entries) == sum(
            len(str(m.content)) for m in sent
        )
        assert agent.prompt_chars(report, "", "", isrs, entries) > agent.prompt_chars(
            report, "", "", isrs
        )

    def test_a_sections_note_shares_the_claims_room(self) -> None:
        bundle = {"claims": [{"claim": "Routine 0xb984 has not been read.", "evidence_ref": ""}]}
        whole = _bundle_text("payloads", bundle, _entries())
        tight = _bundle_text("payloads", bundle, _entries(), item_chars=40)
        measured = _bundle_text("payloads", bundle, _entries(), item_chars=-1)

        assert ABSENCE_HELD_LEAD in whole
        assert ABSENCE_HELD_LEAD not in tight
        assert ABSENCE_HELD_LEAD not in measured
