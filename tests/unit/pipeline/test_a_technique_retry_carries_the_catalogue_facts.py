"""A retry about technique lines carries what the catalogue holds for each id, so none is looked up.

On the stored haiku8 run the analysts' validation retries made 34 ATT&CK
look-ups in the debate alone (an id's name, its tactic, whether it is
valid), each one more long-prompt turn, while fixing technique lines. The
platform holds those facts in the vendored catalogue its own check reads, so
the retry turn now states them, one line per id the answer's claims write or
the questions name; the look-up tools stay attached.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    TECHNIQUE_FACTS_LEAD,
    TECHNIQUE_LINE_UNREAD_CODE,
    UNGROUNDED_TECHNIQUE_CODE,
    Violation,
    technique_facts_note,
)
from maljan.tools import knowledge


def _claim(technique_id: str | None = None, line: str | None = None) -> Any:
    return SimpleNamespace(technique_id=technique_id, technique_line=line)


def _asked(code: str, subject: str = "") -> Violation:
    return Violation(code=code, message="asked", subject=subject)


class TestWhenTheFactsAreCarried:
    def test_no_technique_question_carries_none(self) -> None:
        asked = [_asked("isr.claim_without_confidence")]
        assert technique_facts_note(asked, [_claim("T1005")], knowledge) == ""

    def test_each_technique_question_kind_carries_them(self) -> None:
        for code in (
            CLAIM_DOES_NOT_DESCRIBE_CODE,
            UNGROUNDED_TECHNIQUE_CODE,
            TECHNIQUE_LINE_UNREAD_CODE,
            "attck.absence_claim",
        ):
            note = technique_facts_note([_asked(code)], [_claim("T1005")], knowledge)
            assert note.startswith(TECHNIQUE_FACTS_LEAD), code

    def test_a_catalogue_without_the_look_up_carries_none(self) -> None:
        asked = [_asked(UNGROUNDED_TECHNIQUE_CODE)]
        assert technique_facts_note(asked, [_claim("T1005")], object()) == ""


class TestWhatTheyHold:
    def test_a_sub_technique_names_its_parent_and_its_tactics(self) -> None:
        note = technique_facts_note(
            [_asked(UNGROUNDED_TECHNIQUE_CODE)], [_claim("T1053.005")], knowledge
        )
        line = next(row for row in note.splitlines() if row.startswith("- T1053.005"))
        assert "Scheduled Task" in line
        assert "a sub-technique of T1053 Scheduled Task/Job" in line
        assert "tactics: " in line and "persistence" in line

    def test_an_id_the_catalogue_lacks_says_so_with_its_nearest(self) -> None:
        note = technique_facts_note(
            [_asked(CLAIM_DOES_NOT_DESCRIBE_CODE, "T1055.999")], [_claim()], knowledge
        )
        line = next(row for row in note.splitlines() if row.startswith("- T1055.999"))
        assert "not a technique of the catalogue" in line
        assert "T1055" in line.split("nearest ids:")[1]

    def test_the_ids_of_every_claim_and_every_line_once_in_order(self) -> None:
        claims = [_claim("T1005"), _claim(None, "T1057, T1083 (lead)"), _claim("T1005")]
        note = technique_facts_note([_asked(TECHNIQUE_LINE_UNREAD_CODE)], claims, knowledge)
        ids = [row.split()[1].rstrip(":") for row in note.splitlines()[1:]]
        assert ids == ["T1005", "T1057", "T1083"]

    def test_an_id_the_catalogue_cannot_answer_is_left_out(self) -> None:
        class _Failing:
            @staticmethod
            def attck_lookup(tid: str) -> dict[str, Any]:
                if tid == "T1005":
                    raise RuntimeError("unreadable")
                return {"valid": True, "name": "Process Discovery", "tactics": ["discovery"]}

        note = technique_facts_note(
            [_asked(UNGROUNDED_TECHNIQUE_CODE)], [_claim("T1005"), _claim("T1057")], _Failing()
        )
        assert note.splitlines()[1:] == ["- T1057 Process Discovery; tactics: discovery"]

    def test_a_retired_id_says_its_release_and_successor_once(self) -> None:
        class _Retired:
            @staticmethod
            def attck_lookup(tid: str) -> dict[str, Any]:
                return {
                    "valid": False,
                    "reason": "retired in ATT&CK v12 and revoked by T1574.002",
                    "retired_in": "v12",
                    "revoked_by": "T1574.002",
                }

        note = technique_facts_note(
            [_asked(UNGROUNDED_TECHNIQUE_CODE)], [_claim("T1038")], _Retired()
        )
        line = note.splitlines()[1]
        assert line.count("v12") == 1 and line.count("T1574.002") == 1
        assert "revoked by T1574.002" in line

    def test_a_valid_id_the_table_has_no_row_for_is_a_technique(self) -> None:
        class _Unnamed:
            @staticmethod
            def attck_lookup(tid: str) -> dict[str, Any]:
                return {"valid": True, "name": "", "tactics": []}

        note = technique_facts_note(
            [_asked(UNGROUNDED_TECHNIQUE_CODE)], [_claim("T1700")], _Unnamed()
        )
        assert note.splitlines()[1] == "- T1700: a technique of the catalogue"
