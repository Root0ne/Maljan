"""A value is found in the evidence however the evidence spells it.

A tool answers in JSON, so a quote inside a string it returned is stored ``\\"``
and a backslash ``\\\\``; the triage pack quotes a decoded string on one line
and writes a quote, a control character and a final backslash as escapes. A
judge reads either and writes the value back plainly, and a search for the
plain value in the escaped text told it that strings the pack had shown it
"appear nowhere in the evidence". Each escaping form is pinned here, through
the real recorder where a tool's answer is involved.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.run_evidence_corpus import CorpusState, RunEvidenceCorpus
from maljan.pipeline.validation import Haystack, validate_verdict_bundle
from maljan.schemas.stix_models import Bundle, Indicator
from maljan.utils.written_forms import pack_escaped, written_forms

# Invented values of the shapes that were refused: a command line with a
# quoted argument, and a Windows path with format specifiers after it.
QUOTED_COMMAND = '/c query "Example Operators" /all'
PATH_WITH_FORMAT = "C:\\Windows\\System32\\examplehost.exe %s,%s"
REGISTRY_PATH = "Software\\ExampleVendor\\Settings"


def _decoded_answer(*strings: str) -> str:
    """A decoded-strings answer as a tool returns it: JSON text."""
    return json.dumps(
        {
            "strings": [
                {"kind": "decoded", "string": value, "encoding": "UTF-16LE"} for value in strings
            ]
        }
    )


def _searched(*answers: str) -> list[str]:
    """What a check searches: the recorder's corpus, lower-cased as it keeps it."""
    corpus = RunEvidenceCorpus(1 << 20)
    recorder = EvidenceRecorder("static", corpus=corpus)
    for answer in answers:
        recorder.record(tool="floss", args={}, server="analysis", output=answer)
    return list(corpus.parts())


def _absences(pattern: str, searched: list[str]) -> list[Any]:
    bundle = Bundle(objects=[Indicator(pattern=pattern)])  # type: ignore[list-item]
    found = validate_verdict_bundle(bundle, set(), searched=searched, corpus_state=CorpusState())
    return [v for v in found if v.code == "stix.ungrounded_indicator"]


class TestTheRefusalReproduced:
    """The plain value is not a substring of the text the tool answered."""

    def test_a_quote_is_escaped_in_the_answer(self) -> None:
        (text,) = _searched(_decoded_answer(QUOTED_COMMAND))
        assert QUOTED_COMMAND.lower() not in text

    def test_a_backslash_is_doubled_in_the_answer(self) -> None:
        (text,) = _searched(_decoded_answer(PATH_WITH_FORMAT))
        assert PATH_WITH_FORMAT.lower() not in text


class TestAJsonAnswer:
    def test_a_value_with_a_quote_is_grounded(self) -> None:
        searched = _searched(_decoded_answer(QUOTED_COMMAND))
        pattern = "[process:command_line = '" + QUOTED_COMMAND + "']"

        assert _absences(pattern, searched) == []

    def test_a_value_with_backslashes_is_grounded(self) -> None:
        searched = _searched(_decoded_answer(PATH_WITH_FORMAT))
        # Written with the STIX escape for a backslash, as a careful judge does.
        pattern = "[process:command_line = '" + PATH_WITH_FORMAT.replace("\\", "\\\\") + "']"

        assert _absences(pattern, searched) == []

    def test_a_value_with_single_backslashes_is_grounded(self) -> None:
        searched = _searched(_decoded_answer(PATH_WITH_FORMAT))
        pattern = "[process:command_line = '" + PATH_WITH_FORMAT + "']"

        assert _absences(pattern, searched) == []

    def test_a_non_ascii_value_escaped_by_the_answer_is_grounded(self) -> None:
        value = "C:\\Users\\Público\\example.dat"
        answer = json.dumps({"strings": [{"string": value}]}, ensure_ascii=True)
        searched = _searched(answer)
        assert "público" not in searched[0]

        pattern = "[process:command_line = '" + value.replace("\\", "\\\\") + "']"

        assert _absences(pattern, searched) == []

    def test_a_non_ascii_capital_escaped_before_the_fold_is_grounded(self) -> None:
        """The corpus escapes, then folds: ``Ú`` stays ``\\u00da``, not ``\\u00fa``."""
        value = "C:\\Users\\ÚLTIMO\\example.dat"
        answer = json.dumps({"strings": [{"string": value}]}, ensure_ascii=True)
        searched = _searched(answer)

        pattern = "[process:command_line = '" + value.replace("\\", "\\\\") + "']"

        assert _absences(pattern, searched) == []

    def test_a_value_the_model_copied_with_its_json_escapes_is_grounded(self) -> None:
        searched = _searched(_decoded_answer(QUOTED_COMMAND))
        copied = json.dumps(QUOTED_COMMAND)[1:-1]
        pattern = "[process:command_line = '" + copied.replace("\\", "\\\\") + "']"

        assert _absences(pattern, searched) == []

    def test_a_value_the_run_never_saw_is_still_refused(self) -> None:
        searched = _searched(_decoded_answer(QUOTED_COMMAND))
        pattern = "[process:command_line = '/c query \"Other Operators\" /all']"

        assert len(_absences(pattern, searched)) == 1


class TestThePackLine:
    """Each escape the pack writes a decoded string with."""

    @pytest.mark.parametrize(
        "value",
        [
            QUOTED_COMMAND,
            "first line\nsecond line",
            "a\ttab and a\rreturn",
            "bell\x07inside",
            "Software\\ExampleVendor\\",
            PATH_WITH_FORMAT,
        ],
    )
    def test_the_pack_spelling_is_one_of_the_forms(self, value: str) -> None:
        line = f'routine 0x1000: "{pack_escaped(value)}"@0x1010'.lower()

        assert Haystack([line]).__contains__(value.lower())

    def test_a_final_backslash_is_written_as_its_code(self) -> None:
        assert pack_escaped("Software\\ExampleVendor\\") == "Software\\ExampleVendor\\x5c"

    def test_the_pack_line_writes_what_the_search_reads(self) -> None:
        from maljan.pipeline.triage_pack import _quoted

        assert _quoted(QUOTED_COMMAND) == f'"{pack_escaped(QUOTED_COMMAND)}"'


class TestTheForms:
    def test_the_plain_value_comes_first(self) -> None:
        assert written_forms(REGISTRY_PATH)[0] == REGISTRY_PATH

    def test_a_value_with_nothing_to_escape_has_one_form(self) -> None:
        assert written_forms("example.invalid") == ("example.invalid",)

    def test_the_forms_are_distinct(self) -> None:
        forms = written_forms(QUOTED_COMMAND)
        assert len(forms) == len(set(forms))

    def test_an_empty_value_has_none(self) -> None:
        assert written_forms("") == ()

    def test_a_whole_value_search_reads_every_form(self) -> None:
        text = _searched(_decoded_answer(REGISTRY_PATH))[0]

        assert Haystack([text]).holds_value(REGISTRY_PATH.lower())
