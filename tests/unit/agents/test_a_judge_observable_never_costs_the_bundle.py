"""A cyber-observable the judge writes never breaks the parse of the rest of its bundle.

When ``file`` and ``process`` joined the bundle's object types, a judge ``file``
with no ``name`` failed the model and sent the judge's whole answer to the
text fallback — the verdict read from prose, its confidence and assessment
lost. A named ``file`` parsed and silently dropped its ``hashes``; a
``process`` silently dropped its ``name``. The stored runs show the judge
writing exactly these: a ``file`` it put in its bundle, a ``file`` with name,
size, hashes and MIME type inside an observed-data it wrote, and ``process``
objects carrying ``name`` beside ``pid`` and ``command_line``.

Now every property STIX 2.1 defines for a file or a process is modelled and
kept; a property it does not define, a value the model cannot hold, or an
object that does not parse is set aside with a recorded
``stix.unknown_object`` and the rest of the bundle is read; a file with
neither ``hashes`` nor ``name`` is a question (``stix.file_unidentified``),
not a parse failure, and one the judge keeps is not exported.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.judge_postprocess import UNKNOWN_OBJECT_CODE
from maljan.pipeline.validation import FILE_UNIDENTIFIED_CODE, validate_verdict_bundle
from maljan.schemas.stix_models import Bundle, File, Process

# The shapes the stored runs hold, as the judge or the old export wrote them.
STORED_FILE = {
    "name": "putty.exe",
    "size": 1706136,
    "type": "file",
    "hashes": {"SHA-256": "d01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87"},
    "mime_type": "application/octet-stream",
}
STORED_PROCESS = {
    "pid": 100,
    "name": "loader.exe",
    "type": "process",
    "command_line": "loader.exe /q",
}


def _answer(*extra: dict[str, Any]) -> str:
    return json.dumps(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
                *extra,
            ],
            "x_maljan_assessment": {"verdict": "Malware", "confidence": 0.85},
        }
    )


def _parse(answer: str) -> tuple[Bundle, list]:
    record: list = []
    bundle = JudgeAgent(llm=MagicMock())._bundle_from_response(answer, {}, None, record=record)
    return bundle, record


def _of(bundle: Bundle, kind: str) -> list:
    return [o for o in bundle.objects if getattr(o, "type", "") == kind]


class TestTheBundleSurvives:
    def test_a_file_with_no_name_does_not_cost_the_verdict(self) -> None:
        bundle, _record = _parse(
            _answer({"type": "file", "id": "file--1", "hashes": {"MD5": "a" * 32}})
        )

        assert bundle.x_maljan_fallback_verdict is None
        assert bundle.x_maljan_assessment is not None
        assert bundle.x_maljan_assessment.confidence == 0.85
        (file,) = _of(bundle, "file")
        assert file.hashes == {"MD5": "a" * 32}

    def test_the_stored_file_is_kept_whole(self) -> None:
        bundle, record = _parse(_answer({**STORED_FILE, "id": "file--1"}))

        (file,) = _of(bundle, "file")
        dumped = file.model_dump(mode="json")
        for key in ("name", "size", "hashes", "mime_type"):
            assert dumped[key] == STORED_FILE[key], key
        assert [v.code for v in record] == []

    def test_a_process_carrying_a_property_stix_does_not_define_is_set_aside_with_a_record(
        self,
    ) -> None:
        bundle, record = _parse(_answer({**STORED_PROCESS, "id": "process--1"}))

        assert _of(bundle, "process") == []
        assert _of(bundle, "malware")
        (row,) = record
        assert row.code == UNKNOWN_OBJECT_CODE
        assert "'name'" in row.message
        assert "image_ref" in row.message

    def test_a_process_with_its_defined_properties_is_kept_whole(self) -> None:
        written = {
            "type": "process",
            "id": "process--1",
            "pid": 100,
            "command_line": "loader.exe /q",
            "cwd": "C:\\Temp",
            "image_ref": "file--1",
        }
        bundle, record = _parse(_answer(written, {**STORED_FILE, "id": "file--1"}))

        (process,) = _of(bundle, "process")
        (file,) = _of(bundle, "file")
        assert (process.pid, process.command_line, process.cwd) == (
            100,
            "loader.exe /q",
            "C:\\Temp",
        )
        assert process.image_ref == file.id
        assert record == []

    def test_an_observed_data_with_the_old_objects_dictionary_is_set_aside_with_a_record(
        self,
    ) -> None:
        written = {
            "type": "observed-data",
            "id": "observed-data--1",
            "first_observed": "2026-09-19T00:00:00Z",
            "last_observed": "2026-09-19T00:00:00Z",
            "number_observed": 1,
            "objects": {"0": STORED_FILE},
        }
        bundle, record = _parse(_answer(written))

        assert _of(bundle, "observed-data") == []
        assert bundle.x_maljan_fallback_verdict is None
        assert [v.code for v in record] == [UNKNOWN_OBJECT_CODE]
        assert "'objects'" in record[0].message

    def test_a_value_the_model_cannot_hold_costs_that_object_only(self) -> None:
        bundle, record = _parse(
            _answer({"type": "file", "id": "file--1", "name": "a", "size": "big"})
        )

        assert _of(bundle, "file") == []
        assert _of(bundle, "malware")
        assert [v.code for v in record] == [UNKNOWN_OBJECT_CODE]

    def test_the_set_aside_sentence_does_not_invite_types_the_judge_is_not_asked_for(self) -> None:
        _bundle, record = _parse(_answer({"type": "sighting", "id": "sighting--1"}))

        (row,) = record
        assert "observed-data" not in row.message
        assert "report" not in row.message.split("(", 1)[1]


class TestAFileWithNothingToIdentifyIt:
    def test_it_is_a_question(self) -> None:
        bundle = Bundle.model_validate({"objects": [{"type": "file", "id": "file--1", "size": 10}]})

        codes = [v.code for v in validate_verdict_bundle(bundle, {"x"})]

        assert FILE_UNIDENTIFIED_CODE in codes

    def test_the_models_keep_every_defined_property(self) -> None:
        assert {"hashes", "name", "size", "mime_type", "parent_directory_ref", "extensions"} <= set(
            File.model_fields
        )
        assert {"pid", "command_line", "cwd", "image_ref", "parent_ref", "child_refs"} <= set(
            Process.model_fields
        )
