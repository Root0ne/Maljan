"""A pattern the standard's grammar refuses is asked about, then declined.

A judge's indicator compared ``file:extensions['windows-pebinary-ext']
.original_filename``: a key written in brackets, which the pattern grammar has
no form for, and a property the extension does not define. The platform's path
check read the bracketed key as a key and never looked inside the extension,
so the pattern was exported as written and the bundle failed the official
validator with three errors. Both are now problems of the path: the judge is
asked once, and an indicator that keeps the pattern is declined with a record,
never exported and never rewritten.
"""

from __future__ import annotations

from typing import Any

from stix2validator import ValidationOptions, validate_instance

from maljan.pipeline.validation import UNKNOWN_OBJECT_PATH_CODE, validate_verdict_bundle
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_PATTERN_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.stix_models import Bundle
from maljan.schemas.stix_pattern import object_path_problems

SHA256 = "e" * 64
REFUSED = (
    f"[file:hashes.'SHA-256' = '{SHA256}'] AND "
    "[file:extensions['windows-pebinary-ext'].original_filename = 'example.exe']"
)


def _indicator(pattern: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "valid_from": "2026-01-01T00:00:00Z",
        "name": "Signed example tool",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["benign"],
    }


def _errors(bundle: dict[str, Any]) -> list[str]:
    result = validate_instance(bundle, ValidationOptions(version="2.1"))
    return [str(getattr(error, "message", error)) for error in result.errors]


class TestTheDefect:
    def test_the_official_validator_refuses_the_pattern(self) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332211",
            "objects": [_indicator(REFUSED)],
        }

        assert _errors(bundle)


class TestThePathCheck:
    def test_a_bracketed_key_and_a_property_the_extension_lacks_are_one_problem(self) -> None:
        (problem,) = object_path_problems(REFUSED)

        assert "never ['windows-pebinary-ext']" in problem
        assert "windows-pebinary-ext has no property 'original_filename'" in problem

    def test_the_grammar_s_own_form_raises_nothing(self) -> None:
        pattern = "[file:extensions.'windows-pebinary-ext'.imphash = 'aa']"

        assert object_path_problems(pattern) == []

    def test_a_bracketed_hash_key_is_named(self) -> None:
        (problem,) = object_path_problems(f"[file:hashes['SHA-256'] = '{SHA256}']")

        assert "never ['sha-256']" in problem

    def test_a_list_index_is_not_a_key(self) -> None:
        assert object_path_problems("[domain-name:resolves_to_refs[*].value = '1.2.3.4']") == []

    def test_an_extension_s_custom_property_is_the_producer_s(self) -> None:
        pattern = "[file:extensions.'windows-pebinary-ext'.x_acme_note = 'a']"

        assert object_path_problems(pattern) == []


class TestTheJudgeIsAskedAndTheExportDeclines:
    def _bundle(self) -> Bundle:
        return Bundle.model_validate({"type": "bundle", "objects": [_indicator(REFUSED)]})

    def test_the_judge_is_asked(self) -> None:
        codes = [v.code for v in validate_verdict_bundle(self._bundle(), {SHA256})]

        assert UNKNOWN_OBJECT_PATH_CODE in codes

    def test_the_export_declines_it_with_a_record_and_passes_the_validator(self) -> None:
        judge = self._bundle()
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)), verdict="Benign"
        )
        renderer = ExtendedSTIXRenderer()

        exported = renderer.render(report, judge)

        patterns = [getattr(o, "pattern", "") for o in exported.objects]
        assert REFUSED not in patterns
        assert UNPUBLISHABLE_PATTERN_CODE in [code for code, _why in renderer.declined]
        assert _errors(exported.model_dump(mode="json")) == []

    def test_the_judge_s_own_bundle_keeps_the_pattern_as_written(self) -> None:
        judge = self._bundle()
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)), verdict="Benign"
        )

        ExtendedSTIXRenderer().render(report, judge)

        assert [getattr(o, "pattern", "") for o in judge.objects] == [REFUSED]
