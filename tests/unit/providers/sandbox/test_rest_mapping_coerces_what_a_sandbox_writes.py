"""PS-M4: the REST mapping reads what a sandbox writes, and a failed path says nothing.

A severity written as a word (``"high"``) or a number written as text
(``"0x10"``) used to raise out of the mapping and lose the whole report; a
string ``ttps`` was split into its characters; a channel whose path failed on
the report was laid out empty and read as "none observed".
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import RestMappingConfig
from maljan.core.report_formats import SignatureScale
from maljan.providers.sandbox.readers import required_reader
from maljan.providers.sandbox.rest_mapping import (
    apply_mapping,
    compile_mapping,
    rung_score,
    whole_number,
)

MAPPING = RestMappingConfig(signatures="$.sigs[*]", processes="$.procs[*]", calls="$.calls[*]")


def _map(payload: dict[str, Any], cfg: RestMappingConfig = MAPPING) -> Any:
    return apply_mapping(compile_mapping(cfg), payload, provider="rest", task_id="1")


class TestNumbers:
    def test_numbers_written_as_text_are_read(self) -> None:
        assert whole_number("16") == 16
        assert whole_number("0x10") == 16
        assert whole_number(" 010 ") == 10
        assert whole_number("3.0") == 3
        assert whole_number(7) == 7
        assert whole_number(2.9) == 2

    def test_a_word_is_no_number(self) -> None:
        assert whole_number("high") is None
        assert whole_number(None) is None
        assert whole_number(True) is None
        assert whole_number(float("nan")) is None

    def test_a_hex_pid_is_read_and_the_report_survives(self) -> None:
        payload = {
            "procs": [{"pid": "0x10", "ppid": "4", "name": "a.exe"}],
            "calls": [{"pid": "0x10", "api": "CreateFileW"}],
        }
        report = _map(payload).report
        assert [(p.pid, p.ppid) for p in report.processes] == [(16, 4)]
        assert report.processes[0].calls and report.apistats == {"16": {"CreateFileW": 1}}


class TestSignatures:
    def test_a_word_severity_is_kept_and_the_report_survives(self) -> None:
        report = _map({"sigs": [{"name": "inject", "severity": "high"}]}).report
        (sig,) = report.signatures
        assert sig.severity is None
        assert sig.extra == {"severity": "high"}

    def test_a_numeric_text_severity_is_its_number(self) -> None:
        report = _map({"sigs": [{"name": "inject", "severity": "3"}]}).report
        assert report.signatures[0].severity == 3
        assert report.signatures[0].extra == {}

    def test_a_string_ttps_is_one_technique_not_its_characters(self) -> None:
        report = _map({"sigs": [{"name": "inject", "ttps": "T1055"}]}).report
        assert report.signatures[0].ttp_tags == ["T1055"]

    def test_a_list_ttps_is_read_as_before(self) -> None:
        report = _map({"sigs": [{"name": "inject", "ttps": ["T1055", "", "T1112"]}]}).report
        assert report.signatures[0].ttp_tags == ["T1055", "T1112"]

    def test_the_declared_scale_rates_a_word_by_its_rung(self) -> None:
        scale = SignatureScale(name="1-3", rungs=["Low", "Medium", "High"])
        report = apply_mapping(
            compile_mapping(MAPPING),
            {"sigs": [{"name": "a", "severity": "High"}, {"name": "b", "severity": "loud"}]},
            provider="rest",
            task_id="1",
            signature_scale=scale,
        ).report
        assert [s.severity for s in report.signatures] == [3, None]
        assert rung_score(" high ", scale) == 3 and rung_score("loud", scale) is None
        assert report.signatures[1].extra == {"severity": "loud"}

    def test_the_mapping_reader_rates_words_on_the_scale_it_is_given(self) -> None:
        scale = SignatureScale(name="1-3", rungs=["Low", "Medium", "High"])
        report = required_reader("generic").read(
            {"sigs": [{"name": "a", "severity": "medium"}]},
            provider="rest",
            task_id="1",
            mapping=MAPPING,
            signature_scale=scale,
        )
        assert report.signatures[0].severity == 2

    def test_with_no_scale_a_word_stays_the_word(self) -> None:
        report = _map({"sigs": [{"name": "a", "severity": "high"}]}).report
        assert rung_score("high", None) is None
        assert report.signatures[0].severity is None
        assert report.signatures[0].extra == {"severity": "high"}

    def test_the_reader_with_no_declared_scale_says_unknown_not_zero(self) -> None:
        from maljan.schemas.sandbox_document import sandbox_document

        report = required_reader("generic").read(
            {"sigs": [{"name": "a", "severity": "high"}]},
            provider="rest",
            task_id="1",
            mapping=MAPPING,
        )
        assert report.signature_scale is None
        (sig,) = report.signatures
        assert sig.severity is None and sig.extra == {"severity": "high"}
        # The document an analyst reads says the same: no number, the word kept.
        (row,) = sandbox_document(report)["signatures"]
        assert row["severity"] is None


class TestAFailedPath:
    def test_a_failing_path_is_unavailable_and_its_derived_section_too(self) -> None:
        compiled = compile_mapping(MAPPING)

        class _Failing:
            def finditer(self, payload: Any) -> Any:
                raise ValueError("the path cannot be read on this report")

        compiled.paths["calls"] = _Failing()
        result = apply_mapping(compiled, {"procs": [{"pid": 1}]}, provider="rest", task_id="1")
        assert result.stats["calls"].error
        unavailable = set(result.report.unavailable)
        assert {"api_calls", "apistats"} <= unavailable
        # A path that read is not named.
        assert "processes" not in unavailable

    def test_a_path_that_read_nothing_is_not_named(self) -> None:
        result = _map({"sigs": [], "procs": [], "calls": []})
        assert "signatures" not in result.report.unavailable
