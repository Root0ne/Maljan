"""The condition language: what it accepts, what it refuses, and what it means.

A ``when`` expression is operator text evaluated on the worker, so the first
half of this file is an allow-list test rather than a feature test: the things
that must never run are asserted one by one, because "we only parse a subset"
is a claim that decays the moment someone adds a node type to the walker.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.conditions import (
    ConditionError,
    StageContext,
    StageResult,
    evaluate,
    validate_condition,
)

PE = StageContext(
    file_type="PE32 executable",
    platform="windows",
    mime="application/x-dosexec",
    size=204_800,
    extension="exe",
    sandbox_available=True,
    has_pcap=False,
    has_sandbox_report=True,
    stages={
        "triage": StageResult(
            ran=True, claim_count=3, technique_ids=("T1055", "T1027"), agents=("static",)
        ),
        "detonate": StageResult(ran=False, reason="condition not met: sandbox_available"),
    },
)


class TestTheGrammarItAccepts:
    def test_an_empty_condition_is_always_true(self) -> None:
        assert evaluate("", PE) is True
        assert evaluate("   ", PE) is True
        assert validate_condition("") == []

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ('platform == "windows"', True),
            ('platform != "windows"', False),
            ('extension in ("exe", "dll")', True),
            ('extension not in ["apk", "elf"]', True),
            ("size > 1000", True),
            ("size >= 204800", True),
            ("size < 1000", False),
            ("size <= 204800", True),
            ("has_pcap", False),
            ("not has_pcap", True),
            ("sandbox_available and has_sandbox_report", True),
            ("has_pcap or has_sandbox_report", True),
            ("1000 < size < 999999", True),
        ],
    )
    def test_each_operator_means_what_it_says(self, expression: str, expected: bool) -> None:
        assert evaluate(expression, PE) is expected

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("stages.triage.ran", True),
            ("stages.detonate.ran", False),
            ("stages.triage.claim_count > 2", True),
            ('"T1055" in stages.triage.technique_ids', True),
            ('"T1071" in stages.triage.technique_ids', False),
            ('"static" in stages.triage.agents', True),
            ('stages["triage"].claim_count == 3', True),
            ("stages.triage.finding_count == 0", True),
        ],
    )
    def test_a_stage_result_is_read_both_ways(self, expression: str, expected: bool) -> None:
        assert evaluate(expression, PE) is expected

    def test_a_stage_nobody_ran_reads_as_a_stage_that_did_not_run(self) -> None:
        """The normal case, not a configuration error: an upstream skip."""
        assert evaluate("stages.never_declared.ran", PE) is False
        assert evaluate("not stages.never_declared.ran", PE) is True


class TestTheGrammarItRefuses:
    @pytest.mark.parametrize(
        "expression",
        [
            '__import__("os").system("id")',
            "open('/etc/passwd').read()",
            "len(file_type) > 3",
            "lambda: 1",
            "[x for x in file_type]",
            'f"{file_type}"',
            "size + 1 > 2",
            "size if has_pcap else 0",
            "{1: 2}",
            "{1, 2}",
            "extension[0:2] == 'ex'",
            "platform.upper()",
            "(size := 3) > 2",
        ],
    )
    def test_anything_that_could_run_code_or_compute_is_refused(self, expression: str) -> None:
        problems = validate_condition(expression)
        assert problems, f"{expression!r} was accepted"
        with pytest.raises(ConditionError):
            evaluate(expression, PE)

    def test_an_unknown_name_names_the_ones_that_exist(self) -> None:
        (problem,) = validate_condition("verdict == 'Malware'")
        assert "unknown name 'verdict'" in problem
        assert "sandbox_available" in problem

    def test_an_unknown_stage_field_names_the_ones_that_exist(self) -> None:
        (problem,) = validate_condition("stages.triage.verdict")
        assert "claim_count" in problem

    def test_a_stage_read_without_a_field_is_refused(self) -> None:
        assert validate_condition("stages.triage")
        assert validate_condition('stages["triage"]')

    def test_a_stage_looked_up_by_something_other_than_a_literal_is_refused(self) -> None:
        assert validate_condition("stages[platform].ran")

    def test_a_syntax_error_is_reported_as_one(self) -> None:
        (problem,) = validate_condition("size >")
        assert "cannot parse the condition" in problem

    def test_comparing_incomparable_values_is_the_operator_s_error(self) -> None:
        (problem,) = validate_condition('size < "big"')
        assert "cannot compare" in problem


class TestTheResultRoundTrips:
    def test_a_result_survives_the_state_channel_it_travels_on(self) -> None:
        original = StageResult(
            ran=True,
            reason="",
            claim_count=2,
            technique_ids=("T1055",),
            finding_count=1,
            agents=("static", "dynamic"),
        )
        assert StageResult.from_dict(original.to_dict()) == original

    def test_an_empty_dict_reads_as_a_stage_that_did_not_run(self) -> None:
        assert StageResult.from_dict({}) == StageResult(ran=False)
