"""A pattern the official validator accepts is kept, whatever its comparison operator.

The judge's integrity pass kept only patterns containing ``=``, so a judge that
wrote its command-and-control hosts as ``[url:value LIKE '%host%']`` had twelve
of thirteen indicators dropped as "empty_pattern", with their relationships,
before any rule was asked about them. Well-formedness is read by the one
pattern reader now: an indicator is dropped only when its pattern is not
written whole.

What happens next is asked honestly too. A ``LIKE`` value is a shape, not a
value: the grounding check asks the evidence for the text between its
wildcards, the IOC table and ``/iocs`` list no row for it (``'%x%'`` is not the
literal ``x``), and the export declines one of a kind the publish rule answers
for, with the reason. A value that writes a backslash the grammar cannot read
is asked about and, kept, declined — never rewritten.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from stix2patterns.validator import run_validator
from stix2validator import ValidationOptions, validate_instance

from maljan.agents.judge_postprocess import enforce_bundle_integrity
from maljan.pipeline.validation import (
    PATTERN_REFUSED_CODE,
    STRAY_BACKSLASH_CODE,
    validate_verdict_bundle,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_PATTERN_CODE,
    UNPUBLISHED_VALUE_CODE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
    pattern_values,
)
from maljan.schemas.stix_models import Bundle
from maljan.schemas.stix_pattern import (
    like_fixed_text,
    pattern_refusal,
    reads_whole,
    stray_backslash_values,
)

SHA256 = "c" * 64

# Every comparison operator the grammar has, each in a pattern the official
# validator accepts.
ACCEPTED = (
    "[url:value LIKE '%example.org%']",
    "[process:command_line LIKE '%whoami /all%']",
    "[file:name MATCHES '^tmp[0-9]+\\\\.dat$']",
    "[file:name != 'a.exe']",
    "[file:name NOT = 'a.exe']",
    "[file:size > 1000]",
    "[file:size < 1000]",
    "[process:pid <= 4]",
    "[process:pid >= 4]",
    "[file:name IN ('a.exe', 'b.exe')]",
    "[ipv4-addr:value ISSUBSET '198.51.100.0/24']",
    "[ipv4-addr:value ISSUPERSET '198.51.100.7/32']",
    "[EXISTS windows-registry-key:values]",
    "[file:name = 'a.exe' AND file:size >= 10]",
    "([file:name = 'a.exe'] OR [file:name = 'b.exe']) WITHIN 300 SECONDS",
    "[file:name = 'a.exe'] REPEATS 5 TIMES",
    "[file:name = 'a.exe'] START t'2026-01-01T00:00:00Z' STOP t'2026-02-01T00:00:00Z'",
    "[windows-registry-key:key LIKE '%Software\\\\Example%']",
    f"[file:hashes.'SHA-256' = '{SHA256}']",
)

# What a generation cut short leaves behind, what is not a pattern at all, and
# what keeps its brackets balanced and still is not one: a review's examples.
REFUSED = (
    "[]",
    "[url:value LIKE '%example.org",
    "[file:hashes.'SHA",
    "[file:name = 'a.exe'",
    "file:name = 'a.exe'",
    "([file:name = 'a.exe'] OR [file:name = 'b.exe']",
    "[file:name]",
    "[file:name =]",
    "[file:name LIKE]",
    "[file:name = 'x' AND]",
    "[file:name = 'x'] garbage",
    "[x] file:name",
    "[file:name = x]",
    '[file:name = "x"]',
    "[file:name = 'a''b']",
    "[directory:path = 'C:\\Users\\Public\\']",
    "[file:name = 'x' and file:size = 3]",
    "[file:name IN ('a',)]",
    "[file:name LIKE 3]",
    "[file:name = 'a'] REPEATS 1.5 TIMES",
    "[file:name = 'a'] START '2026-01-01T00:00:00Z' STOP '2026-02-01T00:00:00Z'",
)


def _refused(pattern: str) -> bool:
    """Whether the official pattern validator refuses ``pattern``; it raises on an empty one."""
    try:
        return run_validator(pattern) != []
    except Exception:  # noqa: BLE001 — a validator that cannot read it refuses it
        return True


def _indicator(pattern: str, index: int = 1) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--{index}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
    }


class TestWellFormedness:
    @pytest.mark.parametrize("pattern", ACCEPTED)
    def test_a_pattern_the_official_validator_accepts_is_kept(self, pattern: str) -> None:
        assert run_validator(pattern) == [], "the fixture must be a valid pattern"

        kept = enforce_bundle_integrity([_indicator(pattern)])

        assert reads_whole(pattern)
        assert [o["pattern"] for o in kept] == [pattern]

    @pytest.mark.parametrize("pattern", REFUSED)
    def test_a_pattern_the_validator_refuses_is_refused_by_the_reader(self, pattern: str) -> None:
        assert _refused(pattern), "the fixture must be refused by the grammar"

        assert not reads_whole(pattern)
        assert pattern_refusal(pattern)

    @pytest.mark.parametrize("pattern", ACCEPTED + REFUSED)
    def test_the_grammar_alone_answers_as_the_validator_does(self, pattern: str) -> None:
        """Where ``stix2-patterns`` is not installed — the image installs no dev group."""
        with patch("maljan.schemas.stix_pattern._validator_refusal", return_value=""):
            assert reads_whole(pattern) is not _refused(pattern)

    @pytest.mark.parametrize("pattern", REFUSED)
    def test_it_is_kept_for_the_judge_to_be_asked(self, pattern: str) -> None:
        """Only an empty pattern is dropped by the pass; the rest are asked, then declined."""
        assert [o["pattern"] for o in enforce_bundle_integrity([_indicator(pattern)])] == [pattern]

    @pytest.mark.parametrize("pattern", ["", "   "])
    def test_an_empty_pattern_is_dropped(self, pattern: str) -> None:
        assert enforce_bundle_integrity([_indicator(pattern)]) == []

    @pytest.mark.parametrize("pattern", REFUSED)
    def test_the_judge_is_asked_once_and_the_export_declines_it(self, pattern: str) -> None:
        bundle = Bundle.model_validate({"type": "bundle", "objects": [_indicator(pattern)]})

        codes = [v.code for v in validate_verdict_bundle(bundle, {"x"})]
        exported, renderer = _export(pattern)

        assert set(codes) & {PATTERN_REFUSED_CODE, STRAY_BACKSLASH_CODE}
        assert pattern not in [getattr(o, "pattern", "") for o in exported.objects]
        assert UNPUBLISHABLE_PATTERN_CODE in [code for code, _why in renderer.declined]
        assert _errors(exported) == []

    def test_like_indicators_keep_their_relationships(self) -> None:
        """The run's shape: the domains and their edges reach the rules after the pass."""
        objects: list[dict[str, Any]] = [
            {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
            _indicator("[url:value LIKE '%one.example%']", 1),
            _indicator("[url:value LIKE '%two.example%']", 2),
        ]
        objects += [
            {
                "type": "relationship",
                "id": f"relationship--{i}",
                "relationship_type": "indicates",
                "source_ref": f"indicator--{i}",
                "target_ref": "malware--1",
            }
            for i in (1, 2)
        ]

        kept = enforce_bundle_integrity(objects)

        assert [o["id"] for o in kept] == [o["id"] for o in objects]


class TestAShapeIsNotAValue:
    def test_the_fixed_text_is_what_lies_between_the_wildcards(self) -> None:
        assert like_fixed_text("%one.example%") == ["one.example"]
        assert like_fixed_text("%net view /all%") == ["net view /all"]
        assert like_fixed_text("a%b_c") == ["a", "b", "c"]
        assert like_fixed_text("%%") == []

    def test_the_ioc_table_reads_no_value_out_of_a_like(self) -> None:
        bundle = {
            "objects": [
                _indicator("[url:value LIKE '%one.example%']", 1),
                _indicator("[domain-name:value = 'two.example']", 2),
            ]
        }

        assert pattern_values("[url:value LIKE '%one.example%']") == []
        assert [(v.kind, v.value) for v in exported_indicator_values(bundle)] == [
            ("domain", "two.example")
        ]

    def test_grounding_asks_for_the_text_not_the_wildcards(self) -> None:
        bundle = Bundle.model_validate(
            {"type": "bundle", "objects": [_indicator("[url:value LIKE '%one.example%']")]}
        )

        found = validate_verdict_bundle(bundle, {"decoded string: https://one.example/gate"})

        assert [v for v in found if v.code == "stix.ungrounded_indicator"] == []

    def test_an_absent_fixed_text_is_named_as_itself(self) -> None:
        bundle = Bundle.model_validate(
            {"type": "bundle", "objects": [_indicator("[url:value LIKE '%one.example%']")]}
        )

        (row,) = [
            v
            for v in validate_verdict_bundle(bundle, {"nothing about it here"})
            if v.code == "stix.ungrounded_indicator"
        ]

        assert "the text 'one.example'" in row.message
        assert "LIKE '%one.example%'" in row.message


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)), verdict="Malware"
    )


def _uuid(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def _export(*patterns: str) -> tuple[Bundle, ExtendedSTIXRenderer]:
    judge = Bundle.model_validate(
        {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": f"malware--{_uuid(0)}", "name": "x", "is_family": False},
                *(
                    {**_indicator(p), "id": f"indicator--{_uuid(i)}"}
                    for i, p in enumerate(patterns, start=1)
                ),
            ],
        }
    )
    renderer = ExtendedSTIXRenderer()
    return renderer.render(_report(), judge), renderer


def _errors(bundle: Bundle) -> list[str]:
    result = validate_instance(bundle.model_dump(mode="json"), ValidationOptions(version="2.1"))
    return [str(getattr(error, "message", error)) for error in result.errors]


class TestTheExport:
    def test_a_shape_of_a_kind_the_publish_rule_answers_is_declined_with_its_reason(
        self,
    ) -> None:
        pattern = "[process:command_line LIKE '%whoami /all%']"

        exported, renderer = _export(pattern)

        assert pattern not in [getattr(o, "pattern", "") for o in exported.objects]
        (row,) = [why for code, why in renderer.declined if code == UNPUBLISHED_VALUE_CODE]
        assert "LIKE '%whoami /all%'" in row
        assert "rather than one value" in row

    def test_a_like_url_is_declined_by_the_endpoint_question(self) -> None:
        pattern = "[url:value LIKE '%one.example%']"

        exported, renderer = _export(pattern)

        assert pattern not in [getattr(o, "pattern", "") for o in exported.objects]
        assert renderer.declined

    def test_a_shape_over_a_path_the_rule_has_no_row_for_is_carried(self) -> None:
        pattern = "[file:size > 1000]"

        exported, _renderer = _export(pattern)

        assert pattern in [getattr(o, "pattern", "") for o in exported.objects]
        assert _errors(exported) == []

    def test_the_export_of_the_run_s_shapes_passes_the_official_validator(self) -> None:
        exported, _renderer = _export(
            "[url:value LIKE '%one.example%']",
            "[process:command_line LIKE '%whoami /all%']",
            "[windows-registry-key:key LIKE '%Software\\Example%']",
        )

        assert _errors(exported) == []


class TestAStrayBackslash:
    PATTERN = "[windows-registry-key:key LIKE '%Software\\Example\\Run%']"

    def test_the_official_validator_refuses_it(self) -> None:
        assert run_validator(self.PATTERN) != []

    def test_the_reader_names_the_value(self) -> None:
        assert stray_backslash_values(self.PATTERN) == ["%Software\\Example\\Run%"]
        assert stray_backslash_values("[file:name = 'C:\\\\x.exe']") == []
        assert stray_backslash_values("[file:name = 'it\\'s.exe']") == []

    def test_the_judge_is_asked(self) -> None:
        bundle = Bundle.model_validate({"type": "bundle", "objects": [_indicator(self.PATTERN)]})

        (row,) = [v for v in validate_verdict_bundle(bundle) if v.code == STRAY_BACKSLASH_CODE]

        assert "written twice in the pattern" in row.message

    def test_the_export_declines_it_and_the_judge_s_bundle_keeps_it(self) -> None:
        exported, renderer = _export(self.PATTERN)

        assert self.PATTERN not in [getattr(o, "pattern", "") for o in exported.objects]
        assert UNPUBLISHABLE_PATTERN_CODE in [code for code, _why in renderer.declined]
        assert _errors(exported) == []
