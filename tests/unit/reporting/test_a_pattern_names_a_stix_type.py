"""A judge indicator over an object type STIX does not have is asked about.

A recorded run exported ``[ipv-addr:value = '82.157.13.47']`` typed
``["ip-addr"]``. ``ipv-addr`` is not a Cyber-observable type — the address is an
``ipv4-addr`` — so no consumer holds an object that pattern could ever match.
And because the export asks its endpoint question only of the paths it knows,
an unknown type skipped the question entirely: the same misspelling around
``127.0.0.1`` would have exported a loopback indicator unasked.

The pattern is the judge's and nothing rewrites it. The judge is told, once,
which type the value is; a pattern that still names no STIX type is left out of
the export with a recorded sentence, because a consumer cannot act on it and
the export could not ask whether it may carry the value.

The indicator's ``indicator_types`` is asked about the same way when it is
outside STIX's vocabulary: the recorded run wrote the kind of value (``ip-addr``,
``file``) where the vocabulary says what the value indicates. That one is an
open vocabulary, so whatever the judge keeps is published as it wrote it.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    INDICATOR_TYPE_VOCABULARY_CODE,
    UNKNOWN_OBJECT_PATH_CODE,
    UNKNOWN_OBSERVABLE_TYPE_CODE,
    validate_verdict_bundle,
)
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_PATTERN_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.judgement import JudgeAssessment
from maljan.schemas.stix_models import Bundle, Indicator, Malware
from maljan.schemas.stix_pattern import (
    object_path_problems,
    observable_type_for,
    unknown_object_types,
)

ADDRESS = "82.157.13.47"


def _indicator(pattern: str, *types: str) -> Indicator:
    return Indicator(
        name="IP Address",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=list(types) or ["malicious-activity"],
    )


def _bundle(*indicators: Indicator) -> Bundle:
    return Bundle(
        objects=[Malware(name="sample"), *indicators],
        x_maljan_assessment=JudgeAssessment(verdict="Malware", confidence=0.9),
    )


def _violations(bundle: Bundle) -> list:
    return validate_verdict_bundle(bundle, {ADDRESS, "127.0.0.1", "/tmp/log_de.log"})


def _report() -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.elf",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="reverse_shell",
        evidence_ledger=[],
    ).build_deterministic()


class TestTheReader:
    def test_a_misspelt_type_is_named(self) -> None:
        assert unknown_object_types(f"[ipv-addr:value = '{ADDRESS}']") == ["ipv-addr"]

    def test_every_stix_type_and_a_custom_one_are_known(self) -> None:
        for pattern in (
            f"[ipv4-addr:value = '{ADDRESS}']",
            "[x-acme-thing:value = 'a']",
            "[file:hashes.'SHA-256' = 'aa'] OR [windows-registry-key:key = 'k']",
        ):
            assert unknown_object_types(pattern) == [], pattern

    def test_the_type_a_value_is(self) -> None:
        assert observable_type_for("ipv-addr", ADDRESS) == "ipv4-addr"
        assert observable_type_for("ip-addr", "2001:db8::1") == "ipv6-addr"
        assert observable_type_for("domain", "example.org") == "domain-name"
        assert observable_type_for("zzzz", "whatever") == ""


class TestTheJudgeIsAsked:
    def test_a_type_stix_does_not_have_is_a_question_naming_the_type(self) -> None:
        bundle = _bundle(_indicator(f"[ipv-addr:value = '{ADDRESS}']"))
        rows = [v for v in _violations(bundle) if v.code == UNKNOWN_OBSERVABLE_TYPE_CODE]

        assert len(rows) == 1
        assert "'ipv-addr'" in rows[0].message
        assert "ipv4-addr" in rows[0].message
        assert rows[0].path == "objects[1]"

    def test_the_pattern_is_not_rewritten(self) -> None:
        indicator = _indicator(f"[ipv-addr:value = '{ADDRESS}']")
        _violations(_bundle(indicator))

        assert indicator.pattern == f"[ipv-addr:value = '{ADDRESS}']"

    def test_a_pattern_over_stix_types_raises_no_such_row(self) -> None:
        bundle = _bundle(_indicator(f"[ipv4-addr:value = '{ADDRESS}']"))

        assert UNKNOWN_OBSERVABLE_TYPE_CODE not in [v.code for v in _violations(bundle)]

    def test_an_indicator_type_outside_the_vocabulary_is_asked_about(self) -> None:
        bundle = _bundle(_indicator(f"[ipv4-addr:value = '{ADDRESS}']", "ip-addr"))
        rows = [v for v in _violations(bundle) if v.code == INDICATOR_TYPE_VOCABULARY_CODE]

        assert len(rows) == 1
        assert "'ip-addr'" in rows[0].message
        assert "malicious-activity" in rows[0].message

    def test_a_vocabulary_type_raises_nothing(self) -> None:
        bundle = _bundle(_indicator(f"[ipv4-addr:value = '{ADDRESS}']", "anomalous-activity"))

        assert INDICATOR_TYPE_VOCABULARY_CODE not in [v.code for v in _violations(bundle)]


class TestTheExport:
    def test_a_pattern_over_no_stix_type_is_left_out_with_a_sentence(self) -> None:
        renderer = ExtendedSTIXRenderer()
        base = _bundle(_indicator(f"[ipv-addr:value = '{ADDRESS}']"))

        exported = renderer.render(_report(), base)

        patterns = [o.pattern for o in exported.objects if isinstance(o, Indicator)]
        assert not [p for p in patterns if "ipv-addr" in p]
        codes = [code for code, _sentence in renderer.declined]
        assert codes == [UNPUBLISHABLE_PATTERN_CODE]
        assert "'ipv-addr'" in renderer.declined[0][1]
        # The judge's own bundle still says what the judge wrote.
        assert base.objects[1].pattern == f"[ipv-addr:value = '{ADDRESS}']"

    def test_a_loopback_behind_a_misspelt_type_does_not_reach_the_export(self) -> None:
        renderer = ExtendedSTIXRenderer()
        exported = renderer.render(_report(), _bundle(_indicator("[ipv-addr:value = '127.0.0.1']")))

        patterns = [o.pattern for o in exported.objects if isinstance(o, Indicator)]
        assert not [p for p in patterns if "127.0.0.1" in p]

    def test_a_kept_indicator_type_is_published_as_written(self) -> None:
        exported = ExtendedSTIXRenderer().render(
            _report(), _bundle(_indicator(f"[ipv4-addr:value = '{ADDRESS}']", "ip-addr"))
        )

        kept = [o for o in exported.objects if isinstance(o, Indicator) and ADDRESS in o.pattern]
        assert [o.indicator_types for o in kept] == [["ip-addr"]]


class TestThePromptNamesBoth:
    def test_the_judge_is_told_the_types_and_the_vocabulary_before_it_answers(self) -> None:
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM
        from maljan.pipeline.validation import INDICATOR_TYPES

        assert "STIX Cyber-observable type (ipv4-addr" in JUDGE_VERDICT_SYSTEM
        for word in INDICATOR_TYPES:
            assert word in JUDGE_VERDICT_SYSTEM, word


class TestTheObjectPathIsAsked:
    """The object path a pattern compares must be one its type has.

    ``[file:extensions['pe'].pe_imphash = 'abc']`` was carried to the export —
    ``pe`` is not an extension a file has, so the pattern is one the standard's
    grammar refuses. And ``[IPv4-Addr:value = '8.8.8.8']`` passed the type
    question because the reader folded case, although STIX types are written
    in lower case and the grammar refuses the capitalised one.
    """

    def test_a_property_the_type_does_not_have_is_named(self) -> None:
        problems = object_path_problems("[file:colour = 'red']")

        assert len(problems) == 1
        assert "'colour'" in problems[0]

    def test_an_extension_the_type_does_not_have_is_named(self) -> None:
        (problem,) = object_path_problems("[file:extensions['pe'].pe_imphash = 'abc']")

        assert "'pe'" in problem
        assert "windows-pebinary-ext" in problem

    def test_a_capitalised_type_is_not_a_stix_type(self) -> None:
        assert unknown_object_types("[IPv4-Addr:value = '8.8.8.8']") == ["IPv4-Addr"]

    def test_paths_the_types_have_raise_nothing(self) -> None:
        for pattern in (
            "[file:hashes.'SHA-256' = 'aa']",
            "[file:extensions.'windows-pebinary-ext'.imphash = 'aa']",
            "[network-traffic:dst_ref.value = '82.157.13.47']",
            "[domain-name:resolves_to_refs[*].value = '1.2.3.4']",
            "[process:x_acme_label = 'a']",
            "[x-acme-thing:anything = 'a']",
        ):
            assert object_path_problems(pattern) == [], pattern

    def test_the_judge_is_asked_and_the_export_declines_it(self) -> None:
        indicator = _indicator("[file:extensions['pe'].pe_imphash = 'b15607f10222dbea']")
        codes = [v.code for v in _violations(_bundle(indicator))]
        renderer = ExtendedSTIXRenderer()
        exported = renderer.render(_report(), _bundle(indicator))

        assert UNKNOWN_OBJECT_PATH_CODE in codes
        assert not [
            o for o in exported.objects if isinstance(o, Indicator) and "pe_imphash" in o.pattern
        ]
        assert [code for code, _why in renderer.declined] == [UNPUBLISHABLE_PATTERN_CODE]
