"""The verdict a run publishes is the one the judge stated.

A live run on a signed, 0/74-clean PuTTY published ``Malware, confidence 1.0``.
Everything the judge itself said was the opposite: its severity rating was
``Informational``, its category ``legitimate-utility``, and its own rationale
read *"no malicious intent or behavior was detected. The 'malware'
classification is used here strictly as a container for the object type in
STIX, but the assessment confirms it is benign."* The bundle carried a
``malware`` object, the verdict was read off that object, and the contradiction
the pipeline detected was fed back once, survived, and published anyway.

The judge states the verdict now, in a field of its own, and that statement is
read three ways — the word is one this pipeline knows, the word is one it does
not, or there is no word at all — because only the third of those is a question
the object set may answer. A statement nobody can read publishes the
inconclusive verdict with the judge's own word beside it and no confidence; an
absent field falls back to the objects and records that it did.

Two fixtures stand for the two live answers. ``RECORDED_PUTTY_ASSESSMENT`` is
what the model actually wrote, which has no ``verdict`` field, and it is
replayed unchanged. ``_putty_stating`` is that same answer with the field the
new prompt asks for added, which is a fixture for the answer the judge is
expected to give and not a recording of one. The judge's own words are kept and
the sample's own values are replaced.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.outcome import (
    INCONCLUSIVE_VERDICT,
    decide_from_bundle,
    normalise_verdict,
    read_stated_verdict,
    stated_confidence,
    unrecognised_verdict_reason,
)
from maljan.pipeline.validation import (
    ASSESSMENT_CONFLICT_CODE,
    UNRECOGNISED_VERDICT_CODE,
    UNSTATED_VERDICT_CODE,
    assessment_conflict_violations,
    stated_verdict_violations,
)
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import MALWARE_UNDER_BENIGN_CODE, ExtendedSTIXRenderer
from maljan.schemas.stix_models import Bundle

SHA256 = "d0" + "1f" * 31

# The judge's answer on the signed utility, as it was written: a malware object
# it called a container, and an assessment that calls the sample benign.
PUTTY_MALWARE_OBJECT: dict[str, Any] = {
    "type": "malware",
    "id": "malware--b2c3d4e5-f6a7-4901-bcde-f12345678901",
    "name": "PuTTY",
    "is_family": False,
    "malware_types": ["utility"],
    "description": "PuTTY SSH client. Legitimate open-source terminal emulator.",
}

# No ``verdict`` key, which is the whole point of this one: the field did not
# exist when the run was recorded, and every stored run looks like this.
RECORDED_PUTTY_ASSESSMENT: dict[str, Any] = {
    "severity": {
        "rating": "Informational",
        "rationale": (
            "The sample is a legitimate, widely used open-source application signed by its "
            "author. It exhibits capabilities common to terminal emulators but no malicious "
            "intent or behavior was detected."
        ),
    },
    "malware_category": "legitimate-utility",
    "confidence": 1.0,
}

# The other live answer: a packed Windows executable the judge did call malware.
SAMPLE_A_ASSESSMENT: dict[str, Any] = {
    "verdict": "Malware",
    "severity": {"rating": "High", "rationale": "process hollowing and sandbox evasion"},
    "malware_category": "loader",
    "confidence": 0.85,
}


def _bundle(objects: list[dict[str, Any]], assessment: dict[str, Any] | None) -> Bundle:
    payload: dict[str, Any] = {"type": "bundle", "objects": objects}
    if assessment is not None:
        payload["x_maljan_assessment"] = assessment
    return Bundle.model_validate(payload)


def _recorded_putty() -> Bundle:
    """The recorded answer, replayed with nothing added to it."""
    return _bundle([PUTTY_MALWARE_OBJECT], dict(RECORDED_PUTTY_ASSESSMENT))


def _putty_stating(verdict: str) -> Bundle:
    """The recorded answer with the verdict the new prompt asks for added."""
    return _bundle([PUTTY_MALWARE_OBJECT], {**RECORDED_PUTTY_ASSESSMENT, "verdict": verdict})


def _report(bundle: Bundle, decision: str) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash=SHA256,
        file_name="utility.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output=bundle.model_dump(mode="json"),
        run_summary={},
        discussion_history=[],
        final_decision=decision,
        overall_confidence=stated_confidence(bundle),
        judge_assessment=bundle.x_maljan_assessment,
        malware_category=getattr(bundle.x_maljan_assessment, "malware_category", None),
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=[],
    ).build_deterministic()


def _types(bundle: Bundle) -> list[str]:
    return [str(getattr(obj, "type", "")) for obj in bundle.objects]


class TestOneReadingOfAVerdictWord:
    """The normaliser the statement and the report builder share.

    The builder mapped ``malw…`` to Malware and ``benign…`` to Benign two
    layers below the statement, so a stricter reading up here published Malware
    for a judge the renderer would have called Benign.
    """

    def test_the_three_words_read_as_themselves(self) -> None:
        for word in ("Malware", "Benign", "Suspicious"):
            assert normalise_verdict(word) == word

    def test_case_and_whitespace_do_not_matter(self) -> None:
        assert normalise_verdict("  MALWARE ") == "Malware"
        assert normalise_verdict("benign\n") == "Benign"
        assert normalise_verdict(" suspicious") == "Suspicious"

    def test_a_qualifier_after_the_word_does_not_either(self) -> None:
        assert normalise_verdict("Benign (legitimate utility)") == "Benign"
        assert normalise_verdict("Malware - loader") == "Malware"

    def test_a_word_it_cannot_reach_is_not_guessed_at(self) -> None:
        for word in ("Clean", "Not malware", "Malicious", "Trojan", "Likely malware", "", None):
            assert normalise_verdict(word) is None, word

    def test_the_report_builder_reads_it_the_same_way(self) -> None:
        assert MalwareReportBuilder._verdict_literal("Benign (legitimate utility)") == "Benign"
        assert MalwareReportBuilder._verdict_literal("Malicious") == INCONCLUSIVE_VERDICT


class TestTheThreeAnswers:
    def test_a_word_this_pipeline_knows(self) -> None:
        stated = read_stated_verdict(_putty_stating("Benign"))

        assert (stated.recognised, stated.absent, stated.unrecognised) == ("Benign", False, False)

    def test_a_word_it_does_not(self) -> None:
        stated = read_stated_verdict(_putty_stating("Malicious"))

        assert stated.written == "Malicious"
        assert (stated.recognised, stated.absent, stated.unrecognised) == (None, False, True)

    def test_no_word_at_all(self) -> None:
        stated = read_stated_verdict(_recorded_putty())

        assert (stated.written, stated.recognised, stated.absent) == ("", None, True)
        assert stated.unrecognised is False


class TestAWordOutsideTheVocabulary:
    """The object set never decides for a judge that wrote something."""

    def test_a_benign_sounding_word_over_a_malware_object_is_never_malware(self) -> None:
        for word in ("Not malware", "Clean", "Nothing malicious"):
            assert decide_from_bundle(_putty_stating(word)) == INCONCLUSIVE_VERDICT, word

    def test_a_malicious_sounding_word_over_an_empty_bundle_is_never_benign(self) -> None:
        for word in ("Malicious", "Trojan", "Likely malware"):
            bundle = _bundle([], {"verdict": word, "confidence": 0.95})
            assert decide_from_bundle(bundle) == INCONCLUSIVE_VERDICT, word

    def test_the_judge_is_asked_once_and_told_what_it_wrote(self) -> None:
        violations = stated_verdict_violations(_putty_stating("Malicious"))

        assert [v.code for v in violations] == [UNRECOGNISED_VERDICT_CODE]
        assert violations[0].path == "x_maljan_assessment.verdict"
        assert "'Malicious'" in violations[0].message
        assert "Malware, Suspicious, Benign" in violations[0].message

    def test_nothing_is_published_as_its_confidence(self) -> None:
        assert stated_confidence(_putty_stating("Malicious")) is None

    def test_the_judge_own_word_travels_to_the_report(self) -> None:
        reason = unrecognised_verdict_reason(_putty_stating("Malicious"))

        assert "'Malicious'" in reason
        assert INCONCLUSIVE_VERDICT in reason
        assert unrecognised_verdict_reason(_putty_stating("Benign")) == ""
        assert unrecognised_verdict_reason(_recorded_putty()) == ""

    def test_the_retry_that_answers_a_word_it_knows_is_published(self) -> None:
        import asyncio
        import json
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        answers = [
            json.dumps(
                {
                    "type": "bundle",
                    "objects": [PUTTY_MALWARE_OBJECT],
                    "x_maljan_assessment": {**RECORDED_PUTTY_ASSESSMENT, "verdict": "Malicious"},
                }
            ),
            json.dumps(
                {
                    "type": "bundle",
                    "objects": [],
                    "x_maljan_assessment": {**RECORDED_PUTTY_ASSESSMENT, "verdict": "Benign"},
                }
            ),
        ]

        class _Llm:
            async def ainvoke(self, turns: Any) -> Any:
                return MagicMock(content=answers.pop(0))

        judge = JudgeAgent.__new__(JudgeAgent)
        judge.llm = _Llm()
        judge.logger = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None

        verdict = asyncio.run(judge.give_verdict(reports={"static": "signed"}, history=[]))

        assert verdict.retries == 1
        assert verdict.fed_back.get(UNRECOGNISED_VERDICT_CODE) == 1
        assert [v.code for v in verdict.violations] == []
        assert decide_from_bundle(verdict.bundle) == "Benign"
        assert stated_confidence(verdict.bundle) == 1.0


class TestTheRecordedAnswerReplayedUnchanged:
    """What the model actually wrote, with nothing added to it.

    The field did not exist when this was recorded, so the bundle states no
    verdict and the object set answers — which is the fail-safe, not a
    decision. The run says so, and publishes no confidence for a verdict its
    judge did not reach.
    """

    def test_the_objects_still_answer(self) -> None:
        assert decide_from_bundle(_recorded_putty()) == "Malware"

    def test_the_reading_is_recorded_as_unstated(self) -> None:
        violations = stated_verdict_violations(_recorded_putty())

        assert [v.code for v in violations] == [UNSTATED_VERDICT_CODE]
        assert violations[0].path == "x_maljan_assessment.verdict"

    def test_no_confidence_is_published_for_it(self) -> None:
        """The judge's 1.0 was about its own assessment, not about this verdict."""
        assert _recorded_putty().x_maljan_assessment.confidence == 1.0
        assert stated_confidence(_recorded_putty()) is None
        assert _report(_recorded_putty(), "Malware").overall_confidence is None

    def test_the_report_header_says_so(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        markdown = MarkdownRenderer().render(_report(_recorded_putty(), "Malware"))

        assert "**Overall Confidence**: not assessed" in markdown
        assert "1.00" not in markdown.split("## ")[0]

    def test_it_survives_the_retry_and_is_still_recorded(self) -> None:
        import asyncio
        import json
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        answer = json.dumps(
            {
                "type": "bundle",
                "objects": [PUTTY_MALWARE_OBJECT],
                "x_maljan_assessment": RECORDED_PUTTY_ASSESSMENT,
            }
        )

        class _Llm:
            def __init__(self) -> None:
                self.calls = 0

            async def ainvoke(self, turns: Any) -> Any:
                self.calls += 1
                return MagicMock(content=answer)

        llm = _Llm()
        judge = JudgeAgent.__new__(JudgeAgent)
        judge.llm = llm
        judge.logger = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None

        verdict = asyncio.run(judge.give_verdict(reports={"static": "signed"}, history=[]))

        assert (llm.calls, verdict.retries) == (2, 1)
        assert UNSTATED_VERDICT_CODE in [v.code for v in verdict.violations]
        assert decide_from_bundle(verdict.bundle) == "Malware"
        assert stated_confidence(verdict.bundle) is None


class TestTheSignedUtilityWithTheFieldStated:
    def test_the_stated_verdict_is_the_one_read(self) -> None:
        assert decide_from_bundle(_putty_stating("Benign")) == "Benign"

    def test_the_object_set_no_longer_decides(self) -> None:
        """The same objects, with the judge saying each of the three things."""
        for verdict in ("Benign", "Suspicious", "Malware"):
            assert decide_from_bundle(_putty_stating(verdict)) == verdict

    def test_the_contradiction_is_still_recorded(self) -> None:
        violations = assessment_conflict_violations(_putty_stating("Benign"))

        assert {v.code for v in violations} == {ASSESSMENT_CONFLICT_CODE}
        assert "objects" in {v.path for v in violations}

    def test_the_published_confidence_is_the_judge_own(self) -> None:
        assert stated_confidence(_putty_stating("Benign")) == 1.0

    def test_the_export_carries_no_malware_object(self) -> None:
        renderer = ExtendedSTIXRenderer()
        bundle = _putty_stating("Benign")

        exported = renderer.render(_report(bundle, "Benign"), base_bundle=bundle)

        assert "malware" not in _types(exported)
        assert [code for code, _why in renderer.declined] == [MALWARE_UNDER_BENIGN_CODE]

    def test_the_decline_says_which_object_and_why(self) -> None:
        renderer = ExtendedSTIXRenderer()
        bundle = _putty_stating("Benign")

        renderer.render(_report(bundle, "Benign"), base_bundle=bundle)

        _code, why = renderer.declined[0]
        assert "PuTTY" in why
        assert "Benign" in why

    def test_nothing_in_the_export_dangles(self) -> None:
        bundle = _putty_stating("Benign")

        exported = ExtendedSTIXRenderer().render(_report(bundle, "Benign"), base_bundle=bundle)

        ids = {obj.id for obj in exported.objects}
        for obj in exported.objects:
            for ref in ("source_ref", "target_ref"):
                target = getattr(obj, ref, None)
                if target is not None:
                    assert target in ids, f"{ref} of {obj.type} points at nothing"
            for ref_id in getattr(obj, "object_refs", None) or []:
                assert ref_id in ids

    def test_the_judge_own_bundle_keeps_the_object(self) -> None:
        """Declining to export is not editing: the run's record is unchanged."""
        bundle = _putty_stating("Benign")

        ExtendedSTIXRenderer().render(_report(bundle, "Benign"), base_bundle=bundle)

        assert "malware" in _types(bundle)


class TestTheSampleTheJudgeCalledMalware:
    @staticmethod
    def _bundle() -> Bundle:
        return _bundle(
            [
                {
                    "type": "malware",
                    "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "loader",
                    "is_family": False,
                }
            ],
            SAMPLE_A_ASSESSMENT,
        )

    def test_the_stated_verdict_is_malware(self) -> None:
        bundle = self._bundle()

        assert decide_from_bundle(bundle) == "Malware"
        assert assessment_conflict_violations(bundle) == []

    def test_its_malware_object_is_exported(self) -> None:
        bundle = self._bundle()
        renderer = ExtendedSTIXRenderer()

        exported = renderer.render(_report(bundle, "Malware"), base_bundle=bundle)

        assert "malware" in _types(exported)
        assert renderer.declined == []


class TestABundleThatStatesNothing:
    def test_the_reading_names_the_vocabulary(self) -> None:
        violations = stated_verdict_violations(_recorded_putty())

        assert "Malware, Suspicious, Benign" in violations[0].message

    def test_a_fallback_bundle_is_not_asked_for_a_second_verdict(self) -> None:
        bundle = Bundle.model_validate(
            {
                "objects": [],
                "x_maljan_fallback_verdict": {"decision": "Suspicious", "source": "extracted"},
            }
        )

        assert stated_verdict_violations(bundle) == []
        assert decide_from_bundle(bundle) == "Suspicious"


class TestTheReportNamesWhatTheExportLeftOut:
    """``report.md`` says what is not in the bundle, not only the stored JSON.

    The markdown prints ``run_summary.validation.unresolved``, and it used to be
    rendered before the export's declines were written there — so the one
    surface a reader opens named neither the malware object the export dropped
    nor the reason.
    """

    @staticmethod
    def _run() -> dict[str, Any]:
        import asyncio

        from maljan.pipeline.nodes import make_report_node
        from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import (
            _report_container,
            _report_state,
        )

        state = _report_state(None)
        state.update(
            {
                "final_decision": "Benign",
                "stix_output": _putty_stating("Benign").model_dump(mode="json"),
            }
        )
        update = asyncio.run(make_report_node(_report_container())(state))
        assert update.get("report_error") is None
        return update

    def test_the_markdown_names_the_code_and_the_reason(self) -> None:
        update = self._run()

        markdown = update["malware_report_markdown"]
        assert MALWARE_UNDER_BENIGN_CODE in markdown
        assert "not in the exported bundle" in markdown

    def test_the_stored_summary_carries_the_same_row(self) -> None:
        update = self._run()

        rows = update["malware_report"]["run_summary"]["validation"]["unresolved"]
        assert MALWARE_UNDER_BENIGN_CODE in [row["code"] for row in rows]


class TestAStoredReportWithoutTheField:
    def test_it_still_parses(self) -> None:
        """Every run before this field existed has a bundle without it."""
        bundle = _recorded_putty()

        assert bundle.x_maljan_assessment is not None
        assert bundle.x_maljan_assessment.verdict is None
        assert bundle.x_maljan_assessment.severity is not None

    def test_a_stated_benign_with_nothing_to_contradict_exports_plainly(self) -> None:
        bundle = _bundle(
            [],
            {
                "verdict": "Benign",
                "severity": {"rating": "Informational", "rationale": "signed and clean"},
                "confidence": 0.9,
            },
        )
        renderer = ExtendedSTIXRenderer()

        exported = renderer.render(_report(bundle, "Benign"), base_bundle=bundle)

        assert renderer.declined == []
        assert assessment_conflict_violations(bundle) == []
        assert "malware" not in _types(exported)
        assert set(_types(exported)) <= {"identity", "indicator", "note", "report"}
