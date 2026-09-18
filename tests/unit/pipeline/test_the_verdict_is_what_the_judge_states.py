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
what the pipeline reads. The object set illustrates the decision; it no longer
makes it. A bundle that states nothing is still read by its objects — a stored
run, a model that omitted the field — and the reading is recorded as
``verdict.unstated`` rather than passing for a decision.

The fixtures below are the shape of the two live answers, with the judge's own
words kept and the sample's own values replaced.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.outcome import decide_from_bundle, stated_confidence, stated_verdict
from maljan.pipeline.validation import (
    ASSESSMENT_CONFLICT_CODE,
    UNSTATED_VERDICT_CODE,
    assessment_conflict_violations,
    unstated_verdict_violations,
)
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import MALWARE_UNDER_BENIGN_CODE, ExtendedSTIXRenderer
from maljan.schemas.stix_models import Bundle

SHA256 = "d0" + "1f" * 31

# The judge's answer on the signed utility, as it was written: a malware object
# it called a container, an assessment that calls the sample benign, and — the
# field this file is about — the verdict it meant.
PUTTY_MALWARE_OBJECT: dict[str, Any] = {
    "type": "malware",
    "id": "malware--b2c3d4e5-f6a7-4901-bcde-f12345678901",
    "name": "PuTTY",
    "is_family": False,
    "malware_types": ["utility"],
    "description": "PuTTY SSH client. Legitimate open-source terminal emulator.",
}

PUTTY_ASSESSMENT: dict[str, Any] = {
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


def _putty(verdict: str | None = "Benign") -> Bundle:
    assessment = dict(PUTTY_ASSESSMENT)
    if verdict is not None:
        assessment["verdict"] = verdict
    return _bundle([PUTTY_MALWARE_OBJECT], assessment)


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


class TestTheSignedUtility:
    def test_the_stated_verdict_is_the_one_read(self) -> None:
        assert stated_verdict(_putty()) == "Benign"
        assert decide_from_bundle(_putty()) == "Benign"

    def test_the_object_set_no_longer_decides(self) -> None:
        """The same objects, with the judge saying each of the three things."""
        for verdict in ("Benign", "Suspicious", "Malware"):
            assert decide_from_bundle(_putty(verdict)) == verdict

    def test_the_contradiction_is_still_recorded(self) -> None:
        violations = assessment_conflict_violations(_putty())

        assert {v.code for v in violations} == {ASSESSMENT_CONFLICT_CODE}
        assert "objects" in {v.path for v in violations}

    def test_the_published_confidence_is_the_judge_own(self) -> None:
        assert stated_confidence(_putty()) == 1.0

    def test_the_export_carries_no_malware_object(self) -> None:
        renderer = ExtendedSTIXRenderer()
        bundle = _putty()

        exported = renderer.render(_report(bundle, "Benign"), base_bundle=bundle)

        assert "malware" not in _types(exported)
        assert [code for code, _why in renderer.declined] == [MALWARE_UNDER_BENIGN_CODE]

    def test_the_decline_says_which_object_and_why(self) -> None:
        renderer = ExtendedSTIXRenderer()
        bundle = _putty()

        renderer.render(_report(bundle, "Benign"), base_bundle=bundle)

        _code, why = renderer.declined[0]
        assert "PuTTY" in why
        assert "Benign" in why

    def test_nothing_in_the_export_dangles(self) -> None:
        bundle = _putty()

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
        bundle = _putty()

        ExtendedSTIXRenderer().render(_report(bundle, "Benign"), base_bundle=bundle)

        assert "malware" in _types(bundle)


class TestTheSampleTheJudgeCalledMalware:
    def test_the_stated_verdict_is_malware(self) -> None:
        bundle = _bundle(
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

        assert decide_from_bundle(bundle) == "Malware"
        assert assessment_conflict_violations(bundle) == []

    def test_its_malware_object_is_exported(self) -> None:
        bundle = _bundle(
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
        renderer = ExtendedSTIXRenderer()

        exported = renderer.render(_report(bundle, "Malware"), base_bundle=bundle)

        assert "malware" in _types(exported)
        assert renderer.declined == []


class TestABundleThatStatesNothing:
    def test_the_objects_are_read_as_before(self) -> None:
        assert decide_from_bundle(_putty(None)) == "Malware"

    def test_the_reading_is_a_violation(self) -> None:
        violations = unstated_verdict_violations(_putty(None))

        assert [v.code for v in violations] == [UNSTATED_VERDICT_CODE]
        assert violations[0].path == "x_maljan_assessment.verdict"
        assert "Malware, Suspicious, Benign" in violations[0].message

    def test_a_word_outside_the_vocabulary_is_no_statement(self) -> None:
        violations = unstated_verdict_violations(_putty("Probably malware"))

        assert [v.code for v in violations] == [UNSTATED_VERDICT_CODE]
        assert "Probably malware" in violations[0].message

    def test_the_judge_is_asked_once_and_the_reading_survives(self) -> None:
        import asyncio
        import json
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        answer = json.dumps(
            {
                "type": "bundle",
                "objects": [PUTTY_MALWARE_OBJECT],
                "x_maljan_assessment": PUTTY_ASSESSMENT,
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

        verdict = asyncio.run(judge.give_verdict(reports={"static": "nothing"}, history=[]))

        assert (llm.calls, verdict.retries) == (2, 1)
        assert UNSTATED_VERDICT_CODE in [v.code for v in verdict.violations]
        assert decide_from_bundle(verdict.bundle) == "Malware"

    def test_a_fallback_bundle_is_not_asked_for_a_second_verdict(self) -> None:
        bundle = Bundle.model_validate(
            {
                "objects": [],
                "x_maljan_fallback_verdict": {"decision": "Suspicious", "source": "extracted"},
            }
        )

        assert unstated_verdict_violations(bundle) == []
        assert decide_from_bundle(bundle) == "Suspicious"


class TestAStoredReportWithoutTheField:
    def test_it_still_parses(self) -> None:
        """Every run before this field existed has a bundle without it."""
        bundle = _putty(None)

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
