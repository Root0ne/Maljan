"""A Benign verdict beside an indicator typed ``malicious-activity``.

A recorded run on a signed vendor utility concluded Benign at 0.95 with the
category ``legitimate_software``, and the judge wrote the vendor's own project
domain as an indicator typed ``malicious-activity``. The export keeps a
judge-written type, so the vendor's domain went to whoever consumes the bundle
as malicious activity, with nothing anywhere saying the two statements
disagree.

The type stays the judge's to give: nothing rewrites it and nothing drops the
object. The platform asks once, with the vocabulary's milder words named, and
publishes whatever the judge answers — recording a type that is kept, so a
consumer reading the bundle beside the report sees the contradiction was
raised.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.validation import (
    INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE,
    validate_verdict_bundle,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import JudgeAssessment
from maljan.schemas.stix_models import Bundle, Indicator

# The recorded run's two indicators and the sample they were written for.
SAMPLE_SHA256 = "d01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87"
VENDOR_DOMAIN = "putty.projects.tartarus.org"


def _sample_hash_indicator(indicator_type: str) -> Indicator:
    return Indicator(
        name=f"Sample hash {SAMPLE_SHA256[:12]}",
        pattern=f"[file:hashes.'SHA-256' = '{SAMPLE_SHA256}']",
        pattern_type="stix",
        indicator_types=[indicator_type],
    )


def _vendor_domain_indicator(indicator_type: str = "malicious-activity") -> Indicator:
    return Indicator(
        name="PuTTY Domain",
        pattern=f"[domain-name:value = '{VENDOR_DOMAIN}']",
        pattern_type="stix",
        indicator_types=[indicator_type],
    )


def _bundle(verdict: str, *indicators: Indicator) -> Bundle:
    return Bundle(
        objects=list(indicators),
        x_maljan_assessment=JudgeAssessment(verdict=verdict, confidence=0.95),
    )


def _codes(bundle: Bundle) -> list[str]:
    return [
        v.code
        for v in validate_verdict_bundle(
            bundle,
            {SAMPLE_SHA256, VENDOR_DOMAIN},
            sample={"sha256": SAMPLE_SHA256},
        )
    ]


def _rows(bundle: Bundle) -> list[str]:
    return [
        v.message
        for v in validate_verdict_bundle(
            bundle,
            {SAMPLE_SHA256, VENDOR_DOMAIN},
            sample={"sha256": SAMPLE_SHA256},
        )
        if v.code == INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE
    ]


def test_the_recorded_bundle_is_asked_about_its_vendor_domain() -> None:
    bundle = _bundle("Benign", _sample_hash_indicator("benign"), _vendor_domain_indicator())

    assert _codes(bundle).count(INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE) == 1


def test_the_sentence_names_the_indicator_the_verdict_and_the_alternatives() -> None:
    bundle = _bundle("Benign", _vendor_domain_indicator())

    (message,) = _rows(bundle)

    assert "PuTTY Domain" in message
    assert "malicious-activity" in message
    assert "Benign" in message
    for alternative in ("benign", "anomalous-activity", "unknown"):
        assert alternative in message
    assert "keep the type as it is" in message


def test_nothing_is_rewritten_and_nothing_is_dropped() -> None:
    """The row is a question. The bundle it was asked about is untouched."""
    indicator = _vendor_domain_indicator()
    bundle = _bundle("Benign", indicator)

    validate_verdict_bundle(bundle, {VENDOR_DOMAIN}, sample={"sha256": SAMPLE_SHA256})

    assert [obj.name for obj in bundle.objects] == ["PuTTY Domain"]
    assert indicator.indicator_types == ["malicious-activity"]


def test_the_samples_own_hash_indicator_is_not_the_contradiction() -> None:
    """That one is the verdict's own statement about the sample, not a claim."""
    bundle = _bundle("Benign", _sample_hash_indicator("malicious-activity"))

    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in _codes(bundle)


def test_a_verdict_that_is_not_benign_is_asked_nothing() -> None:
    for verdict in ("Malware", "Suspicious"):
        bundle = _bundle(verdict, _vendor_domain_indicator())
        assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in _codes(bundle)


def test_the_mirror_case_is_not_a_contradiction() -> None:
    """A malicious sample may touch something harmless; that is not a conflict."""
    bundle = _bundle("Malware", _vendor_domain_indicator("benign"))

    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in _codes(bundle)


def test_a_benign_verdict_with_milder_types_is_asked_nothing() -> None:
    for indicator_type in ("benign", "anomalous-activity", "unknown"):
        bundle = _bundle("Benign", _vendor_domain_indicator(indicator_type))
        assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in _codes(bundle)


def test_a_bundle_with_no_stated_verdict_is_asked_nothing() -> None:
    bundle = Bundle(objects=[_vendor_domain_indicator()])

    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in _codes(bundle)


# The judge's own loop: asked once, and what it answers is what is published.

_BENIGN_JSON = (
    '{"type": "bundle", "objects": [{"type": "indicator", "name": "PuTTY Domain", '
    '"pattern": "[domain-name:value = \''
    + VENDOR_DOMAIN
    + '\']", "pattern_type": "stix", "indicator_types": ["%s"], '
    '"valid_from": "2026-09-19T22:49:52Z"}], '
    '"x_maljan_assessment": {"verdict": "Benign", "confidence": 0.95, '
    '"malware_category": "legitimate_software", '
    '"severity": {"rating": "Informational", "rationale": "a signed vendor utility"}}}'
)


def _judge(answers: list[str], seen: list[str]) -> Any:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]
    queue = list(answers)

    class _Model:
        async def ainvoke(self, messages: Any) -> Any:
            seen.append("\n".join(str(getattr(m, "content", m)) for m in messages))
            return MagicMock(content=queue.pop(0) if queue else answers[-1])

    judge.llm = _Model()
    return judge


def _claims() -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[ClaimEvidence(claim="signed", evidence_ref="ev_0001", confidence=0.9)],
        )
    }


def _ask(judge: Any) -> Any:
    return asyncio.run(
        judge.give_verdict(
            reports={"static": "a signed vendor utility"},
            history=[],
            isr_reports=_claims(),
            evidence_corpus={VENDOR_DOMAIN},
            sample={"sha256": SAMPLE_SHA256},
            ledger_ids=["ev_0001"],
        )
    )


def test_the_judge_is_asked_once_and_a_retyped_indicator_settles_it() -> None:
    seen: list[str] = []
    verdict = _ask(_judge([_BENIGN_JSON % "malicious-activity", _BENIGN_JSON % "unknown"], seen))

    assert len(seen) == 2
    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE in seen[1]
    assert verdict.retries == 1
    assert verdict.fed_back.get(INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE) == 1
    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in [v.code for v in verdict.violations]
    assert [o.indicator_types for o in verdict.bundle.objects] == [["unknown"]]


def test_a_type_the_judge_keeps_is_published_and_recorded() -> None:
    seen: list[str] = []
    verdict = _ask(_judge([_BENIGN_JSON % "malicious-activity"] * 2, seen))

    assert len(seen) == 2, "asked once, and no second retry"
    assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE in [v.code for v in verdict.violations]
    assert [o.indicator_types for o in verdict.bundle.objects] == [["malicious-activity"]]
