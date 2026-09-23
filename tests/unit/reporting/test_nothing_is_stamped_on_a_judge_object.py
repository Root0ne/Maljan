"""A property the judge did not write is not written for it.

Two model defaults answered for the judge. An indicator with no
``indicator_types`` was published as ``malicious-activity`` — and on a Benign
verdict the judge was then asked why it had typed the indicator
``malicious-activity``, a word it never wrote. A malware object with no
``is_family`` was published as ``false``. STIX 2.1 makes ``indicator_types``
optional, so an absent one stays absent; it requires ``is_family``, so an absent
one is asked about, once, and never filled in.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE,
    INDICATOR_TYPE_VOCABULARY_CODE,
    IS_FAMILY_MISSING_CODE,
    validate_verdict_bundle,
)
from maljan.schemas.stix_models import Bundle

DOMAIN = "putty.projects.tartarus.org"


def _bundle(verdict: str, *objects: dict) -> Bundle:
    return Bundle.model_validate(
        {
            "objects": list(objects),
            "x_maljan_assessment": {"verdict": verdict, "confidence": 0.9},
        }
    )


def _untyped_indicator() -> dict:
    return {
        "type": "indicator",
        "id": "indicator--1",
        "pattern": f"[domain-name:value = '{DOMAIN}']",
        "pattern_type": "stix",
    }


class TestAnUntypedIndicator:
    def test_it_is_published_without_a_type(self) -> None:
        dumped = _bundle("Malware", _untyped_indicator()).model_dump(mode="json")

        assert "indicator_types" not in dumped["objects"][0]

    def test_it_is_asked_about_no_word_it_did_not_write(self) -> None:
        codes = [
            v.code
            for v in validate_verdict_bundle(_bundle("Benign", _untyped_indicator()), {DOMAIN})
        ]

        assert INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE not in codes
        assert INDICATOR_TYPE_VOCABULARY_CODE not in codes


class TestAMalwareObjectWithoutIsFamily:
    def test_it_is_published_without_one(self) -> None:
        dumped = _bundle(
            "Malware", {"type": "malware", "id": "malware--1", "name": "x"}
        ).model_dump(mode="json")

        assert "is_family" not in dumped["objects"][0]

    def test_it_is_asked_about(self) -> None:
        bundle = _bundle("Malware", {"type": "malware", "id": "malware--1", "name": "x"})
        rows = [
            v for v in validate_verdict_bundle(bundle, {"x"}) if v.code == IS_FAMILY_MISSING_CODE
        ]

        assert len(rows) == 1
        assert "is_family" in rows[0].message

    def test_one_the_judge_stated_is_asked_nothing(self) -> None:
        bundle = _bundle(
            "Malware", {"type": "malware", "id": "malware--1", "name": "x", "is_family": False}
        )

        assert IS_FAMILY_MISSING_CODE not in [
            v.code for v in validate_verdict_bundle(bundle, {"x"})
        ]
