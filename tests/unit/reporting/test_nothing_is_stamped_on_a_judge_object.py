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
    IS_FAMILY_CONTRADICTS_FAMILY_CODE,
    IS_FAMILY_MISSING_CODE,
    MALWARE_TYPE_VOCABULARY_CODE,
    MALWARE_TYPES,
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


FAMILY = "Examplefamily"


def _attributed(*objects: dict) -> Bundle:
    return Bundle.model_validate(
        {
            "objects": list(objects),
            "x_maljan_assessment": {
                "verdict": "Malware",
                "confidence": 0.9,
                "family": {"name": FAMILY, "confidence": 0.9, "evidence_ids": ["ev_0001"]},
            },
        }
    )


def _malware(**written: object) -> dict:
    return {"type": "malware", "id": "malware--1", "name": FAMILY, **written}


class TestAMalwareObjectNamedForTheFamily:
    """``is_family: false`` on an object named for the attributed family is asked about."""

    def test_it_is_asked_which_it_stands_for(self) -> None:
        bundle = _attributed(_malware(is_family=False, malware_types=["trojan"]))
        rows = [
            v
            for v in validate_verdict_bundle(bundle, {"x"})
            if v.code == IS_FAMILY_CONTRADICTS_FAMILY_CODE
        ]

        assert len(rows) == 1
        assert FAMILY in rows[0].message
        assert "is_family" in rows[0].message

    def test_the_name_is_matched_whatever_its_case(self) -> None:
        bundle = _attributed(
            {**_malware(is_family=False, malware_types=["trojan"]), "name": f" {FAMILY.upper()} "}
        )

        assert IS_FAMILY_CONTRADICTS_FAMILY_CODE in [
            v.code for v in validate_verdict_bundle(bundle, {"x"})
        ]

    def test_an_object_for_this_sample_is_asked_nothing(self) -> None:
        bundle = _attributed(
            {**_malware(is_family=False, malware_types=["trojan"]), "name": f"{FAMILY} sample"}
        )
        codes = [v.code for v in validate_verdict_bundle(bundle, {"x"})]

        assert IS_FAMILY_CONTRADICTS_FAMILY_CODE not in codes

    def test_true_is_asked_nothing(self) -> None:
        bundle = _attributed(_malware(is_family=True, malware_types=["trojan"]))

        assert IS_FAMILY_CONTRADICTS_FAMILY_CODE not in [
            v.code for v in validate_verdict_bundle(bundle, {"x"})
        ]

    def test_nothing_is_rewritten(self) -> None:
        bundle = _attributed(_malware(is_family=False, malware_types=["trojan"]))
        validate_verdict_bundle(bundle, {"x"})

        assert bundle.model_dump(mode="json")["objects"][0]["is_family"] is False


class TestAMalwareObjectsKind:
    """Labels the export drops, and a type outside STIX's vocabulary, are asked about."""

    def test_labels_without_malware_types_are_asked_about(self) -> None:
        written = {"objects": [_malware(is_family=True, labels=["stealer", "bot"])]}
        bundle = _attributed(_malware(is_family=True))
        (row,) = [
            v
            for v in validate_verdict_bundle(bundle, {"x"}, written=written)
            if v.code == MALWARE_TYPE_VOCABULARY_CODE
        ]

        assert "labels" in row.message and "'stealer'" in row.message
        # The question lists the vocabulary it asks for.
        assert ", ".join(MALWARE_TYPES) in row.message

    def test_a_type_outside_the_vocabulary_is_asked_about(self) -> None:
        bundle = _attributed(_malware(is_family=True, malware_types=["stealer", "bot"]))
        (row,) = [
            v
            for v in validate_verdict_bundle(bundle, {"x"})
            if v.code == MALWARE_TYPE_VOCABULARY_CODE
        ]

        assert "'stealer'" in row.message and "'bot'" not in row.message
        assert ", ".join(MALWARE_TYPES) in row.message

    def test_types_from_the_vocabulary_are_asked_nothing(self) -> None:
        written = {"objects": [_malware(is_family=True, labels=["x"], malware_types=["bot"])]}
        bundle = _attributed(_malware(is_family=True, malware_types=["bot", "Spyware"]))

        assert MALWARE_TYPE_VOCABULARY_CODE not in [
            v.code for v in validate_verdict_bundle(bundle, {"x"}, written=written)
        ]

    def test_no_labels_and_no_types_are_asked_nothing(self) -> None:
        bundle = _attributed(_malware(is_family=True))

        assert MALWARE_TYPE_VOCABULARY_CODE not in [
            v.code for v in validate_verdict_bundle(bundle, {"x"}, written={"objects": []})
        ]

    def test_the_vocabulary_is_stix_2_1_s(self) -> None:
        assert set(MALWARE_TYPES) == {
            "adware",
            "backdoor",
            "bot",
            "bootkit",
            "ddos",
            "downloader",
            "dropper",
            "exploit-kit",
            "keylogger",
            "ransomware",
            "remote-access-trojan",
            "resource-exploitation",
            "rogue-security-software",
            "rootkit",
            "screen-capture",
            "spyware",
            "trojan",
            "virus",
            "webshell",
            "wiper",
            "worm",
            "unknown",
        }

    def test_the_prompt_says_when_an_object_stands_for_the_family(self) -> None:
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM, MALWARE_OBJECT_RULE

        assert MALWARE_OBJECT_RULE in JUDGE_VERDICT_SYSTEM
        assert "family.name" in MALWARE_OBJECT_RULE
        assert "malware_types" in MALWARE_OBJECT_RULE
        assert "malware-type-ov" in MALWARE_OBJECT_RULE
