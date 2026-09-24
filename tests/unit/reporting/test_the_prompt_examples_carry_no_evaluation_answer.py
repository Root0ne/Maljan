"""The words shown to the report models describe nothing an evaluation scores.

A local model copies the shape it is shown, and sometimes the words. An example
that describes the behaviour a scoring key expects lets a model that copies it
"find" the key's items with no evidence behind them, which makes the score
meaningless and puts the platform's words in text the report labels as the
model's. So the examples describe an invented sample of a different class, and
this test holds them to it: no string value of any example may carry one of the
distinctive terms of the evaluation key below. The same holds for everything
else the models are shown on every run — the answer contract, both system
prompts and each section's instruction — because an id in a contract or a rule
is copied as readily as one in an example.

The list is data owned by this test, drawn from the behaviours, identifiers,
values and technique ids the key scores. A term is matched case-insensitively
as a substring: of any example's string values (the keys of the answer object
are the schema's own names and are not checked), and of the whole text of the
contract, the prompts and the instructions.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from maljan.agents.judge_agent import COMPACT_BUNDLE_RULES, verdict_cut_violation
from maljan.pipeline.validation import (
    CapabilityGrounding,
    absence_claim_violation,
    analyst_cut_violation,
    claim_does_not_describe_violation,
    repeated_item_violations,
    section_cut_violation,
    ungrounded_capabilities,
    validate_verdict_bundle,
)
from maljan.reporting.composer import (
    _EXAMPLES,
    _INSTRUCTIONS,
    _PROSE_SECTIONS,
    _SYSTEM,
    PUBLISHED_TECHNIQUES_HEADING,
    RULE_ONLY_NOTE,
    SECTION_SCHEMAS,
    WHERE_QUOTED_LEAD,
    section_contract,
)
from maljan.reporting.narrative_agent import _SYSTEM_PROMPT, EXAMPLE_OBJECT, EXPECTED_OBJECT
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    JUDGE_ONLY_TECHNIQUE_MARKER,
    ClaimEvidence,
)
from maljan.schemas.stix_models import Bundle
from maljan.tools import knowledge

# The distinctive terms of the evaluation key: how the scored sample resolves its
# APIs, checks its host, persists, configures itself, talks to its server and
# what its commands do, and the technique ids the key expects.
KEY_TERMS: tuple[str, ...] = (
    "crc32",
    "fnv",
    "rc4",
    "peb",
    "beingdebugged",
    "debugger",
    "wow64",
    "mac address",
    "process count",
    "running processes",
    "mutex",
    "single instance",
    "scheduled task",
    "logon",
    "rundll32",
    "appdata",
    "self-delet",
    "alternate data stream",
    "by hash",
    "hashing export",
    "export name",
    "api hash",
    "resolves its",
    "loader",
    "downloader",
    "64-bit dll",
    "volume serial",
    "bot id",
    "group id",
    "campaign",
    "https post",
    "post request",
    "beacon",
    "base64",
    "key=value",
    "user-agent",
    "sleep",
    "update_data",
    "c2 url",
    "xor",
    "string decryption",
    "run_exe",
    "download",
    "shellcode",
    "desktop",
    "process list",
    "ipconfig",
    "systeminfo",
    "nltest",
    "net view",
    "whoami",
    "domain trust",
    "antivirus",
    "t1053.005",
    "t1218.011",
    "t1071.001",
    "t1027",
    "t1055",
    "t1070.004",
    "t1059.003",
    "t1105",
    "t1622",
    "t1497",
    # The key-writer's derived mapping and the reports' remaining rows.
    "t1106",
    "t1027.007",
    "t1140",
    "t1573",
    "t1132",
    "t1082",
    "t1016",
    "t1482",
    "t1057",
    "t1083",
    "t1480",
    "t1036",
    "t1069.002",
    "t1135",
    "t1518.001",
    "t1033",
    "t1059.007",
    "t1047",
    "t1218.007",
    # Identifiers and values the key names.
    "/live/",
    "updater",
    "custom_update",
    "runnung",
    "msie 7",
    "wininet",
    "getadaptersinfo",
    "12345",
    "0x19660d",
    "wtfbbq",
    "tob 1.1",
    "guid=",
    "proclist",
    "desklinks",
    "clearurl",
    "ifconfig.me",
    "iphlpapi",
    "bp.dat",
    "scub",
    "follower",
)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


EXAMPLES: dict[str, str] = {"narrative": EXAMPLE_OBJECT, **_EXAMPLES}

# Everything else a report model is shown on every run, as plain text.
PROMPTS: dict[str, str] = {
    "narrative contract": EXPECTED_OBJECT,
    "narrative system prompt": _SYSTEM_PROMPT,
    "composer system prompt": _SYSTEM,
    **{f"composer instruction {name}": text for name, text in _INSTRUCTIONS.items()},
    "composer section titles": " ".join(_PROSE_SECTIONS.values()),
    "composer published-techniques heading": PUBLISHED_TECHNIQUES_HEADING,
    "composer claim note": WHERE_QUOTED_LEAD,
    "composer cut-at-cap question": section_cut_violation(8192).message,
    "composer cut-at-cap question on a repeating answer": section_cut_violation(
        8192, chars=20000, begun=160, distinct=20
    ).message,
    "composer repeated-items question": " ".join(
        v.message
        for v in repeated_item_violations({"items": [{"v": "x"}, {"v": "x"}]}, {"items": ("v",)})
    ),
    "analyst absence-claim question": " ".join(
        v.message
        for v in [
            absence_claim_violation(
                ClaimEvidence(
                    claim="The file holds no persistence mechanism.",
                    evidence_ref="[ev_0001]",
                    confidence=0.9,
                    technique_id="T1547",
                ),
                "T1547",
            )
        ]
        if v is not None
    ),
    "analyst question for a claim that does not describe its technique": " ".join(
        v.message
        for v in [
            claim_does_not_describe_violation(
                ClaimEvidence(
                    claim="The file opens a window.",
                    evidence_ref="[ev_0001]",
                    confidence=0.9,
                    technique_id="T1003",
                ),
                "T1003",
                knowledge,
            )
        ]
        if v is not None
    ),
    "capability questions for evading analysis and packing": " ".join(
        v.message
        for v in ungrounded_capabilities(
            "The file tries to evade analysts. It is a repacked build.",
            CapabilityGrounding(evidence_keys=frozenset({"pe_header"})),
        )
    ),
    "judge compact bundle rules": COMPACT_BUNDLE_RULES,
    "judge cut-at-cap question": verdict_cut_violation(
        8192, '{"type": "bundle", "objects": [{"type": "attack-pattern", "id": "a"}'
    ).message,
    "absence marker": ABSENCE_TECHNIQUE_MARKER,
    "capability questions for the anti-analysis and anti-forensics terms": " ".join(
        v.message
        for v in ungrounded_capabilities(
            "The file uses anti-analysis tricks and anti-forensics routines.",
            CapabilityGrounding(evidence_keys=frozenset({"pe_header"})),
        )
    ),
    "rule-match-only note": RULE_ONLY_NOTE,
    "judge-only technique note": JUDGE_ONLY_TECHNIQUE_MARKER,
    "analyst cut-at-cap question": analyst_cut_violation(
        4096, "CLAIM: The file opens a window.\nEVIDENCE: [ev_0001]\nCLAIM: The fi"
    ).message,
    "judge cut-at-cap question naming where the room went": verdict_cut_violation(
        8192,
        '{"type": "bundle", "objects": [{"type": "attack-pattern", "id": "a"}, '
        '{"type": "attack-pattern", "id": "b"}',
    ).message,
    "judge questions about a pattern's backslash and a shape's fixed text": " ".join(
        v.message
        for v in validate_verdict_bundle(
            Bundle.model_validate(
                {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--1",
                            "pattern": "[url:value LIKE '%one.example%']",
                            "indicator_types": ["malicious-activity"],
                        },
                        {
                            "type": "indicator",
                            "id": "indicator--2",
                            "pattern": "[file:name = 'C:\\Temp\\a.exe']",
                            "indicator_types": ["malicious-activity"],
                        },
                    ],
                }
            ),
            {"nothing here"},
        )
        if v.code in ("stix.ungrounded_indicator", "stix.unescaped_backslash")
    ),
    "judge questions about a shape naming a value and a pattern the grammar refuses": " ".join(
        v.message
        for v in validate_verdict_bundle(
            Bundle.model_validate(
                {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--1",
                            "pattern": "[domain-name:value LIKE '%one.example%']",
                            "indicator_types": ["malicious-activity"],
                        },
                        {
                            "type": "indicator",
                            "id": "indicator--2",
                            "pattern": "[url:value MATCHES '^two\\\\.example$']",
                            "indicator_types": ["malicious-activity"],
                        },
                        {
                            "type": "indicator",
                            "id": "indicator--3",
                            "pattern": "[file:name =]",
                            "indicator_types": ["malicious-activity"],
                        },
                    ],
                }
            ),
            {"host one.example and two.example seen"},
        )
        if v.code in ("stix.shape_names_a_value", "stix.pattern_refused")
    ),
}

# Each composer section's whole contract — the object, the lines on how to
# write it and its example — with the object's key names taken out: a key is
# the schema's own name, the one part of a contract a model is not writing.
_KEY_NAME_RE = re.compile(r'"[a-z_]+":')
CONTRACTS: dict[str, str] = {
    name: _KEY_NAME_RE.sub(" ", section_contract(name, schema))
    for name, schema in SECTION_SCHEMAS.items()
}


@pytest.mark.parametrize("name", sorted(EXAMPLES))
def test_no_example_carries_a_term_the_key_scores(name: str) -> None:
    text = " ".join(_strings(json.loads(EXAMPLES[name]))).lower()
    shared = [term for term in KEY_TERMS if term in text]
    assert not shared, f"the {name} example carries {shared}"


@pytest.mark.parametrize("name", sorted(PROMPTS))
def test_no_contract_prompt_or_instruction_carries_a_term_the_key_scores(name: str) -> None:
    text = PROMPTS[name].lower()
    shared = [term for term in KEY_TERMS if term in text]
    assert not shared, f"the {name} carries {shared}"


@pytest.mark.parametrize("name", sorted(CONTRACTS))
def test_no_section_contract_carries_a_term_the_key_scores(name: str) -> None:
    text = CONTRACTS[name].lower()
    shared = [term for term in KEY_TERMS if term in text]
    assert not shared, f"the {name} contract carries {shared}"


def test_every_section_the_composer_asks_for_has_its_contract_read() -> None:
    assert set(SECTION_SCHEMAS) >= {"configuration", "host_identifiers"}
    assert set(SECTION_SCHEMAS) - {"prose"} <= set(_INSTRUCTIONS)


def test_the_guard_would_catch_one() -> None:
    leaked = {"steps": [{"action": "Creates a mutex and exits if it already exists"}]}
    text = " ".join(_strings(leaked)).lower()
    assert [term for term in KEY_TERMS if term in text] == ["mutex"]


def test_the_term_list_is_long_enough_to_mean_something() -> None:
    assert len(KEY_TERMS) >= 50
    assert len(set(KEY_TERMS)) == len(KEY_TERMS)


def test_the_shape_and_refusal_questions_are_both_scanned() -> None:
    text = PROMPTS["judge questions about a shape naming a value and a pattern the grammar refuses"]
    assert "write domain-name:value = 'one.example'" in text
    assert "keep the MATCHES" in text
    assert "is not a pattern the STIX grammar reads" in text


def test_every_question_built_for_this_scan_has_words_to_scan() -> None:
    """A builder that answered nothing would leave an empty text that passes."""
    assert all(PROMPTS[name].strip() for name in PROMPTS)


def test_both_new_capability_terms_are_scanned() -> None:
    text = PROMPTS["capability questions for the anti-analysis and anti-forensics terms"]

    assert "claims anti-analysis" in text and "claims anti-forensics" in text
