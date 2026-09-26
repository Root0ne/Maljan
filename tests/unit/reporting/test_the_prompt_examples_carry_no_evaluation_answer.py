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
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.base_agent import (
    FINAL_ANSWER_NUDGE,
    INPUT_SHORTENED_NOTICE,
    SPEND_CEILING_QUESTION,
    ClaimRead,
    claims_unread_sentence,
)
from maljan.agents.delegation import (
    SPEND_CEILING_REFUSAL,
    WAITING_ON_EACH_OTHER_REFUSAL,
    _what_an_ask_gets_sentence,
)
from maljan.agents.ghidra_http_client import no_program_as_error
from maljan.agents.judge_agent import (
    COMPACT_BUNDLE_RULES,
    EVIDENCE_SHORTENED_NOTICE,
    LOWERED_ENTRY_MARK,
    NO_ENTRY_TEXT,
    PARTIAL_ENTRY_MARK,
    PROMPT_SHORTENED_NOTICE,
    TECHNIQUE_ANSWER_FORM,
    TECHNIQUE_ANSWER_UNREAD,
    TECHNIQUE_QUESTION_NOT_ASKED,
    TECHNIQUE_QUESTION_SYSTEM,
    technique_question_head,
    technique_question_text,
    verdict_cut_violation,
)
from maljan.agents.network_analyst import NO_PACKET_TOOL_LINE, OTHER_TOOLS_THEN_ANALYZE
from maljan.agents.prompt_fragments import (
    ENDPOINTS_ROW_SHAPE,
    NO_TOOLS_STATEMENT,
    TOOL_FREE_TURN_STATEMENT,
    tools_statement,
)
from maljan.agents.prompts import (
    ANDROID_STATIC_PROMPT,
    LEAD_PROMPT,
    REVERSER_PROMPT,
    TRIAGE_PROMPT,
)
from maljan.agents.static_analyst import (
    _extract_load_hint,
    _reframe_static_raw_data,
    _tool_use_line,
)
from maljan.agents.tool_pinning import (
    UNREADABLE_FILLED_CAPTURE,
    UNREADABLE_FILLED_CAPTURE_REMEDIATION,
)
from maljan.analysis.function_summarizer import SHORTENED_NOTE as SUMMARISER_SHORTENED_NOTE
from maljan.analysis.pcap_summary import CaptureRead
from maljan.extractors.capability_matrix import NOT_ASKED_UNKNOWN_ID, TechniqueQuestion
from maljan.llm.openai_provider import NO_REPLY_RECORDED
from maljan.pipeline import triage_pack
from maljan.pipeline.nodes import (
    NO_SANDBOX_DATA_REASON,
    NO_STATIC_FIXTURE_NOTE,
    skipped_analysts_reason,
)
from maljan.pipeline.run_state import NO_LIMIT, budget_line
from maljan.pipeline.validation import (
    ANALYST_FEEDBACK_CLOSING,
    CapabilityGrounding,
    EntryTexts,
    _term_ids_said,
    absence_claim_violation,
    analyst_cut_violation,
    claim_does_not_describe_violation,
    gate_removed_note,
    misstated_entry_contents,
    repeated_item_violations,
    section_cut_violation,
    technique_line_violation,
    ungrounded_capabilities,
    validate_verdict_bundle,
)
from maljan.providers.base import STATIC_EVIDENCE_INSTRUCTIONS, absent_provider_fragment
from maljan.providers.static.ghidra import (
    GHIDRA_GUIDANCE,
    ghidra_not_answering,
    sample_not_opened,
)
from maljan.providers.static.null import NullStaticProvider
from maljan.providers.static.r2 import r2_error_reply
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
from maljan.reporting.renderers.stix_renderer import (
    BENIGN_NAME_IN_A_URL,
    BENIGN_NAME_RESOLVED,
    FLOW_OUTSIDE_THE_TREE,
    UNATTRIBUTED_FLOW,
    disputed_flow_reason,
    not_kept_reason,
)
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    JUDGE_ONLY_TECHNIQUE_MARKER,
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    ClaimEvidence,
    judge_dropped_reason,
    judge_kept_note,
)
from maljan.schemas.stix_models import Bundle
from maljan.tools import knowledge
from maljan.tools.errors import CAPTURES_REMEDIATION, NO_CAPTURE_REMEDIATION

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


class _StampedTool:
    """A tool as the registry hands it over, for the tool statement's words."""

    def __init__(self, name: str, server: str = "") -> None:
        self.name = name
        self.metadata = {"maljan_server": server} if server else {}


# The prompts the example team document ships for an operator to import.
def _spend_sentences() -> str:
    """The spend ceiling's degradation reason and one refusal, as the run states them."""
    from maljan.core.spend import SpendCeilingStop, SpendMeter

    meter = SpendMeter(
        0.01, {"m": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 1.0}}, table={}
    )
    meter.settle({"input_tokens": 0, "output_tokens": 5_000}, "m")
    try:
        meter.admit(kind="loop turn", model="m", prompt_chars=3_000, cap_tokens=10_000)
    except SpendCeilingStop as stop:
        refused = str(stop)
    return f"{meter.reason()} {refused}"


_TEAM_DOCUMENT = (
    Path(__file__).resolve().parents[3] / "docs" / "examples" / "profiles" / "all-tools.json"
)
_TEAM_DOCUMENT_PROMPTS = " ".join(
    str(entry.get("prompt") or "")
    for entry in json.loads(_TEAM_DOCUMENT.read_text(encoding="utf-8"))["values"][
        "core.agents.definitions"
    ].values()
)


# Everything else a report model is shown on every run, as plain text.
PROMPTS: dict[str, str] = {
    "example team document prompts": _TEAM_DOCUMENT_PROMPTS,
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
    "analyst retry closing line": ANALYST_FEEDBACK_CLOSING,
    "judge technique question": " ".join(
        [
            TECHNIQUE_QUESTION_SYSTEM,
            technique_question_text(
                [
                    TechniqueQuestion("T1003", "claimed", [("a", "x", ["ev_0001"])]),
                    TechniqueQuestion("T1112", "finding", [("b", "y", [])]),
                ],
                {"ev_0001": "entry text"},
                notice=EVIDENCE_SHORTENED_NOTICE.format(cut=1, total=2, width=10),
            ),
        ]
    ),
    "judge technique answer form": TECHNIQUE_ANSWER_FORM,
    "judge prompt shortened to its window": PROMPT_SHORTENED_NOTICE.format(
        cut=2, total=5, names="static report, evidence summary", width=900
    ),
    "a loop started past the spend ceiling": SPEND_CEILING_QUESTION,
    "an analyst input shortened to its window": INPUT_SHORTENED_NOTICE.format(
        detail="the first 1,000 of 9,000 characters are shown, ending in …"
    ),
    "a summariser prompt shortened to its window": SUMMARISER_SHORTENED_NOTE.format(
        shown=1000, total=9000
    ),
    "an ask refused at the spend ceiling": SPEND_CEILING_REFUSAL.format(callee="'helper'"),
    "the spend ceiling's reason and a call it refused": _spend_sentences(),
    "an ask refused for a mutual wait": WAITING_ON_EACH_OTHER_REFUSAL.format(callee="'helper'"),
    "the pack's decoded strings in part": triage_pack.DECODED_STRINGS_ROOM_SENTENCE.format(
        shown=10, total=90, offset=10
    ),
    "a term's example ids and how many more": _term_ids_said(["T1000", "T1001", "T1002"]),
    "run-state budget line of a loop with no limit": budget_line(NO_LIMIT, NO_LIMIT),
    "ask tool budget sentence with no limit": _what_an_ask_gets_sentence("lead", None, None),
    "judge technique question head": technique_question_head("r", "Suspicious", ["T1112"]),
    "judge technique question entry marks": " ".join(
        [PARTIAL_ENTRY_MARK, LOWERED_ENTRY_MARK, NO_ENTRY_TEXT]
    ),
    "analyst question naming the claims the gate set aside": gate_removed_note(["x"]),
    "judge technique notes": " ".join(
        [
            JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
            judge_dropped_reason("r"),
            judge_kept_note("r"),
            TECHNIQUE_QUESTION_NOT_ASKED,
            TECHNIQUE_ANSWER_UNREAD,
            NOT_ASKED_UNKNOWN_ID,
        ]
    ),
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
    "analyst tool statement naming every family": tools_statement(
        [
            _StampedTool("a", "analysis"),
            _StampedTool("ask_static", "team"),
            _StampedTool("sandbox_processes"),
            _StampedTool("load_program"),
        ],
        provider_label="the Ghidra static provider",
    ),
    "analyst tool statement for a request with none": NO_TOOLS_STATEMENT,
    "static provider sentence when none is attached": NullStaticProvider.NO_PROVIDER_FRAGMENT[
        len(STATIC_EVIDENCE_INSTRUCTIONS) :
    ],
    "a Ghidra that could not open the job's sample, as an ask's caller reads it": str(
        sample_not_opened("File not found: /data/samples/.work/a.bin")
    ),
    "a Ghidra that gave no answer to the load, as an ask's caller reads it": str(
        ghidra_not_answering("http://localhost:8089", "HTTP 401")
    ),
    "a Ghidra answer with no program current": no_program_as_error(
        "No program loaded.", "get_function_count"
    ),
    "static provider sentence when its tools did not attach": absent_provider_fragment("Ghidra")[
        len(STATIC_EVIDENCE_INSTRUCTIONS) :
    ],
    "static human-turn tool lines": " ".join(
        [
            _tool_use_line([_StampedTool("decompile_function")]),
            _tool_use_line([_StampedTool("a", "analysis")]),
            _extract_load_hint('{"analysis_file_path": "/s/a.bin"}', frozenset({"x"})),
            _extract_load_hint('{"analysis_file_path": "/s/a.bin"}', frozenset()),
        ]
    ),
    "network packet-tool lines": f"{NO_PACKET_TOOL_LINE} {OTHER_TOOLS_THEN_ANALYZE}",
    "question for an entry said to hold one line": " ".join(
        v.message
        for v in misstated_entry_contents(
            {"body": "The capture entry holds only a header line [ev_0001]."},
            EntryTexts(
                texts={"ev_0001": '{"summary": "a\\nb", "packets_read": 3}'},
                tools={"ev_0001": "pcap_summary"},
            ),
        )
    ),
    "publish rule reasons for a sandbox row": " ".join(
        [
            UNATTRIBUTED_FLOW,
            FLOW_OUTSIDE_THE_TREE,
            BENIGN_NAME_RESOLVED,
            BENIGN_NAME_IN_A_URL,
            not_kept_reason("x", "a claim by the network analyst"),
            not_kept_reason(
                f"{FLOW_OUTSIDE_THE_TREE} (SearchHost.exe (procid 104))",
                "a claim by the dynamic analyst",
            ),
            disputed_flow_reason(["SearchHost.exe (procid 104)"], ["cmd.exe (procid 7)"]),
        ]
    ),
    "the reply a tool call that was not run is sent with": NO_REPLY_RECORDED,
    "analyst question for technique lines no single id was read from": technique_line_violation(
        ["T1000 (candidate)", "T1001, T1002"]
    ).message,
    "the degradation reason for claims begun and not read": claims_unread_sentence(
        "reverser", ClaimRead(claims=[], without_confidence=1, begun=4), 2
    ),
    "failure of a capture the platform filled in": " ".join(
        [UNREADABLE_FILLED_CAPTURE, UNREADABLE_FILLED_CAPTURE_REMEDIATION]
    ),
    "capture line in the pack": triage_pack._pcap(
        {
            "packets_read": 10,
            "packets_in_capture": 12,
            "bytes": 900,
            "duration_s": 3.0,
            "protocols": {"tcp": 10},
            "conversations": [{"dst": "d", "dport": 1, "proto": "tcp", "packets": 1, "bytes": 1}],
            "beacons": [],
        }
    ),
    "capture read statement": CaptureRead(
        packets_read=10, packets_in_capture=12, limit=10
    ).statement(),
    "analyst findings block's endpoints row shape": ENDPOINTS_ROW_SHAPE,
    "capture refusal remediations": " ".join(
        [
            NO_CAPTURE_REMEDIATION.format(argument="pcap_path"),
            CAPTURES_REMEDIATION.format(argument="pcap_path", names="captures/a.pcap"),
        ]
    ),
    "radare2 refusal remediation": r2_error_reply(
        "list_functions", "No file is currently open. Call open_file first."
    )["error"]["remediation"],
    "final-answer nudge": FINAL_ANSWER_NUDGE,
    "skipped-analyst degradation reason": skipped_analysts_reason(
        NO_SANDBOX_DATA_REASON, ["dynamic", "network"]
    ),
    "seeded prompts": f"{REVERSER_PROMPT} {LEAD_PROMPT} {TRIAGE_PROMPT} {ANDROID_STATIC_PROMPT}",
    "static placeholder note": NO_STATIC_FIXTURE_NOTE,
    "static revision's reframed placeholder": _reframe_static_raw_data(
        "No static data available for sample ab.", has_tools=True
    ),
    "tool families' labels": " ".join(
        [
            tools_statement([_StampedTool("x")]),
            tools_statement(
                [_StampedTool("x")], provider_label="the cape2 sandbox's own tool server"
            ),
            tools_statement([_StampedTool("x")], provider_label="the CAPEv2 tool server"),
        ]
    ),
    "tool-free turn sentence": TOOL_FREE_TURN_STATEMENT,
    "ghidra guidance reworded for a call with no tool": GHIDRA_GUIDANCE[
        GHIDRA_GUIDANCE.index("FALSIFIED it first") : GHIDRA_GUIDANCE.index("- A claim is High")
    ],
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
