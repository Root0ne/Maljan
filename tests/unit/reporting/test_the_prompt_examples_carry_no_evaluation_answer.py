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
    claims_under_disputes_sentence,
    claims_unread_sentence,
    earlier_chunks_block,
)
from maljan.agents.delegation import (
    SPEND_CEILING_REFUSAL,
    WAITING_ON_EACH_OTHER_REFUSAL,
    _what_an_ask_gets_sentence,
)
from maljan.agents.evidence_recorder import earlier_chunk_answer, same_function_notice
from maljan.agents.ghidra_http_client import no_program_as_error
from maljan.agents.judge_agent import (
    COMPACT_BUNDLE_RULES,
    CONTRADICTION_DEFINITION,
    CONTRADICTIONS_BLOCK_QUESTION,
    CONTRADICTIONS_BLOCK_RULE,
    EVIDENCE_SHORTENED_NOTICE,
    LOWERED_ENTRY_MARK,
    MALWARE_OBJECT_RULE,
    MEDIATION_EXTRACTION_SYSTEM,
    MEDIATOR_HUMAN_CLOSING,
    MEDIATOR_SYSTEM_HEAD,
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
from maljan.agents.judge_agent import QUESTION_ROOTS_LABEL as _ROOTS_LABEL
from maljan.agents.network_analyst import NO_PACKET_TOOL_LINE, OTHER_TOOLS_THEN_ANALYZE
from maljan.agents.prompt_fragments import (
    CLAIM_FORMAT_FRAGMENT,
    ENDPOINTS_ROW_SHAPE,
    NO_TOOLS_STATEMENT,
    TOOL_FREE_TURN_STATEMENT,
    no_tool_call_question,
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
from maljan.agents.tool_fence import FENCE_STATEMENT as _FENCE_STATEMENT
from maljan.agents.tool_fence import fenced as _fenced
from maljan.agents.tool_pinning import (
    UNREADABLE_FILLED_CAPTURE,
    UNREADABLE_FILLED_CAPTURE_REMEDIATION,
)
from maljan.analysis import evidence_roots as _roots
from maljan.analysis.evidence_roots import layers_and_roots as _layers_and_roots
from maljan.analysis.evidence_roots import roots_phrase as _roots_phrase
from maljan.analysis.function_summarizer import SHORTENED_NOTE as SUMMARISER_SHORTENED_NOTE
from maljan.analysis.function_summarizer import SUMMARY_CUT_NOTE, SUMMARY_FENCE_STATEMENT
from maljan.analysis.pcap_summary import CaptureRead
from maljan.extractors.capability_matrix import (
    NOT_ASKED_UNKNOWN_ID,
    TechniqueQuestion,
    not_asked_unknown_id,
    unknown_id_reason,
)
from maljan.llm.context_window import no_room_sentence
from maljan.llm.tool_replies import NO_REPLY_RECORDED, NOT_RUN_REPLY
from maljan.memory.technique_cards import card_lines, load_cards
from maljan.pipeline import triage_pack
from maljan.pipeline.debate_facts import (
    ledger_count_facts,
    with_ledger_facts,
)
from maljan.pipeline.evidence_summary import summarise
from maljan.pipeline.mediation_models import (
    CONTRADICTIONS_BLOCK_MISSING_NOTE,
    CONTRADICTIONS_BLOCK_MIXED_NOTE,
    MediatorVerdict,
)
from maljan.pipeline.nodes import (
    NO_SANDBOX_DATA_REASON,
    NO_STATIC_FIXTURE_NOTE,
    run_quality_note,
    skipped_analysts_reason,
)
from maljan.pipeline.run_state import NO_LIMIT, budget_line
from maljan.pipeline.validation import (
    _UNPARSED_ANSWER_MESSAGE,
    ANALYST_FEEDBACK_CLOSING,
    FUNCTION_CHECK_HEAD,
    FUNCTION_CHECK_NOT_ASKED_HEAD,
    ITEM_NOT_IN_RUN,
    MALWARE_TYPES,
    UNATTRIBUTED_INDICATOR_CODE,
    CapabilityGrounding,
    ClaimsRepeated,
    DecompiledFunction,
    EntryTexts,
    RetryDrops,
    Violation,
    _term_ids_said,
    absence_claim_violation,
    analyst_cut_violation,
    analyst_repeated_violation,
    chunk_cut_unread_sentence,
    claim_does_not_describe_violation,
    claims_kept_under_disputes_finding,
    claims_under_disputes_violation,
    confidence_violation,
    decompiled_not_described_violation,
    feedback_text,
    flow_voice_violations,
    gate_removed_note,
    kept_after_the_sandbox_fact,
    library_only_claims_violation,
    malware_object_violations,
    misstated_entry_contents,
    persistence_not_observed_violations,
    recommendation_indicator_violations,
    recommendation_technique_violations,
    repeated_item_violations,
    retry_drop_question,
    section_cut_violation,
    stated_value_violations,
    technique_line_violation,
    unattributed_indicator_violations,
    undescribed_technique_finding,
    ungrounded_capabilities,
    unpublished_value_violations,
    validate_verdict_bundle,
)
from maljan.providers.base import STATIC_EVIDENCE_INSTRUCTIONS, absent_provider_fragment
from maljan.providers.static import r2 as _r2
from maljan.providers.static.ghidra import (
    GHIDRA_GUIDANCE,
    GHIDRA_WORKFLOW,
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
    ANALYST_CLAIMS_HEADING,
    PUBLISHED_TECHNIQUES_HEADING,
    RULE_ONLY_NOTE,
    SECTION_SCHEMAS,
    WHERE_QUOTED_LEAD,
    section_contract,
)
from maljan.reporting.evidence_bundles import sample_flow_fact
from maljan.reporting.ledger_report import FUNCTION_NOT_SHOWN
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
    TTPMapping,
)
from maljan.reporting.narrative_agent import (
    _SYSTEM_PROMPT,
    CLAIMS_IN_FORCE_HEADING,
    EXAMPLE_OBJECT,
    EXPECTED_OBJECT,
    build_prompt_text,
)
from maljan.reporting.renderers.markdown import analyst_list_note
from maljan.reporting.renderers.stix_renderer import (
    BENIGN_NAME_IN_A_URL,
    BENIGN_NAME_RESOLVED,
    CAPTURE_TLS_NAME,
    FLOW_OUTSIDE_THE_TREE,
    JUDGE_KEPT_WHEN_TOLD,
    JUDGE_KEPT_WHEN_TOLD_OF_ITS_HOST,
    JUDGE_NOT_ASKED_IN_TIME,
    JUDGE_QUESTION_NOT_RECORDED,
    SEARCHED_THE_REPORT,
    UNATTRIBUTED_FLOW,
    disputed_flow_reason,
    judge_not_told,
    judge_only_reason,
    named_only_reason,
    not_kept_reason,
    public_resolver_reason,
    seen_in_reason,
    yes_because,
)
from maljan.schemas.evidence import LedgerEntry, not_shown_record
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    JUDGE_ONLY_TECHNIQUE_MARKER,
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
    Finding,
    judge_and_findings_note,
    judge_dropped_reason,
    judge_kept_note,
)
from maljan.schemas.stix_models import Bundle
from maljan.tools import api_hashes, binary, knowledge, string_blobs
from maljan.tools.errors import CAPTURES_REMEDIATION, NO_CAPTURE_REMEDIATION

# Every no: sentence a root reading writes, and the names of the roots.
_ROOT_SENTENCES = [
    getattr(_roots, name)
    for name in (
        "NO_ENTRY",
        "NO_CITATION",
        "FAILED",
        "REFERENCE",
        "NOTHING_TO_PLACE",
        "BY_NAME_ONLY",
        "REPEAT_LOOP",
        "SIGNATURE_UNPLACED",
        "MATCH_UNPLACED",
        "SHARED_COMMAND",
        "NAMES_NO_ROW",
        "NO_ROW_NAMES_TECHNIQUE",
        "FILE_UNTOLD",
        "OUTSIDE_PROGRAM",
        "OFFSET_UNPLACED",
        "BLOB_UNMATCHED",
        "WHOLE_FILE",
        "PE_HEADER",
        "IMPORT_TABLE",
        "EXPORT_TABLE",
        "RESOURCE_TABLE",
        "DEBUG_DIRECTORY",
        "OVERLAY",
    )
]

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


def _function_map_text() -> str:
    """The map block as a model reads it, head, coverage and both kinds of line."""
    from types import SimpleNamespace

    from maljan.agents.function_map import (
        build_function_map,
        function_artefacts,
        function_map_block,
    )

    floss = LedgerEntry(
        id="ev_0001",
        tool="floss",
        output=json.dumps(
            {"strings": [{"kind": "decoded", "string": "a", "function_rva": "0x2000"}]}
        ),
    )
    own = [
        LedgerEntry(
            id="ev_0002", tool="decompile_function", args={"address": "0x1000"}, output="x"
        ),
        LedgerEntry(id="ev_0003", tool="disassemble_function", args={"address": "0x3000"}),
    ]
    claim = SimpleNamespace(claim="0x1000 reads a value.", evidence_ref="ev_0002")
    block = function_map_block(build_function_map(own, function_artefacts([floss]), [claim]))
    assert block
    return block


def _function_index_text() -> str:
    """The index as the pack shows it, whole and cut, its run-state line and the map's coverage."""
    import tempfile

    from maljan.agents.function_map import (
        build_function_map,
        function_artefacts,
        function_map_block,
    )
    from maljan.pipeline.run_state import index_sentence
    from maljan.tools import artefact_index
    from tests.unit.tools.synthetic_pe import SyntheticPE

    def cells(key: str, values: list[str], source: str) -> list[dict[str, Any]]:
        return [{key: value, "sources": [source]} for value in values]

    rows = [
        {
            "function": hex(0x401000 + 0x100 * i),
            "offset": hex(0x1000 + 0x100 * i),
            "direct": 5 - i,
            "imports": cells("name", ["OpenThing"], artefact_index.SELF),
            "slot_calls": [
                {
                    "name": "ShutThing",
                    "sources": ["ev_0002"],
                    "slot": "0x405000",
                    "named_at": "0x401010",
                }
            ],
            "resolved": cells("name", ["CloseThing"], "ev_0002"),
            "decoded_strings": cells("text", ["a", "b"], "ev_0003"),
            "plain_strings": cells("text", ["c"], artefact_index.SELF),
            "capa": cells("rule", ["a rule"], "ev_0004"),
            "callers": ["0x402000"],
            "callees": ["0x403000", "0x404000"],
            "indirect": {"artefacts": 3, "through": 2},
            **({"names": ["anexport"], "entry_point": True} if i == 0 else {}),
        }
        for i in range(3)
    ]
    data = {
        "tool": artefact_index.TOOL,
        "image_base": "0x400000",
        "functions_known": 9,
        "function_sources": {"exception directory": 4, "call targets the decoder reached": 5},
        "function_lists": artefact_index.FUNCTION_LISTS_ABSENT,
        "undecoded_functions": 1,
        "unplaced": {"floss": 2},
        "total": len(rows),
        "rows": rows,
    }
    data["absent"] = {
        "capa": "no: [ev_0004] failed: capa produced no result",
        "floss": artefact_index.FLOSS_NOT_REMEMBERED,
    }
    # Built as the pack holds it: the answer parsed into ``structured``.
    entry = LedgerEntry(
        id="ev_0005", tool=artefact_index.TOOL, output=json.dumps(data), structured=data, seq=5
    )
    whole = triage_pack.pack_block([entry], 0)
    head_and_rows = whole.split("\n")[1:]
    assert len(head_and_rows) == len(rows) + 1
    assert head_and_rows[1].startswith("- 0x401000 (export ")
    cut = triage_pack.render_pack([entry], len(head_and_rows[0]) + len(head_and_rows[1]) + 300)
    assert cut.split("\n")[-1].startswith("2 more rows not shown here (pack room)")
    empty = triage_pack.render_pack(
        [entry.model_copy(update={"structured": {**data, "rows": [], "total": 0}})], 0
    )
    dropped = entry.model_copy(update={"output": "", "structured": None, "truncated": True})
    found = build_function_map(
        [LedgerEntry(id="ev_0006", tool="decompile_function", args={"address": "0x1000"})],
        function_artefacts([entry]),
        [],
    )
    block = function_map_block(found)
    assert "not visited, holding artefacts in the function index (ev_0005)" in block
    # The line in its three forms: every row, the rows that fit and "and N more", the count only.
    many_rows = [
        {**row, "function": hex(0x401000 + 0x100 * i), "offset": hex(0x1000 + 0x100 * i)}
        for i, row in enumerate(rows * 4)
    ]
    many = entry.model_copy(update={"structured": {**data, "rows": many_rows, "total": 12}})
    found_many = build_function_map(
        [LedgerEntry(id="ev_0006", tool="decompile_function", args={"address": "0x1000"})],
        function_artefacts([many]),
        [],
    )
    every_row = function_map_block(found_many, room=10**6)
    assert "; and " not in every_row and "(ev_0005): 0x401100 (4 artefacts); " in every_row
    cut_rows = function_map_block(found_many, room=len(every_row) - 1)
    assert "; and " in cut_rows and " more; the index is ev_0005" in cut_rows
    with tempfile.TemporaryDirectory() as folder:
        text = Path(folder) / "a.txt"
        text.write_text("plain text\n", encoding="utf-8")
        not_pe = artefact_index.served_index(text)["error"]
        assert "reads Windows PE images only" in not_pe
        image = Path(folder) / "s.exe"
        image.write_bytes(SyntheticPE(functions=[(0x1000, 0x1010)]).build())
        nowhere = artefact_index.served_index(image, "0x9999")["row"]
        assert nowhere.startswith("no: no function the run knows starts at or holds")
        served = artefact_index.served_index(image)["table"]
        at_start = artefact_index.served_index(image, "0x140001000")["address_read"]
        inside = artefact_index.served_index(image, "0x140001004")["address_read"]
        assert " read as a virtual address: the start of the function at " in at_start
        assert " read as a virtual address: inside the function at " in inside
    not_an_address = artefact_index.address_readings("the main one", 0x400000)
    assert isinstance(not_an_address, str) and "is not an address" in not_an_address
    served_rows = [artefact_index.row_line(row, artefact_index.THIS_ANSWER) for row in rows]
    return " ".join(
        [
            whole,
            cut,
            empty,
            index_sentence("ev_0005", data),
            index_sentence("ev_0005", None, dropped=True),
            index_sentence("ev_0005", None),
            triage_pack.render_pack([dropped], 0),
            found.coverage(),
            block,
            served,
            *served_rows,
            not_pe,
            nowhere,
            not_an_address,
            at_start,
            inside,
            artefact_index.FAILED_HERE.format("ValueError: x"),
            artefact_index.ERROR_HERE.format("x"),
            artefact_index.FLOSS_UNREADABLE.format("x"),
            triage_pack.INDEX_SOURCE_NOT_IN_PACK,
            triage_pack.INDEX_SOURCE_UNREADABLE.format(entry="ev_0002"),
            function_map_block(found, room=200),
            every_row,
            cut_rows,
        ]
    )


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


def _analysis_tool_descriptions(*names: str) -> str:
    """The descriptions the analysis server gives these tools, as every bound agent reads them."""
    import importlib.util
    import sys

    path = Path(__file__).resolve().parents[3] / "services" / "analysis-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("analysis_mcp_leak_scan", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return " ".join(str(getattr(module, name).__doc__ or "") for name in names)


def _deobfuscation_sentences() -> str:
    """Every sentence the deobfuscation passes put in front of a model, filled in."""
    from maljan.analysis import ghidra_passes
    from maljan.tools import crypto_constants

    return " ".join(
        [
            crypto_constants.SCAN_RULE,
            ghidra_passes.SCAN_CHECKS,
            ghidra_passes.STATED_RULE,
            ghidra_passes.GHIDRA_SWITCHED_OFF,
            ghidra_passes.GHIDRA_NOT_OVER_HTTP.format(transport="stdio"),
            ghidra_passes.GHIDRA_HAS_NO_COPY,
            triage_pack.PASS_ROOM_SENTENCE.format(shown=1, total=2),
            triage_pack.SCAN_CHECKS_SHORT,
        ]
    )


def _deobfuscation_lines() -> str:
    """The two pass lines with and without a finding, and the lines of a pass not run."""
    from maljan.analysis.ghidra_passes import ANTI_ANALYSIS_TOOL
    from maljan.tools import crypto_constants

    place = {"offset": "0x1", "rva": "0x2", "function": "0x0"}
    value_row = {"value": "0x1", "places": [place]}
    constants = {
        "found": [
            {
                "algorithm": "a",
                "what": "w",
                "tables": [{"byte_order": "big-endian", "place": place}],
            },
            {"algorithm": "a", "what": "w", "matched": 2, "of": 3, "values": [value_row]},
            {"algorithm": "a", "what": "w", "capa": [{"rule": "r", "at": "0x0"}]},
        ],
        "lone": [{"algorithm": "a", "what": "w", "matched": 1, "of": 3, "values": [value_row]}],
        "sets_searched": 3,
    }
    findings = {
        "stated": [{"category": "c", "what": "t", "offset": "0x1", "function": "f"}],
        "not_stated": 2,
        "total_findings": 4,
        "returned": 3,
    }
    not_run = [
        LedgerEntry(id=f"ev_000{i}", tool=tool, error="not run: x", ok=False, seq=i)
        for i, tool in enumerate((crypto_constants.TOOL, ANTI_ANALYSIS_TOOL), 1)
    ]
    failed = [LedgerEntry(id="ev_0004", tool=ANTI_ANALYSIS_TOOL, error="x", ok=False, seq=4)]
    return " ".join(
        [
            triage_pack._constant_sets(constants),
            triage_pack._constant_sets(constants, max_chars=120),
            triage_pack._constant_sets({"found": [], "lone": [], "sets_searched": 3}),
            triage_pack._anti_analysis(findings),
            triage_pack._anti_analysis({**findings, "also_stated": 2}),
            triage_pack._anti_analysis(
                {
                    "stated": [
                        {"category": "c", "what": "t", "offset": "0x1", "capa": [{"rule": "r"}]}
                    ],
                    "beside_capa": [{"category": "c", "what": "t", "offset": "0x2"}],
                }
            ),
            triage_pack._constant_sets({**constants, "agreeing": 1}),
            triage_pack._anti_analysis(findings, max_chars=200),
            triage_pack._anti_analysis({"stated": [], "not_stated": 2, "total_findings": 2}),
            triage_pack._anti_analysis({"stated": []}),
            triage_pack.pack_block([*not_run, *failed], 0),
        ]
    )


def _ghidra_pass_failures() -> str:
    """What each way a Ghidra pass can stop says, from the passes' own code."""
    import httpx

    from maljan.analysis.ghidra_passes import GhidraPasses, GhidraPassFailed

    def ghidra(answers: dict[str, Any]) -> GhidraPasses:
        def handler(request: httpx.Request) -> httpx.Response:
            answer = answers.get(request.url.path, {"success": True, "program": "p"})
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, int):
                return httpx.Response(answer)
            return httpx.Response(200, json=answer)

        return GhidraPasses(base_url="http://g.invalid", transport=httpx.MockTransport(handler))

    opened = {"/get_current_program_info": {"image_base": "1000"}}
    cases = [
        {"/load_program": {"error": "e"}},
        {"/load_program": 500},
        {"/load_program": httpx.ConnectError("x")},
        {"/switch_program": 500},
        {"/run_analysis": {"error": "e"}},
        {"/get_current_program_info": {"image_base": None}},
        {"/get_current_program_info": {"error": "e"}},
        {**opened, "/find_anti_analysis_techniques": {"error": "e"}},
        {**opened, "/find_anti_analysis_techniques": ["x"]},
    ]
    said: list[str] = []
    for answers in cases:
        try:
            ghidra(answers).anti_analysis()
        except GhidraPassFailed as failure:
            said.append(str(failure))
    try:
        ghidra({**opened, "/find_anti_analysis_techniques": httpx.ReadTimeout("x")}).anti_analysis()
    except GhidraPassFailed as failure:
        said.append(str(failure))
    assert len(said) == len(cases) + 1
    return " ".join(said)


def _constant_set_names() -> str:
    """Each catalogue set as the constants line names it: algorithm, what it is, a value."""
    from maljan.tools import crypto_constants

    place = {"offset": "0x1"}
    rows = [
        {
            "algorithm": entry.algorithm,
            "what": entry.what,
            "matched": 1,
            "of": 1,
            "values": [{"value": str(entry.values[0]), "places": [place]}],
        }
        for entry in crypto_constants.catalogue()
        if entry.kind == crypto_constants.VALUES
    ] + [
        {"algorithm": entry.algorithm, "what": entry.what, "tables": [{"place": place}]}
        for entry in crypto_constants.catalogue()
        if entry.kind == crypto_constants.TABLE
    ]
    return triage_pack._constant_sets({"found": rows, "sets_searched": len(rows)})


_TRANSFORM_ENTRY = "the byte transform tool's description, facts, answers and errors"


def _transform_sentences() -> str:
    """What the byte transform tool tells a model: its facts, answers and every kind of error."""
    import tempfile
    import zlib

    from maljan.tools import transforms
    from tests.unit.tools.synthetic_pe import SyntheticPE

    calls: list[tuple[str, dict[str, Any]]] = [
        ("flat", {"offset": 0, "length": 999}),
        ("flat", {"offset": 0, "steps": [{"op": "slice", "start": 1, "length": 999}]}),
        ("packed", {"offset": 0, "steps": [{"op": "zlib"}]}),
        ("cut", {"offset": 0, "steps": [{"op": "zlib"}]}),
        ("flat", {"offset": 0, "steps": [{"op": "xor", "key": {"text": "k"}, "increment": 1}]}),
        ("flat", {"offset": 0, "steps": [{"op": "rot13"}]}),
        ("flat", {"offset": 0, "steps": [{"op": "xor", "key": "41"}]}),
        ("flat", {"offset": 0, "steps": [{"op": "rc4", "key": {"offset": 60, "length": 9}}]}),
        ("flat", {"offset": 0, "steps": [{"op": "base64", "alphabet": "A" * 64}]}),
        ("flat", {"offset": 0, "steps": [{"op": "aes", "mode": "cbc", "key": {"hex": "00" * 16}}]}),
        ("flat", {"rva": "0x10"}),
        ("image", {"rva": "0x90000"}),
        ("image", {"offset": 0, "length": 2}),
        ("image", {"va": "0x10"}),
        ("big", {"offset": 0}),
        ("hosts", {"offset": 0}),
        ("big", {"offset": 1, "show_offset": 3, "show_length": 5}),
        ("flat", {"offset": 0, "show_offset": 999}),
        ("flat", {"offset": 0, "show_length": transforms.MAX_SHOWN_BYTES + 1}),
    ]
    with tempfile.TemporaryDirectory() as folder:
        files = {
            "hosts": b" ".join(b"h%05d.example.com" % i for i in range(200)),
            "big": b"\0" * (transforms.SHOWN_BYTES * 2),
            "flat": b"plain bytes, " * 5,
            "packed": zlib.compress(b"x" * 64) + b"tail",
            "cut": zlib.compress(b"x" * 64)[:-6],
            "image": SyntheticPE().build(),
        }
        for name, blob in files.items():
            (Path(folder) / name).write_bytes(blob)
        answers = [
            transforms.transform_bytes(str(Path(folder) / name), **args) for name, args in calls
        ]
    return " ".join(
        [
            transforms.CAPABILITY_FACTS,
            transforms.REMEDIATION,
            transforms._cap_sentence(),
            transforms._scan_stopped_sentence(9),
            transforms._left_out_sentence(3, 6000),
            transforms._stopped(2, 4, "the output reached the platform's sample upload cap"),
            transforms._stopped(
                2, 4, "the steps had written 9 bytes in all, the platform's sample upload cap"
            ),
            _analysis_tool_descriptions("transform_bytes"),
            *(json.dumps({k: v for k, v in a.items() if k != "output"}) for a in answers),
            # The output's own sentences; its readings are the sample's bytes.
            *(
                json.dumps(
                    {
                        k: a["output"].get(k)
                        for k in (
                            "shown",
                            "utf16le_note",
                            "indicators_left_out",
                            "indicator_scan_stopped",
                        )
                    }
                )
                for a in answers
                if "output" in a
            ),
        ]
    )


_UPX_ENTRY = "the UPX unpacking tool's description, facts, answers, errors and pack lines"


def _upx_sentences() -> str:
    """What UPX unpacking tells a model: the tool, every no: sentence and error, the pack line."""
    import tempfile

    from maljan.schemas.evidence import LedgerEntry
    from maljan.tools import upx
    from tests.unit.tools import synthetic_upx as su
    from tests.unit.tools.synthetic_pe import SyntheticPE

    packed = su.build()
    damaged = bytearray(packed.data)
    damaged[packed.header_offset + 40] ^= 0x10
    offset = hex(packed.header_offset)
    with tempfile.TemporaryDirectory() as folder:
        files = {
            "packed": packed.data,
            "damaged": bytes(damaged),
            "plain": SyntheticPE().build(),
            "text": b"no header at all " * 8,
        }
        answers = []
        for name, blob in files.items():
            (Path(folder) / name).write_bytes(blob)
            answers.append(upx.unpack_upx(str(Path(folder) / name), Path(folder)))
    entries = [
        LedgerEntry(id=f"ev_000{i}", tool=upx.TOOL, structured=a, ok="error" not in a)
        for i, a in enumerate(answers, 1)
    ]
    # Every sentence the module can say, its no: and error forms included:
    # each string the source writes, f-strings' literal parts with them.
    import ast
    import inspect

    written = [
        node.value
        for node in ast.walk(ast.parse(inspect.getsource(upx)))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return " ".join(
        [
            *written,
            upx.CAPABILITY_FACTS,
            upx.REMEDIATION,
            upx.LZMA_NOT_READ.format(lc=5, lp=0),
            upx.NOT_A_PE.format(why="no MZ header"),
            upx.NO_HEADER,
            upx.NO_SECTIONS,
            upx.OLD_VERSION.format(offset=offset, version=9),
            upx.REFUSED.format(offset=offset),
            upx.FORMAT_NOT_READ.format(offset=offset, format=12),
            upx.MACHINE_MISMATCH.format(format=9, name="win32/pe", machine=0x8664),
            upx.METHOD_NOT_READ.format(method=15),
            upx.FILTER_NOT_READ.format(filter=0x49),
            upx.OVER_CAP.format(size=2**32 - 1, cap=upx.UNPACKED_CAP),
            upx.FILE_OVER_CAP.format(size=2**30, cap=upx.UNPACKED_CAP),
            upx.RELOCS16_NOT_READ,
            triage_pack.UPX_NO_JOB,
            _analysis_tool_descriptions("unpack_upx"),
            *(json.dumps(a) for a in answers),
            *(triage_pack._pack_line(e) for e in entries),
            *(triage_pack._within_room(e, 200) or "" for e in entries),
        ]
    )


_SECTIONS_ENTRY = (
    "the sandbox report's section index, its item query and what an item citation is told"
)


def _sandbox_sections_sentences() -> str:
    """What the sandbox sections tell a model: the index, the tool, its answers, the questions."""
    from maljan.analysis import sandbox_sections as ss
    from maljan.providers import sandbox_tools as st
    from maljan.schemas.evidence import LedgerEntry

    report: dict[str, Any] = {
        "behavior": {
            "processes": [
                {"pid": 7, "ppid": 1, "process_name": "a.exe", "command_line": "a.exe /q"},
                {"process_name": "b.exe"},
            ],
            "summary": {"keys": ["HKCU\\x"], "files": []},
        },
        "network": {"tcp": [{"dst": "192.0.2.1", "dport": 1}], "dns": []},
        "signatures": [{"name": "s", "severity": 1}],
        "dropped": [],
        "unavailable": ["calls", "registry", "generic_events", "apistats", "screenshots"],
    }
    # Every no: sentence: a report that holds nothing, and one that lists
    # every section its sandbox does not record.
    indexes = [ss.section_index({}), ss.section_index(report)]
    entries = [
        LedgerEntry(id=f"ev_000{i}", tool=ss.SECTIONS_TOOL, structured=index)
        for i, index in enumerate(indexes, 1)
    ]
    answers = [
        st.sandbox_items(report, "processes"),
        st.sandbox_items(report, "network", ids=["net:1", "net:9"]),
        st.sandbox_items(report, "registry"),
        st.sandbox_items(report, "nope"),
        st.sandbox_items(report, "processes", pid="x"),
        st.sandbox_items(report, "network", signature="sig:1"),
    ]
    return " ".join(
        [
            st.items_tool(report).description,
            *(json.dumps(index) for index in indexes),
            *(triage_pack._pack_line(entry) for entry in entries),
            *(json.dumps(answer) for answer in answers),
            st.ITEMS_NO_SECTION,
            st.ITEMS_BAD_PID,
            st.ITEMS_SIGNATURE_SECTION,
            triage_pack.SECTIONS_SERVED_BY,
            ITEM_NOT_IN_RUN.format(item="proc:9"),
            _roots.NO_ITEM.format(item="proc:9"),
            _roots.ITEM_ROW_UNREAD.format(item="net:9"),
            _roots.ITEM_NO_PID,
            *(_roots.ITEM_UNPLACED.format(section=name) for name in ss.SECTION_PREFIXES),
            *(
                ss.NO_NORMALISED.format(provider=provider, section=name)
                for provider in ("triage", "rest", "upload")
                for name in ss.SECTION_PREFIXES
            ),
            json.dumps(ss.section_index(report, ("triage", "triage"))),
            json.dumps(st.sandbox_items(report, "files", normalised_by=("rest", "generic"))),
        ]
    )


# Everything else a report model is shown on every run, as plain text.
# A network block with one address the sample reached, one the sandbox
# recorded and does not attribute, a name that resolved to the second, a name
# with no answers, and a name it never saw: each fact the observed-step
# question can state.
_FLOW_FACTS_REPORT = MalwareReport(
    identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
    network=NetworkIOCs(
        ips=[
            NetworkIP(address="192.0.2.9", source="sandbox", sample_process_tree=True),
            NetworkIP(address="192.0.2.2", source="sandbox"),
        ],
        domains=[
            NetworkDomain(fqdn="one.example.com", source="sandbox", resolved_ips=["192.0.2.2"]),
            NetworkDomain(fqdn="two.example.com", source="sandbox"),
        ],
    ),
    ttp_mappings=[
        TTPMapping(
            technique_id="T1112",
            technique_name="Modify Registry",
            contributing_layers=["static", "dynamic"],
            independent_layers=["static"],
            identical_statements=1,
        )
    ],
)


def _message_of(violation: Violation | None) -> str:
    """A question's words, which the builder answers only when there is one to ask."""
    assert violation is not None
    return violation.message


def _function_claim_question(several: bool = False) -> str:
    """The question a claim gets when its function's own facts hold none of what it names.

    With ``several``, the claim cites two listings: one function whose row is
    long enough to be counted, and one that holds no artefact of its own.
    """
    from maljan.agents.function_map import function_artefacts
    from maljan.pipeline.function_claims import (
        check_function_claims,
        function_facts,
        listed_functions,
    )
    from maljan.schemas.evidence import LedgerEntry

    data = {
        "tool": "function_index",
        "image_base": "0x400000",
        "functions_known": 1,
        "undecoded_functions": 0,
        "undecoded": [],
        "calls_unnamed": {},
        "rows": [
            {
                "function": "0x401000",
                "offset": "0x1000",
                "direct": 1,
                "imports": [{"name": "GetTickCount", "sources": ["this entry"]}],
                "resolved": [],
                "decoded_strings": [],
                "plain_strings": [],
                "capa": [],
                "callers": [],
                "callees": [],
                "indirect": {"artefacts": 0, "through": 0},
            }
        ],
        "other_callees": {},
    }
    if several:
        data["rows"][0]["resolved"] = [
            {"name": f"RtlUserRoutine{n:02d}", "sources": ["ev_0003"]} for n in range(40)
        ]
        data["rows"][0]["slot_calls"] = [
            {"name": "GetTickCount", "sources": ["ev_0003"], "slot": "0x405000", "named_at": "0x0"}
        ]
        data["other_callees"] = {"0x402000": []}
        data["calls_unnamed"] = {}
    index = LedgerEntry(
        id="ev_0001", agent="pipeline", tool="function_index", output="{}", structured=data
    )
    listing = LedgerEntry(
        id="ev_0002",
        tool="decompile_function",
        args={"address": "401000"},
        output="void FUN_00401000(void) { }",
    )
    listings = [listing]
    claim = "0x401000 draws text with WriteConsoleW."
    if several:
        listings.append(
            LedgerEntry(
                id="ev_0004",
                tool="decompile_function",
                args={"address": "402000"},
                output="void FUN_00402000(void) { }",
            )
        )
        claim = "0x401000 and 0x402000 draw text with WriteConsoleW."
    facts = function_facts(
        listings, function_artefacts([index]), pack_entries=[index], bases=(0x400000,)
    )
    isr = AgentISR(
        agent_id="a",
        domain="static",
        claims=[
            ClaimEvidence(
                claim=claim,
                evidence_ref="[ev_0002], [ev_0004]" if several else "[ev_0002]",
                confidence=0.5,
            )
        ],
    )
    found = check_function_claims(isr, listed_functions(listings), facts, (0x400000,))
    (violation,) = found.violations
    return violation.message


def _every_message(found: list[Any]) -> str:
    """The messages of questions every one of which must be asked; one not asked fails here."""
    missing = [index for index, violation in enumerate(found) if violation is None]
    assert not missing, f"the questions at {missing} were not asked of their synthetic claims"
    return " ".join(violation.message for violation in found)


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
    "analyst question for a claim that names a sibling sub-technique": _message_of(
        claim_does_not_describe_violation(
            ClaimEvidence(
                claim="The program persists by registering its own accessibility features handler.",
                evidence_ref="[ev_0001]",
                confidence=0.9,
                technique_id="T1546.001",
            ),
            "T1546.001",
            knowledge,
        )
    ),
    "the absence and describe questions on one id of a technique list": _every_message(
        [
            absence_claim_violation(
                ClaimEvidence(
                    claim="The file holds no persistence mechanism.",
                    evidence_ref="[ev_0001]",
                    confidence=0.9,
                    technique_id="T1547",
                ),
                "T1547",
                listed=True,
            ),
            claim_does_not_describe_violation(
                ClaimEvidence(
                    claim="The file opens a window.",
                    evidence_ref="[ev_0001]",
                    confidence=0.9,
                    technique_id="T1003",
                ),
                "T1003",
                knowledge,
                listed=True,
            ),
        ]
    ),
    "capability questions for evading analysis and packing": " ".join(
        v.message
        for v in ungrounded_capabilities(
            "The file tries to evade analysts. It is a repacked build.",
            CapabilityGrounding(evidence_keys=frozenset({"pe_header"})),
        )
    ),
    "judge compact bundle rules": COMPACT_BUNDLE_RULES,
    "judge malware object rule": MALWARE_OBJECT_RULE,
    "judge run quality paragraphs": " ".join(
        [
            run_quality_note(["a reason"], degraded=True),
            run_quality_note(["a reason", "a note"], degraded=False, informational=["a note"]),
        ]
    ),
    "judge malware object questions": " ".join(
        v.message
        for v in malware_object_violations(
            Bundle.model_validate(
                {
                    "objects": [
                        {
                            "type": "malware",
                            "id": "malware--1",
                            "name": "Examplefamily",
                            "is_family": False,
                            "malware_types": ["stealer"],
                        }
                    ]
                }
            ).objects[0],
            path="objects[0]",
            family="Examplefamily",
            written={"labels": ["stealer"]},
        )
    )
    + " "
    + " ".join(
        v.message
        for v in malware_object_violations(
            Bundle.model_validate(
                {"objects": [{"type": "malware", "id": "malware--1", "name": "x"}]}
            ).objects[0],
            path="objects[0]",
            family="",
            written={"labels": ["stealer"]},
        )
    ),
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
    "judge-named technique named on findings note": judge_and_findings_note(["a", "b"]),
    "the runtime-name wording and the capability lookup's description": " ".join(
        [
            knowledge.RESOLVED_AT_RUNTIME,
            str(knowledge.api_capability.__doc__ or ""),
        ]
    ),
    "the claims headings of a composer section and the narrative round": (
        f"{ANALYST_CLAIMS_HEADING} {CLAIMS_IN_FORCE_HEADING}"
    ),
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
    "the judge's recorded answer after the sandbox's fact": " ".join(
        v.message
        for v in kept_after_the_sandbox_fact(
            [
                Violation(
                    code=UNATTRIBUTED_INDICATOR_CODE,
                    message="m",
                    subject="domain:one.example.com",
                )
            ]
        )
    ),
    "narrative prompt's technique lines with the independent layers": build_prompt_text(
        _FLOW_FACTS_REPORT
    ),
    "narrative question about a recommendation naming a value not published": " ".join(
        v.message
        for v in recommendation_indicator_violations(
            {
                "defensive_recommendations": [
                    {"action": "Block 192.0.2.1 and one.example.com.", "detection": "x"}
                ]
            },
            lambda kind, value: "no: x" if kind == "ip" else "",
        )
    ),
    "narrative question about a recommendation naming a technique not published": " ".join(
        v.message
        for v in recommendation_technique_violations(
            {"defensive_recommendations": [{"action": "Alert on it.", "technique_id": "T1001"}]},
            ["T1002"],
        )
    ),
    "composer questions about persistence the sandbox did not record": _every_message(
        [
            *persistence_not_observed_violations(
                {"body": "The program persists through a task it registers [ev_0001]."},
                True,
                section="persistence_detail",
            ),
            *persistence_not_observed_violations(
                {"steps": [{"order": 1, "action": "It persists at logon.", "voice": "observed"}]},
                True,
                section="execution_flow",
            ),
        ]
    ),
    "analyst question about what a kept retry left out": retry_drop_question(
        RetryDrops(
            claims=(
                (
                    ClaimEvidence(
                        claim="The file opens a window.",
                        evidence_ref="[ev_0001]",
                        confidence=0.9,
                        technique_id="T1001",
                    ),
                    ("T1001", "0x40"),
                ),
            ),
            findings=(Finding(title="The file opens a window", detail="It names it."),),
        )
    ),
    "composer question about table rows no cited entry holds": " ".join(
        v.message
        for v in stated_value_violations(
            {
                "items": [
                    {"key": "k", "value": "one.example", "evidence_refs": ["ev_0001"]},
                    {"key": "j", "value": "two.example", "evidence_refs": ["ev_0001"]},
                ],
                "identifiers": [{"kind": "k", "value": "three", "evidence_refs": ["ev_0001"]}],
            },
            EntryTexts(texts={"ev_0001": "nothing here"}, tools={"ev_0001": "strings"}),
        )
    ),
    "composer question about an unpublished value in its text": " ".join(
        v.message
        for v in unpublished_value_violations(
            {"body": "It reaches 192.0.2.1."}, lambda kind, value: "no: x"
        )
    ),
    "judge question about an indicator on a value the sample did not reach": " ".join(
        v.message
        for v in unattributed_indicator_violations(
            Bundle.model_validate(
                {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--1",
                            "pattern": "[domain-name:value = 'one.example']",
                            "indicator_types": ["malicious-activity"],
                        }
                    ],
                }
            ),
            lambda kind, value: CAPTURE_TLS_NAME,
        )
    ),
    "publish rule words for the judge's keep and a published row": " ".join(
        [
            JUDGE_KEPT_WHEN_TOLD,
            JUDGE_KEPT_WHEN_TOLD_OF_ITS_HOST,
            JUDGE_NOT_ASKED_IN_TIME,
            JUDGE_QUESTION_NOT_RECORDED,
            judge_not_told(JUDGE_NOT_ASKED_IN_TIME, "its address 192.0.2.1"),
            yes_because("identity"),
            judge_only_reason(),
            judge_only_reason(SEARCHED_THE_REPORT),
            judge_only_reason(asked_in="ev_0004 get_domain_report"),
            yes_because("sandbox"),
        ]
    ),
    "execution step questions for an observed step not watched whole": " ".join(
        v.message
        for v in flow_voice_violations(
            {
                "steps": [
                    {"order": 1, "action": "a", "voice": "observed", "evidence_refs": []},
                    {
                        "order": 2,
                        "action": "a",
                        "voice": "observed",
                        "evidence_refs": ["ev_0001", "ev_0002"],
                    },
                    {
                        "order": 3,
                        "action": (
                            "Reaches 192.0.2.1, 192.0.2.2, one.example.com, two.example.com "
                            "and three.example.com."
                        ),
                        "voice": "observed",
                        "evidence_refs": ["ev_0001"],
                    },
                ]
            },
            ["ev_0001"],
            tools={"ev_0002": "t"},
            flow_fact=sample_flow_fact(_FLOW_FACTS_REPORT),
        )
    ),
    "evidence summary naming each id from the vendored table": summarise(
        {
            "a": AgentISR(
                agent_id="a",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="x", evidence_ref="[ev_0001]", confidence=0.5, technique_id="T1112"
                    )
                ],
            )
        }
    ),
    "mediator contradiction definition, closing block rule and its one question": " ".join(
        [CONTRADICTION_DEFINITION, CONTRADICTIONS_BLOCK_RULE, CONTRADICTIONS_BLOCK_QUESTION]
    ),
    "mediator system turn, its closing line and the missing-block note": " ".join(
        [
            MEDIATOR_SYSTEM_HEAD,
            MEDIATOR_HUMAN_CLOSING,
            CONTRADICTIONS_BLOCK_MISSING_NOTE,
            CONTRADICTIONS_BLOCK_MIXED_NOTE,
        ]
    ),
    "a chunk still cut after its question": chunk_cut_unread_sentence("chunk 1 of 2"),
    "mediator structured extraction and its schema": " ".join(
        [
            MEDIATION_EXTRACTION_SYSTEM,
            str(MediatorVerdict.model_fields["contradictions"].description or ""),
        ]
    ),
    "judge prompt shortened to its window": PROMPT_SHORTENED_NOTICE.format(
        cut=2, total=5, names="static report, evidence summary", width=900
    ),
    "a loop started past the spend ceiling": SPEND_CEILING_QUESTION,
    "an analyst input shortened to its window": INPUT_SHORTENED_NOTICE.format(
        detail="the first 1,000 of 9,000 characters are shown, ending in …"
    ),
    "the summariser's fence statement": SUMMARY_FENCE_STATEMENT,
    "a summariser prompt shortened to its window": SUMMARISER_SHORTENED_NOTE.format(
        shown=1000, total=9000
    ),
    "a summary cut at its output limit": SUMMARY_CUT_NOTE.format(cap=4096),
    "an ask refused at the spend ceiling": SPEND_CEILING_REFUSAL.format(callee="'helper'"),
    "the spend ceiling's reason and a call it refused": _spend_sentences(),
    "an ask refused for a mutual wait": WAITING_ON_EACH_OTHER_REFUSAL.format(callee="'helper'"),
    "the pack's decoded strings in part": triage_pack.DECODED_STRINGS_ROOM_SENTENCE.format(
        shown=10, total=90, offset=10
    ),
    "the pack's resolved hashes and decoded blobs in part": " ".join(
        [
            triage_pack.RESOLVED_HASHES_ROOM_SENTENCE.format(shown=10, total=90, offset=10),
            triage_pack.DECODED_BLOBS_ROOM_SENTENCE.format(shown=10, total=90, offset=10),
        ]
    ),
    "the pack's resolved hashes and decoded blobs lines": " ".join(
        [
            triage_pack._resolved_hashes(
                {
                    "hits": [
                        {
                            "value": "0x00000001",
                            "readings": [{"algorithm": "a", "name": "N", "dlls": ["d"]}],
                            "occurrences": [{"rva": "0x1", "function": "0x0"}],
                        }
                    ],
                    "lone_hits": [{"value": "0x00000002", "readings": [], "occurrences": []}],
                    "total": 1,
                    "candidates": {"scanned": 3},
                    "algorithms": ["a"],
                    "names": {"names": 1, "dlls": 1},
                }
            ),
            triage_pack._resolved_hashes({"hits": [], "total": 0, "candidates": {"given": 1}}),
            triage_pack._decoded_blobs(
                {
                    "results": [
                        {
                            "text": "t",
                            "rva": "0x1",
                            "scheme": "s",
                            "parameters": {"key": "0x1"},
                            "references": [
                                {"at": "0x2", "function": "0x0"},
                                {
                                    "at": "0x3",
                                    "function": "0x0",
                                    "passed_to": {
                                        "call_at": "0x9",
                                        "callee": {"slot": "0x10"},
                                        "argument": 2,
                                    },
                                },
                                {
                                    "at": "0x4",
                                    "passed_to": {
                                        "call_at": "0xa",
                                        "callee": {"function": "0x20"},
                                        "argument": 1,
                                        "address_of": "text",
                                        "output_passed_to": {
                                            "call_at": "0xc",
                                            "callee": {"import": "D.dll!F"},
                                            "argument": 3,
                                            "followed": (
                                                "the frame slot [rsp+0x40], given to that "
                                                "call as argument 2,"
                                            ),
                                            "fall_through": True,
                                        },
                                    },
                                },
                                {
                                    "at": "0x5",
                                    "passed_to": {
                                        "call_at": "0xd",
                                        "callee": {"function": "0x20"},
                                        "argument": 1,
                                        "address_of": "blob",
                                        "output_passed_to": {
                                            "call_at": "0xe",
                                            "callee": {"slot": "0x18"},
                                            "argument": 1,
                                            "followed": "that call's return value in rax",
                                            "fall_through": False,
                                            "output_passed_to": {
                                                "call_at": "0xf",
                                                "callee": {"function": "0x30"},
                                                "argument": 2,
                                                "followed": "that call's return value in rax",
                                                "fall_through": False,
                                            },
                                        },
                                    },
                                },
                            ],
                            "floss": {"function_rva": "0x0", "called_at_rva": "0x2"},
                        }
                    ],
                    "total": 1,
                    "unreferenced": 1,
                    "also_recovered_by_floss": 1,
                }
            ),
            triage_pack._decoded_blobs({"results": [], "total": 0}),
        ]
    ),
    "the pack's capability line for names resolved at runtime": triage_pack._api_capability(
        {
            "capabilities": [
                {"api": "N", "category": "c", "obtained": knowledge.RESOLVED_AT_RUNTIME}
            ],
            "resolved_at_runtime_from_hashes": ["N"],
        }
    ),
    "the APK tool's unread facts and its degraded note": " ".join(
        [
            binary.APK_UNOPENED,
            binary.MANIFEST_UNPARSED,
            binary.MANIFEST_ABSENT,
            binary.SIGNING_BLOCK_UNREAD,
            binary.CERTIFICATES_UNREAD,
            binary.DEX_UNREAD,
            binary.DEX_READER_MISSING,
            binary.DEX_FILE_UNREAD.format(number=2),
            binary.APK_STILL_ANSWERED,
            binary.apk_unread_note(["package", "permissions"], binary.MANIFEST_UNPARSED),
        ]
    ),
    "the stated candidate scan and readability test": (
        f"{api_hashes.SCAN_HEURISTIC} {string_blobs.READABLE_TEST}"
    ),
    "the decoded-blobs provenance, recall price and the lone-hits room sentence": " ".join(
        [
            triage_pack.DECODED_BLOBS_PROVENANCE,
            triage_pack.DECODED_BLOBS_RECALL,
            triage_pack.LONE_HITS_ROOM_SENTENCE,
        ]
    ),
    "the name data's source, license and module set": " ".join(
        [
            str(api_hashes.load_export_names().get("source") or ""),
            str(api_hashes.load_export_names().get("license") or ""),
            str((api_hashes.load_export_names().get("modules") or {}).get("source") or ""),
        ]
    ),
    "pack lines around real catalogue ids": " ".join(
        [
            triage_pack._hash_item(
                {
                    "value": "0x00000001",
                    "readings": [
                        {"algorithm": entry["id"], "set": "exports", "name": "N", "dlls": ["d"]}
                        for entry in api_hashes.load_algorithms()
                    ],
                    "occurrences": [{"rva": "0x1", "function": "0x0"}],
                }
            ),
            *(
                triage_pack._blob_item(
                    {
                        "text": "t",
                        "rva": "0x1",
                        "scheme": scheme,
                        "parameters": {},
                        "references": [],
                    }
                )
                for scheme in string_blobs.SCHEMES
            ),
        ]
    ),
    "the two resolving tools' descriptions": _analysis_tool_descriptions(
        "resolve_api_hashes", "decode_string_blobs"
    ),
    "the deobfuscation passes' rules and reasons": _deobfuscation_sentences(),
    "the ghidra workflow's sentence on the constants": GHIDRA_WORKFLOW[
        GHIDRA_WORKFLOW.index("- Suspected encryption") : GHIDRA_WORKFLOW.index("- Trace a key")
    ],
    "the deobfuscation passes' pack lines": _deobfuscation_lines(),
    "what a Ghidra pass that stopped says": _ghidra_pass_failures(),
    "the constant sets as the pack line names them": _constant_set_names(),
    "the constant scan's description": _analysis_tool_descriptions("find_crypto_constants"),
    "the function index tool's description": _analysis_tool_descriptions("function_index"),
    _TRANSFORM_ENTRY: _transform_sentences(),
    _UPX_ENTRY: _upx_sentences(),
    _SECTIONS_ENTRY: _sandbox_sections_sentences(),
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
            not_asked_unknown_id("T1562.001"),
            unknown_id_reason("T1562.001"),
        ]
    ),
    "analyst cut-at-cap question": analyst_cut_violation(
        4096, "CLAIM: The file opens a window.\nEVIDENCE: [ev_0001]\nCLAIM: The fi"
    ).message,
    "a later chunk's list of the earlier chunks' calls": earlier_chunks_block(
        [
            LedgerEntry(id="ev_0001", tool="a", args={"x": "1"}, output="a recorded result"),
            LedgerEntry(id="ev_0002", tool="b", args={}, ok=False),
        ]
    ),
    "a later chunk's answer from an earlier chunk's recorded result": earlier_chunk_answer(
        "a", "ev_0001", "a recorded result"
    ),
    "a decompile answered with a function an earlier entry holds": same_function_notice(
        "FUN_00401000", "ev_0001"
    ),
    "an r2 open that failed, and an r2 call made before an open": " ".join(
        [
            _r2._open_failed("/srv/samples/.tmp/x.exe", "/srv/samples/r2-work/x.exe"),
            _r2._open_failed("/srv/samples/r2-work/x.exe", "/srv/samples/r2-work/x.exe"),
            _r2._open_first("/srv/samples/r2-work/x.exe"),
        ]
    ),
    "the function map block": _function_map_text(),
    "the function index as the pack, the run state and the map say it": _function_index_text(),
    "a tool answer the conversation had no room for, as told and as recorded": " ".join(
        [no_room_sentence(12_345), not_shown_record(12_345), FUNCTION_NOT_SHOWN]
    ),
    "analyst cut-at-cap question naming a chunk": analyst_cut_violation(
        4096, "CLAIM: The file opens a window.\nCLAIM: The fi", chunk="chunk 1 of 2"
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
            not_kept_reason("x", "", "an artifact of the network analyst"),
            public_resolver_reason(
                UNATTRIBUTED_FLOW, "an artifact of the network analyst", "a claim by the x analyst"
            ),
            named_only_reason("an artifact of the network analyst"),
            named_only_reason(),
            named_only_reason("an artifact of the network analyst", SEARCHED_THE_REPORT),
            named_only_reason(
                "an artifact of the network analyst",
                asked_in="ev_0004 get_domain_report",
            ),
            seen_in_reason("ev_0002 (decompile_function)", "an artifact of the network analyst"),
            seen_in_reason(
                "ev_0006 (iocs_from_file), as the tool sections this stored report keeps show it"
            ),
            not_kept_reason(CAPTURE_TLS_NAME),
        ]
    ),
    "the line an analyst's table is printed under in Appendix A": " ".join(
        analyst_list_note(["network", "static"], kind)
        for kind in ("imports", "endpoints", "persistence")
    ),
    "the replies a tool call with no recorded reply is sent with": (
        f"{NO_REPLY_RECORDED} {NOT_RUN_REPLY}"
    ),
    "analyst question for technique lines no single id was read from": technique_line_violation(
        ["T1000 (candidate)", "T1001 or T1002"]
    ).message,
    "the claim format the analysts are given and the unparsed-answer question": " ".join(
        [CLAIM_FORMAT_FRAGMENT, _UNPARSED_ANSWER_MESSAGE]
    ),
    "the question and the reason for claim headings under DISPUTES": (
        f"{claims_under_disputes_violation(2).message} "
        f"{claims_under_disputes_sentence('reverser', 2, 1)}"
    ),
    "the recorded answer when claim headings are kept under DISPUTES": (
        claims_kept_under_disputes_finding(2).message
    ),
    "the degradation reason for claims begun and not read": claims_unread_sentence(
        "reverser", ClaimRead(claims=[], without_confidence=1, begun=4, after_disputes=2), 2
    ),
    "the unread reason and the question for a confidence the reader could not read": " ".join(
        [
            claims_unread_sentence(
                "reverser",
                ClaimRead(
                    claims=[], without_confidence=0, begun=2, confidence_unreadable=("x", "y")
                ),
                1,
            ),
            confidence_violation(1, ["x"]).message,
        ]
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
    "analyst repeated-claims question with the cut folded in": analyst_repeated_violation(
        ClaimsRepeated(begun=15, distinct=3, margin=3, chars=900, first_repeat=4), cut=4096
    ).message,
    "analyst repeated-claims question naming a chunk": analyst_repeated_violation(
        ClaimsRepeated(begun=15, distinct=3, margin=3, chars=900), chunk="chunk 1 of 2"
    ).message,
    "analyst repeated-claims question of an answer ended while it streamed": (
        analyst_repeated_violation(
            ClaimsRepeated(begun=7, distinct=3, margin=3, chars=600, first_repeat=4), ended=True
        ).message
    ),
    "decompiled functions no claim describes": _message_of(
        decompiled_not_described_violation(
            [
                DecompiledFunction(address=0x10, names=("FUN_10",), entries=("ev_0001",)),
                DecompiledFunction(address=None, names=("F",), entries=("ev_0002",)),
            ]
        )
    ),
    "ledger counts told to a revision round and to the next mediation": with_ledger_facts(
        "mediator feedback",
        ledger_count_facts(
            ["A Claim 1 counts 3 [ev_0001]; B Claim 1 counts 2."],
            {},
            [{"id": "ev_0001", "tool": "t", "structured": {"total": 3}}],
            ["a", "b"],
        ),
    ),
    "claims that say only that a library is used": _message_of(
        library_only_claims_violation(
            AgentISR(
                agent_id="a",
                domain="static",
                claims=[
                    ClaimEvidence(claim="uses a.dll APIs", evidence_ref="[ev_0001]", confidence=0.5)
                ],
            )
        )
    ),
    "claim naming a call its function's facts do not hold": _function_claim_question(),
    "claim naming a call two functions' facts do not hold, one row counted, one with none": (
        _function_claim_question(several=True)
    ),
    "judge's note on the function claims never asked": FUNCTION_CHECK_NOT_ASKED_HEAD,
    "judge's note on the function claims the analysts kept": FUNCTION_CHECK_HEAD,
    "judge technique question's describe-check finding and its kind's label": (
        technique_question_text(
            [
                TechniqueQuestion(
                    "T1112",
                    "undescribed",
                    [("static", "The file opens a window.", ["ev_0001"])],
                    check=undescribed_technique_finding("T1112", knowledge, 1),
                )
            ]
        )
    ),
    "judge technique question's card lines": technique_question_text(
        [
            TechniqueQuestion("T1003", "claimed", [("static", "The file opens a window.", [])]),
            TechniqueQuestion("T1564", "finding", [("static", "The file opens a window.", [])]),
        ]
    ),
    "analyst retry turn showing the technique's card": feedback_text(
        [
            v
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
        ]
    ),
    "question to an analyst whose first answer called no tool": no_tool_call_question(
        ["lookup", "strings"]
    ),
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
    "the fence a text tool answer is shown in": " ".join(
        [
            _FENCE_STATEMENT,
            _fenced("ev_0001", "line one\n<<a line of the answer"),
        ]
    ),
    "evidence roots beside the layers, and why a cited entry gives none": " ".join(
        [
            _ROOTS_LABEL,
            _layers_and_roots(2, ["0x1a40 in .text"], []),
            _layers_and_roots(3, ["0x1a40 in .text", "the import table"], ["ev_0001: no: x"]),
            _roots_phrase([], ["ev_0001: no: x"]),
            # Every root label, as each template writes one.
            _roots.PLACE_IN_SECTION.format(address="0x1a40", section=".text"),
            _roots.PLACE_OUTSIDE.format(address="0x1a40"),
            _roots.FUNCTION_ROOT.format(
                place=_roots.PLACE_IN_SECTION.format(address="0x1a40", section=".text")
            ),
            _roots.SECTION_ROOT.format(name=".rdata"),
            _roots.PROCESS_ROOT.format(pid=84),
            _roots.FLOW_ROOT.format(proto="tcp", host="192.0.2.1", port=443),
            _roots.DNS_ROOT.format(name="example.com"),
            _roots.FILE_OFFSET_ROOT.format(offset="0x500"),
            _roots.FILE_ROOT.format(root=_roots.PE_HEADER, file='"payload.bin"'),
            _roots.WHOLE_OTHER_FILE.format(file="sha256 abcdefabcdef"),
            *(
                sentence.format(tool="a_tool", entry="ev_0001", count=2)
                for sentence in _ROOT_SENTENCES
            ),
        ]
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


# The tools' own catalogue identifiers. A resolved hash is rendered with the id
# of the algorithm it resolves under, and a decoded text with the id of its
# scheme. The catalogues list every algorithm and scheme side by side, all
# tried alike, so an id says nothing about which one a sample uses: that
# pairing only ever comes from arithmetic on the sample's bytes. Built from the
# two vendored catalogues and nothing else
# (``test_the_catalogue_allowance_is_the_two_catalogues_and_nothing_else``).
TOOL_CATALOGUE_IDENTIFIERS: frozenset[str] = frozenset(
    [str(entry["id"]) for entry in api_hashes.load_algorithms()] + list(string_blobs.SCHEMES)
)
_CATALOGUE_TOKEN = re.compile(r"[a-z0-9_]+")

# The entries that render tool output, and the one place in them a renderer
# writes a catalogue id: right after an opening bracket, as the bracketed
# algorithm of a hash reading (``!Name [crc32_ascii]``) or the leading scheme
# token of a decoded blob (``"text"@0x3010 [xor8 key 0x9c]``). The allowance
# applies there and nowhere else; every other entry, and every other word of
# these, is scanned as it stands, so a catalogue id written as a word in any
# instruction or sentence is still a scored term.
RENDERED_TOOL_OUTPUT: frozenset[str] = frozenset(
    {
        "the pack's resolved hashes and decoded blobs lines",
        "pack lines around real catalogue ids",
    }
)
_RENDERED_ID = re.compile(r"\[([a-z0-9_]+)(?=[\] ,])")


def _without_rendered_identifiers(text: str) -> str:
    """``text`` with each catalogue id a renderer put after an opening bracket taken out."""
    return _RENDERED_ID.sub(
        lambda match: "[" if match.group(1) in TOOL_CATALOGUE_IDENTIFIERS else match.group(0),
        text,
    )


# The entries that list STIX 2.1's malware-type vocabulary, as the standard
# lists it and whole: the question about a malware object's kind names every
# value side by side, so the list says nothing about which one a sample is.
# The allowance is the joined vocabulary and nothing else; a value written as a
# word anywhere, these entries included, is still a scored term.
STIX_VOCABULARY_LISTED: frozenset[str] = frozenset({"judge malware object questions"})
_LISTED_VOCABULARY = ", ".join(MALWARE_TYPES)


def _without_the_listed_vocabulary(text: str) -> str:
    """``text`` with each whole listing of the malware-type vocabulary taken out."""
    return text.replace(_LISTED_VOCABULARY, " ")


# The byte transform tool's operation names. The tool lists every operation
# side by side and runs whichever one a model names, so a name says nothing
# about which one a sample uses: that pairing only comes from the model's own
# call on the sample's bytes. The allowance is the tool's own operation list,
# and only where a name stands as an identifier: between backticks, or as the
# value of a step's ``op`` in an answer. The same name written as a word, in
# this entry or any other, is scanned as it stands.
TRANSFORM_OPERATIONS_NAMED: frozenset[str] = frozenset({_TRANSFORM_ENTRY})
_OPERATION_ID = re.compile(r'``([a-z0-9]+)``|`([a-z0-9]+)`|"op": "([a-z0-9]+)"')


def _without_named_operations(text: str) -> str:
    """``text`` with each transform operation written as an identifier taken out."""
    from maljan.tools.transforms import OPERATIONS

    return _OPERATION_ID.sub(
        lambda match: (
            " "
            if (match.group(1) or match.group(2) or match.group(3)) in OPERATIONS
            else match.group(0)
        ),
        text,
    )


# The entry that names the sandbox report's sections and lists as the report
# names them (``analysis.sandbox_sections``): ``mutexes`` is a section and a
# CAPE report's own list, ``mutex:<n>`` the form of its items' ids. The
# allowance is those names, written as identifiers (between backticks, as a
# JSON string, or as an id prefix before its number) in that entry and nowhere
# else; the same word written as a word is scanned as it stands.
SANDBOX_REPORT_NAMES_LISTED: frozenset[str] = frozenset({_SECTIONS_ENTRY})
_REPORT_NAME_ID = re.compile(
    r'``([a-z_.]+)``|`([a-z_.]+)`|"([a-z_.]+)(?:\[\d+\])?"|(?<![\w.])([a-z]+):(?=p?\d)'
)


def _report_names() -> frozenset[str]:
    from maljan.analysis import sandbox_sections as ss

    paths = {f"behavior.summary.{key}" for keys in ss._SUMMARY_LISTS.values() for key in keys} | {
        key for keys in ss._SUMMARY_LISTS.values() for key in keys
    }
    return frozenset({*ss.SECTION_PREFIXES, *ss.SECTION_PREFIXES.values(), *paths})


def _without_report_names(text: str) -> str:
    """``text`` with each section or report list name written as an identifier taken out."""
    names = _report_names()
    return _REPORT_NAME_ID.sub(
        lambda match: (
            " " if next(g for g in match.groups() if g is not None) in names else match.group(0)
        ),
        text,
    )


def _scanned(name: str) -> str:
    """The text of one ``PROMPTS`` entry as the scan reads it."""
    text = PROMPTS[name].lower()
    if name in SANDBOX_REPORT_NAMES_LISTED:
        text = _without_report_names(text)
    if name in STIX_VOCABULARY_LISTED:
        text = _without_the_listed_vocabulary(text)
    if name in TRANSFORM_OPERATIONS_NAMED:
        text = _without_named_operations(text)
    return _without_rendered_identifiers(text) if name in RENDERED_TOOL_OUTPUT else text


def test_the_operation_allowance_is_the_tool_s_list_and_only_as_identifiers() -> None:
    from maljan.tools.transforms import OPERATIONS

    assert TRANSFORM_OPERATIONS_NAMED <= set(PROMPTS)
    assert all(re.fullmatch(r"[a-z0-9]+", name) for name in OPERATIONS)
    assert "xor" not in _without_named_operations('use ``xor`` or `rc4`; {"op": "base64"}')
    # Written as words they are scanned as they stand, and an identifier the
    # tool does not list is not let through either.
    sentence = "the replies are base64 encoded, then xor with a key, `beacon`"
    assert _without_named_operations(sentence) == sentence


def test_the_report_name_allowance_is_the_section_names_and_only_as_identifiers() -> None:
    assert SANDBOX_REPORT_NAMES_LISTED <= set(PROMPTS)
    said = '`mutexes` 1 (mutex:1); "kind": "mutexes", "behavior.summary.mutexes[0]"'
    assert "mutex" not in _without_report_names(said)
    # Written as a word it is scanned as it stands, and a name the sections
    # module does not list is not let through either.
    sentence = "the sample creates a mutex, then `beacon` and beacon:1"
    assert _without_report_names(sentence) == sentence


@pytest.mark.parametrize("tid", sorted(load_cards()))
def test_no_card_carries_a_term_the_key_scores(tid: str) -> None:
    """Every word a card shows a model is free of the key's terms, with no allowance.

    A card is read as written and again with its hyphens, underscores and
    slashes as spaces, so a term is not let through by its spelling.
    """
    text = "\n".join(card_lines(load_cards()[tid])).lower()
    spaced = re.sub(r"[-_/]+", " ", text)
    shared = [term for term in KEY_TERMS if term in text or term in spaced]
    assert not shared, f"the {tid} card carries {shared}"


def test_the_vocabulary_allowance_is_the_whole_listing_and_nothing_else() -> None:
    assert STIX_VOCABULARY_LISTED <= set(PROMPTS)
    for name in STIX_VOCABULARY_LISTED:
        assert _LISTED_VOCABULARY in PROMPTS[name].lower(), name
    # One value of the vocabulary written as a word is scanned as it stands.
    assert "downloader" in _without_the_listed_vocabulary("write downloader under the types")
    assert "downloader" not in _without_the_listed_vocabulary(f"one of: {_LISTED_VOCABULARY}.")


def test_the_catalogue_allowance_is_the_two_catalogues_and_nothing_else() -> None:
    algorithm_ids = {str(entry["id"]) for entry in api_hashes.load_algorithms()}
    assert TOOL_CATALOGUE_IDENTIFIERS == algorithm_ids | set(string_blobs.SCHEMES)
    assert all(_CATALOGUE_TOKEN.fullmatch(identifier) for identifier in TOOL_CATALOGUE_IDENTIFIERS)
    assert RENDERED_TOOL_OUTPUT <= set(PROMPTS)


def test_an_id_is_allowed_only_where_a_renderer_puts_one() -> None:
    blob = triage_pack._blob_item(
        {"text": "t", "rva": "0x1", "scheme": "base64", "parameters": {}, "references": []}
    ).lower()
    reading = triage_pack._hash_item(
        {
            "value": "0x00000001",
            "readings": [{"algorithm": "crc32_ascii", "set": "exports", "name": "n", "dlls": []}],
            "occurrences": [],
        }
    ).lower()
    assert "base64" not in _without_rendered_identifiers(blob)
    assert "crc32" not in _without_rendered_identifiers(reading)
    # The same ids written as words are not renderer output.
    sentence = "the replies are base64 encoded, then read with crc32_ascii"
    assert "base64" in _without_rendered_identifiers(sentence)
    assert "crc32" in _without_rendered_identifiers(sentence)
    assert "crc32" in _without_rendered_identifiers("[crc32 over the names]")


def test_a_bare_id_in_an_instruction_entry_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(PROMPTS, "an instruction naming a scheme", "Decode each reply as base64.")
    with pytest.raises(AssertionError, match="base64"):
        test_no_contract_prompt_or_instruction_carries_a_term_the_key_scores(
            "an instruction naming a scheme"
        )


def test_no_catalogue_description_reaches_a_model(tmp_path: Path) -> None:
    """The algorithms' descriptions are developer-facing data and are not scanned.

    That holds only while no model reads them: not in a tool's answer, not in a
    server's tool descriptions, not in a pack line. If one ever does, this
    fails, and the description is then scanned as prose like any other.
    """
    import struct
    import zlib

    from tests.unit.tools.synthetic_pe import SyntheticPE

    image = SyntheticPE()
    for offset, name in ((0x10, b"VirtualAlloc"), (0x20, b"CreateFileW")):
        image.put("data", offset, struct.pack("<I", zlib.crc32(name)))
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    answer = api_hashes.resolve_api_hashes(str(target))
    assert answer["hits"], "the answer the check reads resolves something"
    seen = " ".join(
        [
            json.dumps(answer),
            json.dumps(string_blobs.decode_string_blobs(str(target))),
            triage_pack._resolved_hashes(answer),
            _analysis_tool_descriptions(
                "resolve_api_hashes", "decode_string_blobs", "capabilities"
            ),
        ]
    ).lower()
    for entry in api_hashes.load_algorithms():
        assert str(entry["description"]).lower() not in seen, entry["id"]


@pytest.mark.parametrize("name", sorted(PROMPTS))
def test_no_contract_prompt_or_instruction_carries_a_term_the_key_scores(name: str) -> None:
    text = _scanned(name)
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
