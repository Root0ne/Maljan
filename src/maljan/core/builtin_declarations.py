"""The declarations the built-in servers, providers and in-process tools ship with.

Data, in the schema of ``maljan.core.tool_declarations``: one block per
built-in source, holding the facts the code's name tables encode today, so
every current behaviour is the default and each consumer can move from its
table to the declaration with the same output. The comment over each block
names the tables a value comes from.

Only the declaration fields are here. A built-in server's connection settings
stay in ``config._builtin_servers``; its declaration is merged from this
module under whatever an operator stored (``tool_declarations.fill_declaration``).

The static providers' and the CAPE sidecar's workflow prompts and radare2's
error patterns live here as the text of their declarations; the adapters read
the workflow from their block, so there is one copy of each. The Ghidra and
radare2 tool tables are data in ``maljan.core.builtin_reverser_tools``.
"""

from __future__ import annotations

import hashlib
import json
from functools import cache
from typing import TYPE_CHECKING, Any

from maljan.core.builtin_reverser_tools import GHIDRA_TOOLS, R2_TOOLS
from maljan.core.legacy_reputation import STORED_REPUTATION_KINDS
from maljan.core.reputation import REPUTATION_KIND
from maljan.tools.errors import BAD_ARGUMENT, TOOL_FAILED

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig
    from maljan.core.tool_declarations import SourceRef

# ---------------------------------------------------------------------------
# Model-facing text the declarations carry
# ---------------------------------------------------------------------------

# Each static provider's workflow: the tool calls, in the order the server's
# tools are best called. It is the server's declared ``prompt_fragment``, shown
# only where that server's tools are attached to the agent; the provider's own
# opening sentence and the claim guidance every static analyst is given
# (``providers.base.CLAIM_GUIDANCE``) come before it. A sentence here names only
# the server's own tools: a tool of another server is named by what it does.
GHIDRA_WORKFLOW: str = (
    "=== TOOL USAGE WORKFLOW ===\n"
    "Follow this reverse engineering sequence. Prefer the malware-specific\n"
    "analyzers first — they return pre-digested triage signals in one call,\n"
    "which is far cheaper than walking every function manually:\n"
    "1. Call `load_program(file=<path>)` to load the binary into Ghidra.\n"
    "   The file path is the absolute path on the server filesystem.\n"
    "2. Call `get_current_program_info` to verify the program loaded correctly.\n"
    "3. Call `detect_malware_behaviors` for a fast behavior-category summary.\n"
    "4. Call `analyze_api_call_chains` for suspicious API sequences with threat\n"
    "   classifications.\n"
    "5. Call `find_anti_analysis_techniques` to surface packing/anti-debug/VM\n"
    "   evasion patterns.\n"
    "6. Call `extract_iocs_with_context` to pull URLs, IPs, registry keys, and\n"
    "   filesystem paths with the calling function context.\n"
    "7. Call `list_imports` to confirm suspicious API imports raised above.\n"
    "8. Call `list_strings` for any encoded/hardcoded artefacts the IOC pass\n"
    "   missed.\n"
    "9. For the 3–5 most suspicious functions: `decompile_function(address=<addr>)`\n"
    "   then `get_xrefs_to(address=<addr>)` to confirm call-sites.\n\n"
    "=== ADVANCED TOOLS (reach for these when the triage signals call for them) ===\n"
    "- API names resolved by hash (a hashing loop, sparse imports): call\n"
    "  `emulate_hash_batch` to brute-force the obfuscated API names.\n"
    "- Suspected encryption / ransomware: the pack's crypto constants line names the\n"
    "  published constants and where they stand; a crypto-constant tool, where one\n"
    "  is attached, gives its whole answer (Ghidra's `detect_crypto_constants`\n"
    "  is not implemented).\n"
    "- Trace a key, config value, or decoded buffer through a function:\n"
    "  `analyze_dataflow(address=<addr>, direction=backward|forward)`.\n"
    "- Run a small hash / decode routine to see its output: `emulate_function`.\n"
    "- Packed binary with few functions: `find_code_gaps` to surface missed code.\n"
    "- Record `get_function_hash` on the core malicious function for attribution.\n"
    "- The falsification the verification discipline asks for is `emulate_function`\n"
    "  with a known input, or `analyze_dataflow(direction=backward)`.\n\n"
    "IMPORTANT:\n"
    "- Step 1 (load_program) MUST happen before any analysis tool call.\n"
    "- Always prefer the high-level malware analyzers (steps 3–6) before\n"
    "  decompiling individual functions — they are much cheaper.\n"
    "- Focus decompilation on 3-5 most suspicious functions, not every function.\n"
    "- Large binaries may have 1000+ functions. Prioritize entry point, main,\n"
    "  and functions referencing crypto/network/process APIs.\n"
    "- Summarize assembly patterns instead of dumping raw hex."
)

R2_WORKFLOW: str = (
    "=== TOOL USAGE WORKFLOW ===\n"
    "1. Call `open_file` with the path you are given, then `analyze` to run the\n"
    "   analysis pass.\n"
    "2. Call `list_imports` and `list_strings` to see what the binary can reach.\n"
    "3. Call `list_functions` and pick the 3-5 that reference crypto, network or\n"
    "   process APIs; `decompile_function` those and `xrefs_to` their addresses.\n"
    "4. Summarise assembly patterns instead of dumping raw hex, and prefer one\n"
    "   summarising call over many narrow ones.\n"
)

# The CAPE MCP sidecar's workflow, the CAPE sandbox provider's dynamic
# fragment (``providers.sandbox.cape2``), sent only where its tools are attached.
CAPE_WORKFLOW: str = (
    "=== TOOL USAGE WORKFLOW ===\n"
    "Follow this sequence when given a file path or hash:\n"
    "1. Call `get_cuckoo_status` to verify the sandbox is online.\n"
    "2. Call `search_task(hash_value=<sha256>)` to check if this sample was already analyzed.\n"
    "3. If no existing task: call `submit_file(file_path=<path>)` to submit for analysis.\n"
    "4. After submission, POLL with `get_task_status(task_id=<id>)` until status "
    "is 'reported'.\n"
    "5. Once reported: call `get_task_report(task_id=<id>, format='lean')` for a "
    "summarized report.\n"
    "6. Call `get_task_iocs(task_id=<id>)` for IOCs (domains, IPs, mutexes).\n"
    "7. Optionally call `get_task_config(task_id=<id>)` for extracted malware configs.\n\n"
    "IMPORTANT: Always use format='lean' for reports to avoid context overflow. "
    "The lean format filters 50MB reports down to key findings.\n"
    "If given a Task ID directly, skip to step 5."
)

# What r2mcp is told after an answer that says no file is open, without and
# with the path radare2 can open for the job's sample.
R2_OPEN_FILE_FIRST = "call open_file with the path you are given, then call this tool again"
R2_OPEN_FILE_FIRST_AT = "call open_file with {sample_path}, then call this tool again"

# radare2's log envelope: r2mcp hands back what radare2 logged while running a
# command inside ``<log>…</log>``. An envelope and nothing else, whose lines
# are all radare2 log lines (``[LEVEL] text``, the level at the start of the
# line) with at least one ``[ERROR]`` or ``[FATAL]`` line, is radare2 saying the
# command failed with no answer beside it; the message is its lines. A line
# ends exactly where Python's ``str.splitlines`` ends one, a line holding only
# whitespace (as ``str.isspace`` has it, Unicode included) is blank, and a
# level tag in the middle of a line is part of that line's text.
_LINE_BREAK = r"\n\x0b\x0c\r\x1c-\x1e\x{85}\x{2028}\x{2029}"
_IN_LINE_SPACE = r"\t\x1f \x{a0}\x{1680}\x{2000}-\x{200a}\x{202f}\x{205f}\x{3000}"
_BREAK = rf"[{_LINE_BREAK}]"
_BLANK = rf"[{_IN_LINE_SPACE}]*"
_TEXT = rf"[^{_IN_LINE_SPACE}{_LINE_BREAK}][^{_LINE_BREAK}]*"
_LOG_LINE = rf"{_BLANK}\[[A-Z]+\]{_BLANK}{_TEXT}"
_FAILURE_LINE = rf"{_BLANK}\[(?:ERROR|FATAL)\]{_BLANK}{_TEXT}"
_ANY_LINE = rf"(?:{_LOG_LINE}|{_BLANK})"
R2_LOG_ENVELOPE = (
    rf"<log>(?P<body>(?:{_ANY_LINE}{_BREAK})*{_FAILURE_LINE}(?:{_BREAK}{_ANY_LINE})*)</log>"
)

# The ways r2mcp says "error" in place of an answer, in the order they are
# held: the open-first refusal it raises as an MCP protocol error, its log
# envelope, and the sentences it writes as an ordinary text result (without
# these the ledger filed "Invalid regex used in filter parameter, try a simpler
# expression" as a successful ``list_strings`` whose output was that sentence).
R2_ERROR_PATTERNS: tuple[dict[str, Any], ...] = (
    {
        "match": r"(?:\w+: )?Use the open_file method before calling any other method\b.*",
        "code": TOOL_FAILED,
        "applies_to": ["protocol_error"],
        "remediation": R2_OPEN_FILE_FIRST,
        "remediation_with_path": R2_OPEN_FILE_FIRST_AT,
    },
    {"match": R2_LOG_ENVELOPE, "code": TOOL_FAILED, "multiline": True, "message_group": "body"},
    {"match": r"Invalid regex used in filter parameter\b.*", "code": BAD_ARGUMENT},
    {"match": r"Invalid parameter '[^']*':.*", "code": BAD_ARGUMENT},
    {"match": r"Invalid params:.*", "code": BAD_ARGUMENT},
    {"match": r"Missing required parameter:.*", "code": BAD_ARGUMENT},
    {"match": r"Unknown tool: .*", "code": BAD_ARGUMENT},
    {"match": r"Unknown decompiler\b.*", "code": BAD_ARGUMENT},
    {
        "match": r"Cannot run (?:commands|script files) without calling the `open_file` tool.*",
        "code": TOOL_FAILED,
        "remediation": R2_OPEN_FILE_FIRST,
        "remediation_with_path": R2_OPEN_FILE_FIRST_AT,
    },
    {
        "match": r"No file is currently open\..*",
        "code": TOOL_FAILED,
        "remediation": R2_OPEN_FILE_FIRST,
        "remediation_with_path": R2_OPEN_FILE_FIRST_AT,
    },
    {
        "match": r"Failed to (?:open file|initialize r(?:adare)?2(?: core)?)\b.*",
        "code": TOOL_FAILED,
    },
    {"match": r"Error: command returned NULL", "code": TOOL_FAILED},
)

# ---------------------------------------------------------------------------
# Shared tool facts
# ---------------------------------------------------------------------------

# Where an asserting tool's answer names technique ids: under these keys within
# six levels, as ``pipeline.evidence_summary._technique_ids`` reads every source.
TECHNIQUES_ANYWHERE: tuple[dict[str, str], ...] = (
    {"path": "/**6/technique_id", "format": "attck"},
    {"path": "/**6/attck", "format": "attck"},
    {"path": "/**6/technique_ids", "format": "attck"},
    {"path": "/**6/tags", "format": "sigma_tag"},
)

_PATH = {"path": "path", "carved": "carved_path"}

# The answer shapes a reader is named by (documented in the configuration
# guide's tool declarations section). Each is a shape the paths alone cannot
# express; a shape the paths express has no reader.
READERS: dict[str, str] = {
    "pe_header": "a PE header answer: sections and the entry point, read as file layout",
    "emulated_strings_with_call_sites": (
        "rows of recovered strings, each with the call site that produced it and the "
        "routine around it, joined to the encoded blobs a static decoder read at that site"
    ),
    "function_table": "a function index: per function its start, range and what it references",
    "byte_transform": "the result of byte transforms over a range of the file, with its origin",
    "unpacked_image": "an unpacked program written out as a file of its own",
    "flow_table": "flows and DNS queries with their endpoints, from a capture or a sandbox",
    "dns_query_lines": "a text answer holding one DNS query per line",
    "packet_lines": "a text answer holding one captured packet per line, with its endpoints",
    "report_items": "sandbox report items, each with an id and the fields that place it",
}

_CAPABILITY_RULES: dict[str, Any] = {
    "kind": "capability_rules",
    "asserts_techniques": True,
    "source": "capa",
    "long_running": True,
    "rows": "/capabilities/*",
    "places": {"addresses": "/addresses"},
    "values": {"rule": "/rule", "namespace": "/namespace"},
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": {"path": "path"},
    "display_name": "capa",
}
_SIGNATURE_RULES: dict[str, Any] = {
    "kind": "signature_rules",
    "asserts_techniques": True,
    "source": "yara",
    "rows": "/matches/*",
    "places": {"offset": "/strings/*/offset", "instance_offset": "/strings/*/instances/*/offset"},
    "values": {"rule": "/rule"},
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": _PATH,
    "words": ["yara", "rule", "rules"],
    "display_name": "YARA",
}


def _event_rules(argument: str) -> dict[str, Any]:
    return {
        "kind": "event_rules",
        "asserts_techniques": True,
        "source": "sigma",
        "rows": "/matches/*",
        "places": {"command_line": "/matched_fields/CommandLine"},
        "values": {"rule": "/rule", "title": "/title"},
        "techniques": list(TECHNIQUES_ANYWHERE),
        "arguments": {argument: argument},
        "words": ["sigma", "rule", "rules"],
        "display_name": "Sigma",
    }


_STRINGS: dict[str, Any] = {
    "kind": "strings",
    "rows": "/strings/*",
    "places": {"offset": "/offset"},
    "values": {"text": "/text"},
    "arguments": _PATH,
}
_EMULATED_STRINGS: dict[str, Any] = {
    "kind": "emulated_strings",
    "long_running": True,
    "rows": "/strings/*",
    "places": {"call_site": "/called_at_rva", "function": "/function_rva"},
    "values": {"text": "/string", "scheme": "/kind"},
    "arguments": _PATH,
    "reader": "emulated_strings_with_call_sites",
    "words": ["decoded", "emulation", "floss"],
    "display_name": "FLOSS",
}
_DECODED_STRINGS: dict[str, Any] = {
    "kind": "decoded_strings",
    "rows": "/results/*",
    "places": {"rva": "/rva"},
    "values": {"text": "/text"},
    "arguments": _PATH,
}
_API_HASHES: dict[str, Any] = {
    "kind": "api_hash_resolution",
    "rows": "/hits/*",
    "places": {"rva": "/occurrences/*/rva"},
    "values": {"name": "/readings/*/name"},
    "arguments": _PATH,
}


def _file(kind: str, reader: str = "") -> dict[str, Any]:
    facts: dict[str, Any] = {"kind": kind, "arguments": _PATH}
    if reader:
        facts["reader"] = reader
    return facts


_REFERENCE = {"kind": "reference"}
_API_CATALOGUE = {"kind": "api_catalogue"}
_CAPABILITIES = {"kind": "capabilities"}
_COMMAND_MATCH: dict[str, Any] = {
    "kind": "command_match",
    "asserts_techniques": True,
    "source": "lolbin",
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": {"command_lines": "command_lines"},
}
_PCAP_WORDS = ["capture", "packet", "packets", "pcap"]
_PCAP_SUMMARY: dict[str, Any] = {
    "kind": "pcap",
    "arguments": {"path": "pcap_path"},
    "reader": "flow_table",
    "words": _PCAP_WORDS,
}

# The analysis sidecar's tools. Answer shapes from ``analysis.evidence_roots``
# ``_read_entry``; capa and FLOSS long-running and YARA's own budget as the
# sidecar's manifest (``services/analysis-mcp/server.py`` TOOL_NEEDS) declares.
_ANALYSIS_TOOLS: dict[str, dict[str, Any]] = {
    "apk_info": _file("format_info"),
    "archive_list": _file("archive_listing"),
    "capa": _CAPABILITY_RULES,
    "capabilities": _CAPABILITIES,
    "carve_payloads": _file("carve"),
    "decode_string_blobs": _DECODED_STRINGS,
    "document_info": _file("document_info"),
    "elf_info": _file("format_info"),
    "find_crypto_constants": _file("crypto_constants"),
    "floss": _EMULATED_STRINGS,
    "function_index": {**_file("function_index", "function_table")},
    "hashes": _file("identity"),
    "identify_file": _file("identity"),
    "iocs_from_file": _file("file_iocs"),
    "iocs_from_text": {"kind": "text_iocs", "arguments": {"text": "text"}},
    "macho_info": _file("format_info"),
    "pe_info": _file("format_info", "pe_header"),
    "put_sample": {"kind": "sample_delivery"},
    "put_sample_begin": {"kind": "sample_delivery"},
    "put_sample_chunk": {"kind": "sample_delivery"},
    "put_sample_finish": {"kind": "sample_delivery"},
    "resolve_api_hashes": _API_HASHES,
    "sigma_match": _event_rules("events"),
    "sigma_match_sandbox": _event_rules("report"),
    "signing_info": _file("signing"),
    "strings": _STRINGS,
    "transform_bytes": _file("transform", "byte_transform"),
    "unpack_upx": _file("unpack", "unpacked_image"),
    "yara_scan": {**_SIGNATURE_RULES, "timeout_seconds": 60},
}

_KNOWLEDGE_TOOLS: dict[str, dict[str, Any]] = {
    "api_capability": _API_CATALOGUE,
    "attck_lookup": _REFERENCE,
    "attck_validate": _REFERENCE,
    "capabilities": _CAPABILITIES,
    "family_lookup": _REFERENCE,
    "lolbin_lookup": _COMMAND_MATCH,
    "resolve_technique": _REFERENCE,
    "similar_cases": _REFERENCE,
}

_NETWORK_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "extract_dns": {
        "kind": "dns",
        "arguments": {"path": "pcap_path"},
        "reader": "dns_query_lines",
    },
    "extract_http": {"kind": "http", "arguments": {"path": "pcap_path"}},
    "pcap_summary": _PCAP_SUMMARY,
    "read_pcap_summary": {**_PCAP_SUMMARY, "kind": "packet_overview", "reader": "packet_lines"},
}

# The threat-intel sidecar answers in prose. The live sidecar writes
# "42/71 malicious, 0/71 suspicious" (``services/threatintel-mcp/server.py``);
# its mock writes "55/70 detections". Both are declared. Its rank puts it
# after VirusTotal's own server, which the triage pack asks first when both
# are enabled.
_THREATINTEL_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "check_domain_reputation": {
        "kind": "indicator_reputation",
        "arguments": {"domain": "domain"},
    },
    "check_hash": {
        "kind": "reputation",
        "arguments": {"hash": "file_hash"},
        "display_name": "Threat intelligence",
        "reputation": {
            "text_patterns": [
                r"(?i)\b(?P<malicious>\d+)\s*/\s*(?P<total>\d+)\s+detections?\b",
                r"(?i)\b(?P<malicious>\d+)\s*/\s*(?P<total>\d+)\s+malicious\b"
                r"(?:,\s*(?P<suspicious>\d+)\s*/\s*\d+\s+suspicious\b)?",
            ],
            "rank": 20,
        },
    },
    "check_ip_reputation": {"kind": "indicator_reputation", "arguments": {"ip": "ip_address"}},
    "get_threatintel_status": {"kind": "status"},
}

# VirusTotal's own server: the lookups and submit tools of ``core.virustotal``;
# the file report's shape read within eight levels of the answer: its engine
# counts, its popular threat labels, its per-engine detection labels, its
# dates and its report link, as the API and the agent server write them.
# Rank 10: the triage pack asks it before the threat-intel sidecar.
_VT_REPUTATION: dict[str, Any] = {
    "service": "VirusTotal",
    "stats": "/**7/last_analysis_stats",
    "malicious": "/**7/last_analysis_stats/malicious",
    "suspicious": "/**7/last_analysis_stats/suspicious",
    "labels": [
        "/**7/popular_threat_classification/suggested_threat_label",
        "/**7/popular_threat_classification/popular_threat_name/*/value",
        "/**7/popular_threat_classification/popular_threat_category/*/value",
    ],
    "detections": "/**7/detections",
    "engines": "/**7/coverage/engines",
    "first_seen": [
        "/**7/first_submission_date",
        "/**7/first_seen_itw_date",
    ],
    "last_seen": [
        "/**7/last_analysis_date",
        "/**7/analysis_date",
        "/**7/last_submission_date",
    ],
    "link": ["/**7/report_url", "/**7/gui_url", "/**7/permalink", "/**7/html_url"],
    "rank": 10,
}
_VIRUSTOTAL_TOOLS: dict[str, dict[str, Any]] = {
    "get_analysis": {"kind": "submission_status"},
    "get_domain_report": {"kind": "indicator_report"},
    "get_file_report": {
        "kind": "reputation",
        "arguments": {"hash": "hash"},
        "reputation": _VT_REPUTATION,
        "display_name": "VirusTotal",
    },
    "get_ip_report": {"kind": "indicator_report"},
    "get_submission": {"kind": "submission_status"},
    "get_url_report": {"kind": "indicator_report"},
    "submit_file": {"kind": "submission", "discloses_sample": True},
    "submit_local_file": {"kind": "submission", "discloses_sample": True},
}

# The platform's sandbox report tools (``providers.sandbox_tools``). Shapes as
# ``analysis.evidence_roots`` and ``reporting.ledger_report._BUILDERS`` read
# them; the signatures assert techniques (``evidence_summary.asserting_source``).
_SANDBOX_TOOLS: dict[str, dict[str, Any]] = {
    "sandbox_report_section": {"kind": "sandbox_report_section"},
    "sandbox_processes": {
        "kind": "sandbox_processes",
        "rows": "/processes/*",
        "places": {"pid": "/pid"},
        "values": {"command_line": "/command_line", "name": "/name"},
    },
    "sandbox_network": {"kind": "sandbox_network", "reader": "flow_table"},
    "sandbox_signatures": {
        "kind": "sandbox_signatures",
        "asserts_techniques": True,
        "source": "sandbox",
        "techniques": list(TECHNIQUES_ANYWHERE),
    },
    "sandbox_dropped_files": {"kind": "sandbox_dropped_files"},
    "sandbox_registry_ops": {"kind": "sandbox_registry"},
    "sandbox_api_calls": {"kind": "sandbox_api_calls"},
    "sandbox_mutexes": {"kind": "sandbox_mutexes"},
    "sandbox_services_and_tasks": {"kind": "sandbox_services"},
    "sandbox_channels": {"kind": "sandbox_channels"},
    "sandbox_items": {"kind": "sandbox_items", "reader": "report_items"},
}

# The triage pack's steps (``pipeline.triage_pack``), each recorded under the
# pack's own source. The in-process implementations answer as the sidecar's
# tools of the same name do, so they declare the same facts.
_PACK_TOOLS: dict[str, dict[str, Any]] = {
    **{
        name: _ANALYSIS_TOOLS[name]
        for name in (
            "identify_file",
            "hashes",
            "signing_info",
            "pe_info",
            "elf_info",
            "macho_info",
            "apk_info",
            "document_info",
            "archive_list",
            "strings",
            "iocs_from_file",
            "capa",
            "sigma_match_sandbox",
            "floss",
            "resolve_api_hashes",
            "decode_string_blobs",
            "find_crypto_constants",
            "function_index",
            "unpack_upx",
        )
    },
    "yara_scan": _SIGNATURE_RULES,
    "api_capability": _API_CATALOGUE,
    "lolbin_lookup": _COMMAND_MATCH,
    "find_anti_analysis_techniques": {
        "kind": "anti_analysis_scan",
        "report_sections": ["packing_obfuscation", "evasion_antiforensics"],
    },
    "function_matches": {"kind": "function_matches"},
    # The pack's own entry for a reputation lookup that did not happen
    # (``triage_pack.REPUTATION_STEP``), which ``run_state`` shows beside a lookup.
    "reputation": {"kind": "reputation_not_asked"},
    "pcap_summary": _PCAP_SUMMARY,
    "sandbox_status": {"kind": "sandbox_status"},
    "sandbox_sections": {"kind": "sandbox_sections"},
    **{
        name: _SANDBOX_TOOLS[name]
        for name in (
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_channels",
        )
    },
}

# ---------------------------------------------------------------------------
# Which kinds each consumer's table is
# ---------------------------------------------------------------------------

# A reputation lookup about the sample: ``reputation`` (``core.reputation``),
# and the two kinds the built-in lookups declared before it, which facts
# records stored then still carry (``core.legacy_reputation``).
REPUTATION_KINDS: tuple[str, ...] = (REPUTATION_KIND, *STORED_REPUTATION_KINDS)

# Each name table the core reads tools by, as the set of kinds that is exactly
# that table over every built-in tool (``tests/unit/core/
# test_every_built_in_declares_what_its_name_tables_say.py`` holds each one
# equal, tool by tool). A consumer that moves onto the declaration reads the
# kinds named here. ``legacy_names`` are names a table holds that no built-in
# tool has; a consumer keeps them for stored runs and servers declared by name.
CONSUMER_KINDS: dict[str, dict[str, Any]] = {
    "evidence_roots._WHOLE_FILE_TOOLS": {"kinds": ["identity", "signing"]},
    "evidence_roots.FILE_ASSESSMENT_TOOLS": {"kinds": [*REPUTATION_KINDS, "reputation_not_asked"]},
    "evidence_roots._REFERENCE_TOOLS": {
        "kinds": ["reference", "api_catalogue", "capabilities", "indicator_report"]
    },
    "evidence_roots._IMPORT_LISTINGS": {
        "kinds": ["import_listing"],
        "legacy_names": ["get_imports"],
    },
    "evidence_roots._EXPORT_LISTINGS": {
        "kinds": ["export_listing"],
        "legacy_names": ["get_exports"],
    },
    "evidence_roots._PROGRAM_TOOLS": {
        "kinds": ["program_info"],
        "legacy_names": ["get_program_info", "program_info", "get_current_program"],
    },
    "evidence_roots._OPEN_TOOLS": {"kinds": ["load_sample", "open_project_program", "open_sample"]},
    "evidence_bundles._STRING_TOOLS": {
        "kinds": ["strings", "emulated_strings", "file_iocs", "listing_strings"]
    },
    "evidence_bundles._NETWORK_SANDBOX_TOOLS": {"kinds": ["sandbox_network", "pcap"]},
    "evidence_bundles.SANDBOX_TOOL_PREFIXES": {
        "kinds": [
            "sandbox_report_section",
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_registry",
            "sandbox_api_calls",
            "sandbox_mutexes",
            "sandbox_services",
            "sandbox_channels",
            "sandbox_items",
            "sandbox_status",
            "sandbox_sections",
            "pcap",
        ]
    },
    "ledger_report._FUNCTION_TOOLS": {
        "kinds": ["decompile", "function_disassembly"],
        "legacy_names": ["decompile", "get_function", "analyze_function", "pdf", "pdc"],
    },
    "ledger_report._FUNCTION_LIST_TOOLS": {
        "kinds": ["function_list", "method_list"],
        "legacy_names": ["get_functions", "afl"],
    },
    "validation._REFERENCE_SECTION_SOURCES": {"kinds": ["api_catalogue"]},
    "validation._SAMPLE_VALUE_SECTION_SOURCES": {
        "kinds": ["strings", "file_iocs", "emulated_strings"]
    },
    "validation._RULE_MATCH_SECTION_SOURCES": {
        "kinds": ["capability_rules", "signature_rules"],
        "legacy_names": ["yara"],
    },
    "markdown._ANALYSIS_TOOLS": {
        "kinds": [
            "capability_rules",
            "signature_rules",
            "command_match",
            "api_catalogue",
            "strings",
        ]
    },
    "markdown._REPUTATION_TOOLS": {
        "kinds": list(REPUTATION_KINDS),
        "legacy_names": ["file_report", "hash_lookup"],
    },
    "markdown._SANDBOX_TOOLS": {"same_as": "evidence_bundles.SANDBOX_TOOL_PREFIXES"},
    "triage_pack._REPUTATION_TOOLS": {"kinds": [*REPUTATION_KINDS, "reputation_not_asked"]},
    "triage_pack.RULE_TOOLS": {"kinds": ["capability_rules", "signature_rules"]},
    "run_state.reputation": {"kinds": [*REPUTATION_KINDS, "reputation_not_asked"]},
    "network_analyst._PCAP_TOOLS": {"kinds": ["packet_overview", "dns", "http"]},
    "function_map": {
        "kinds": ["api_hash_resolution", "decoded_strings", "emulated_strings", "function_index"]
    },
    "stix_renderer.recovering": {
        "kinds": ["emulated_strings", "decoded_strings", "strings", "file_iocs"]
    },
    "stix_renderer.DECODER_TOOL": {"kinds": ["decoded_strings"]},
    "stix_renderer._STRING_SWEEP_TOOLS": {"kinds": ["strings", "file_iocs", "text_iocs"]},
    "figures.code_listing": {"kinds": ["decompile"]},
    "ledger_projection.technique_hits": {"kinds": ["capability_rules"]},
    # The single-tool comparisons the reading half made inline.
    "evidence_summary.yara_rule_strings": {"kinds": ["signature_rules"]},
    "evidence_summary.catalogue_associations": {"kinds": ["api_catalogue"]},
}

# Which section builder of ``reporting.ledger_report._BUILDERS`` each kind is
# drawn with. A kind not named here gets the generic block.
BUILDER_OF_KIND: dict[str, str] = {
    "identity": "_identity",
    "signing": "_signing",
    "format_info": "_binary_info",
    "strings": "_strings",
    "text_iocs": "_iocs",
    "file_iocs": "_iocs",
    "signature_rules": "_yara",
    "event_rules": "_sigma",
    "capability_rules": "_capa",
    "sandbox_processes": "_sandbox_processes",
    "sandbox_network": "_sandbox_network",
    "sandbox_signatures": "_sandbox_signatures",
    "sandbox_dropped_files": "_sandbox_dropped",
    "sandbox_registry": "_sandbox_registry",
    "sandbox_api_calls": "_sandbox_apis",
    "sandbox_mutexes": "_sandbox_mutexes",
    "sandbox_services": "_sandbox_services",
    "sandbox_report_section": "_sandbox_section",
    "sandbox_items": "_sandbox_items",
    "sandbox_status": "_sandbox_status",
    "pcap": "_pcap",
    **{kind: "_reputation" for kind in REPUTATION_KINDS},
}

# ---------------------------------------------------------------------------
# The blocks
# ---------------------------------------------------------------------------

# Each built-in server's declaration. ``roles``: ``reputation`` on the two
# servers that declare a reputation lookup. ``reads_staged_sample`` on the
# servers of ``agents.tool_pinning.PINNED_SERVERS``. ``required_env_allow`` as
# ``config.REQUIRED_ENV_ALLOW``. ``platform_owned`` on the servers of
# ``agents.evidence_recorder._RESOLVING_SERVERS``. VirusTotal's reference URL
# as ``reporting.builder._build_references`` and
# ``reporting.detection_signatures`` write it.
_SERVER_BLOCKS: dict[str, dict[str, Any]] = {
    "analysis": {
        "roles": ["rule_scanner", "strings", "decoder"],
        "required_env_allow": [
            "MALJAN_STAGING_DIR",
            "MALJAN_STAGING_TTL_HOURS",
            "MALJAN_SAMPLE_ROOTS",
        ],
        "reads_staged_sample": True,
        "platform_owned": True,
        "tool_facts": _ANALYSIS_TOOLS,
    },
    "knowledge": {
        "roles": ["reference"],
        "required_env_allow": ["MALJAN_INDEX_RETRY_SECONDS"],
        "reads_staged_sample": True,
        "tool_facts": _KNOWLEDGE_TOOLS,
    },
    "network": {
        "roles": ["capture"],
        "required_env_allow": ["MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"],
        "reads_staged_sample": True,
        "tool_facts": _NETWORK_TOOLS,
    },
    "threatintel": {"roles": ["reputation"], "tool_facts": _THREATINTEL_TOOLS},
    "virustotal": {
        "roles": ["reputation"],
        "reference_urls": ["https://www.virustotal.com/gui/file/{sha256}"],
        "tool_facts": _VIRUSTOTAL_TOOLS,
    },
}

# The static providers' own blocks (``static.ghidra``, ``static.r2``) and the
# CAPE MCP sidecar's (``sandbox.cape2.mcp``). Ghidra's mount is the container
# path the shipped compose file mounts the samples directory at, which its
# provider's ``mirror_spec`` reads; its ``sample_open`` is
# ``config.GHIDRA_SAMPLE_OPEN``, set where it has always been set; its work
# directory is the shared default (``providers.base.DEFAULT_WORK_DIR``) and
# radare2's is its ``mirror_dir``'s own default; its non-secret variable, which
# texts written before the variable was retired still name, is kept whole by
# the redaction of published text (``shipped_variable_names``). The
# auto-name prefixes together are ``pipeline.validation._GENERIC_FUNCTION_NAME``'s.
_PROVIDER_BLOCKS: dict[str, dict[str, Any]] = {
    "ghidra": {
        "sample_mount": "/data/samples",
        "work_dir": ".work",
        "roles": ["decompiler", "disassembler"],
        "prompt_fragment": GHIDRA_WORKFLOW,
        "variable_names": ["GHIDRA_CONTAINER_SAMPLES_PATH"],
        "auto_name_prefixes": ["FUN_", "LAB_", "SUB_"],
        "tool_facts": GHIDRA_TOOLS,
    },
    "r2": {
        "work_dir": "r2-work",
        "roles": ["decompiler", "disassembler"],
        "prompt_fragment": R2_WORKFLOW,
        "error_patterns": list(R2_ERROR_PATTERNS),
        "auto_name_prefixes": ["fcn.", "loc.", "sub.", "func."],
        "tool_facts": R2_TOOLS,
    },
    "cape2_mcp": {"roles": ["sandbox"], "prompt_fragment": CAPE_WORKFLOW},
}

# The platform's own in-process sources, declared like any server.
_IN_PROCESS_BLOCKS: dict[str, dict[str, Any]] = {
    "pack": {"label": "Triage pack", "platform_owned": True, "tool_facts": _PACK_TOOLS},
    "sandbox": {"label": "Sandbox report", "roles": ["sandbox"], "tool_facts": _SANDBOX_TOOLS},
    "provider:capa_yara": {
        "label": "capa and YARA",
        "roles": ["rule_scanner"],
        "tool_facts": {"capa": _CAPABILITY_RULES, "yara_scan": _SIGNATURE_RULES},
    },
}


def builtin_server_names() -> tuple[str, ...]:
    """The keys of ``mcp.servers`` that ship a declaration."""
    return tuple(_SERVER_BLOCKS)


def server_declaration(key: str) -> dict[str, Any]:
    """The declaration fields a built-in server ships with; ``{}`` for any other key."""
    return _block(_SERVER_BLOCKS.get(key, {}))


def provider_names() -> tuple[str, ...]:
    """The provider-owned blocks that ship a declaration."""
    return tuple(_PROVIDER_BLOCKS)


def provider_declaration(provider: str) -> dict[str, Any]:
    """The declaration fields a provider-owned block ships: ghidra, r2, cape2_mcp."""
    return _block(_PROVIDER_BLOCKS.get(provider, {}))


@cache
def shipped_variable_names() -> frozenset[str]:
    """Every non-secret environment variable name a shipped declaration names.

    Each server and provider block says the variable names its own sentences
    name (``variable_names``); the redaction of published text keeps them
    (``pipeline.events``). Read from the shipped data alone, so the rule does
    not depend on which run's settings publish.
    """
    names: set[str] = set()
    for blocks in (_SERVER_BLOCKS, _PROVIDER_BLOCKS, _IN_PROCESS_BLOCKS):
        for block in blocks.values():
            names.update(str(name) for name in block.get("variable_names") or ())
    return frozenset(names)


def _block(block: dict[str, Any]) -> dict[str, Any]:
    """A fresh copy of one block, so no caller can change the shipped data."""
    return {key: _deep(value) for key, value in block.items()}


def _deep(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_deep(v) for v in value]
    return value


@cache
def _in_process_validated() -> dict[str, MCPServerConfig]:
    from maljan.core.config import MCPServerConfig

    return {key: MCPServerConfig.model_validate(_block(b)) for key, b in _IN_PROCESS_BLOCKS.items()}


def in_process_declarations() -> dict[SourceRef, MCPServerConfig]:
    """The platform's in-process sources, each as a fresh block of declaration fields."""
    from maljan.core.tool_declarations import SourceRef

    return {
        SourceRef.parse(key): cfg.model_copy(deep=True)
        for key, cfg in _in_process_validated().items()
    }


def shipped_digest() -> str:
    """A short digest of every declaration this module ships, for a run's record."""
    body = {
        "servers": _SERVER_BLOCKS,
        "providers": _PROVIDER_BLOCKS,
        "in_process": _IN_PROCESS_BLOCKS,
    }
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
