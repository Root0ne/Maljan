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
from collections.abc import Mapping
from functools import cache
from typing import TYPE_CHECKING, Any

from maljan.core import virustotal
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
# the server's own tools; a tool of another server is named only inside
# ``{{attached:<server>|<while that server is attached>|<otherwise>}}``, which
# the prompt resolves for the servers the request carries
# (``prompt_fragments.resolve_attached``).
# Ghidra's verification discipline, as its prompt has always worded it, with
# its own examples. The shared discipline every other static provider carries
# (``providers.base.VERIFICATION_DISCIPLINE``) holds the same rules in generic
# words; this text stays with Ghidra's declaration so a Ghidra run's prompt is
# unchanged.
GHIDRA_VERIFICATION_DISCIPLINE: str = (
    "=== VERIFICATION DISCIPLINE (suppresses confidently-wrong attribution) ===\n"
    "- A SPECIFIC claim (a named algorithm like RC4/djb2/ROR13, a constant or XOR\n"
    "  key, or a hash-resolved API) may reach CONFIDENCE >= 0.8 only if you\n"
    "  FALSIFIED it first: an emulation with a known input against the expected\n"
    "  output, OR a backward data-flow trace confirming its origin. If no such\n"
    "  check ran — the code is non-leaf or has syscall/heap side effects, or no\n"
    "  tool that runs one is attached to this request — cap CONFIDENCE at 0.7.\n"
    "- A hash-resolution result: read the FULL list of matches. If more than one\n"
    "  API name collides, do NOT blindly take the best match — disambiguate via\n"
    "  the likely source DLL, or emit CONFIDENCE <= 0.5.\n"
    "- A claim is High (>= 0.8) only with >= 2 independent evidence loci (e.g. an\n"
    "  import AND its call-site). A single locus caps at 0.7. Reconcile any\n"
    "  contradictory signals before emitting.\n"
    "- Dynamic API resolution (LoadLibrary + GetProcAddress) is by itself the\n"
    "  ORDINARY Windows idiom for optional/delay-loaded DLLs — it is NOT evidence\n"
    "  of packing or obfuscation (T1027) on its own. Only claim T1027 when you\n"
    "  observe a REAL obfuscation mechanism: a hashing/decrypt loop over API\n"
    "  names, a high-entropy/packed section, an unpacking stub, or a sparse\n"
    "  import table that hides the real APIs. A rich, fully-named import table\n"
    "  (dozens of imports across several DLLs) argues AGAINST packing. Do not\n"
    "  inflate a plain LoadLibrary/GetProcAddress pair into an obfuscation claim."
)

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
    "9. Decompile the functions that matter for the question: `batch_decompile`\n"
    "   for several at once, `decompile_function(address=<addr>)` for one; then\n"
    "   `get_xrefs_to(address=<addr>)` to confirm call-sites.\n\n"
    "=== ADVANCED TOOLS (reach for these when the triage signals call for them) ===\n"
    "- API names resolved by hash (a hashing loop, sparse imports): call\n"
    "  `emulate_hash_batch` to brute-force the obfuscated API names.\n"
    "- Suspected encryption / ransomware: the pack's crypto constants line names the\n"
    "  published constants and where they stand; "
    "{{attached:analysis|`find_crypto_constants` on the\n"
    "  analysis server|a crypto-constant tool, where one\n"
    "  is attached,}} gives its whole answer (Ghidra's `detect_crypto_constants`\n"
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
    "- Choose the functions to decompile by what the question needs; where a tool\n"
    "  is the aggregate form of another, one call of it answers many of the other.\n"
    "- Large binaries may have 1000+ functions. Prioritize entry point, main,\n"
    "  and functions referencing crypto/network/process APIs.\n"
    "- Summarize assembly patterns instead of dumping raw hex."
)

R2_WORKFLOW: str = (
    "=== TOOL USAGE WORKFLOW ===\n"
    "1. Call `open_file` with the path you are given, then `analyze` to run the\n"
    "   analysis pass.\n"
    "2. Call `list_imports` and `list_strings` to see what the binary can reach.\n"
    "3. Call `list_functions` and pick the functions that matter for the question\n"
    "   (those referencing crypto, network or process APIs first);\n"
    "   `decompile_function` those and `xrefs_to` their addresses.\n"
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
    "function_starts": "/function_starts",
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
    # capa reads the file, its code and its structure without running it (with
    # the pefile backend, file-scope features only).
    "capa": {
        **_CAPABILITY_RULES,
        "shows": (
            "the capabilities whose capa rules match features of the file, its code and its "
            "structure"
        ),
        "does_not_show": "whether the matched code runs, or a capability no rule describes",
    },
    "capabilities": _CAPABILITIES,
    "carve_payloads": _file("carve"),
    "decode_string_blobs": _DECODED_STRINGS,
    "document_info": _file("document_info"),
    # The PE and ELF parsers' import rows cover the late-bound imports: the PE
    # delay-load table, and the one import table ELF keeps them in. The Mach-O
    # parser does not declare it: its lazily bound imports are not shown to
    # be in the rows it answers.
    "elf_info": {**_file("format_info"), "reads_delay_imports": True},
    "find_crypto_constants": _file("crypto_constants"),
    "floss": _EMULATED_STRINGS,
    "function_index": {**_file("function_index", "function_table")},
    "hashes": _file("identity"),
    "identify_file": _file("identity"),
    "iocs_from_file": _file("file_iocs"),
    "iocs_from_text": {"kind": "text_iocs", "arguments": {"text": "text"}},
    "macho_info": _file("format_info"),
    "pe_info": {**_file("format_info", "pe_header"), "reads_delay_imports": True},
    "put_sample": {"kind": "sample_delivery"},
    "put_sample_begin": {"kind": "sample_delivery"},
    "put_sample_chunk": {"kind": "sample_delivery"},
    "put_sample_finish": {"kind": "sample_delivery"},
    "resolve_api_hashes": _API_HASHES,
    "sigma_match": _event_rules("events"),
    "sigma_match_sandbox": _event_rules("report"),
    "signing_info": _file("signing"),
    # Runs read as they sit in the file (``string_tools.strings``).
    "strings": {
        **_STRINGS,
        "shows": "printable ASCII and UTF-16LE runs as they sit in the file, with their offsets",
        "does_not_show": (
            "strings that are encoded, encrypted, compressed or built at run time; nor runs "
            "shorter than min_len, or past this page (read next_offset)"
        ),
    },
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

# The threat-intel sidecar's hash lookup answers JSON
# (``services/threatintel-mcp/server.py``): the engine counts under
# ``last_analysis_stats``, the sidecar's own sentence under ``summary``, and the
# service's text about the file (a submitted name, which the sample's author
# chooses) under ``file``, where no count is read. The one text pattern reads
# an answer the sidecar wrote in prose before it answered JSON, and only that
# answer's fixed head and tail, anchored to both ends of the text: a name inside
# such an answer is always followed by the tail, so it is never where a count
# is read.
# Without a key the sidecar answers nothing in the service's place. Its rank
# puts it after VirusTotal's own server, which the triage pack asks first when
# both are enabled.
_THREATINTEL_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "check_domain_reputation": {
        "kind": "indicator_reputation",
        "arguments": {"domain": "domain"},
        "shows": "what VirusTotal reports of the domain: its engine counts and categories",
        "does_not_show": "whether the sample contacts the domain, or what it would send there",
    },
    "check_hash": {
        "kind": "reputation",
        "arguments": {"hash": "file_hash"},
        "display_name": "Threat intelligence",
        "shows": "what VirusTotal reports of the hash: its engine counts and details of the file",
        "does_not_show": (
            "this run's own analysis of the sample; an unknown hash or no detections is no "
            "evidence that the file is clean"
        ),
        "reputation": {
            "stats": "/last_analysis_stats",
            "malicious": "/last_analysis_stats/malicious",
            "suspicious": "/last_analysis_stats/suspicious",
            "summary": "/summary",
            "text_patterns": [
                r"(?s)\AHash [0-9A-Fa-f]+ \(.*\): (?:clean|suspicious|malicious) — "
                r"(?P<malicious>\d+)/(?P<total>\d+) malicious, (?P<suspicious>\d+)/\d+ "
                r"suspicious\.\s*\z",
            ],
            "rank": 20,
        },
    },
    "check_ip_reputation": {
        "kind": "indicator_reputation",
        "arguments": {"ip": "ip_address"},
        "shows": "what VirusTotal and AbuseIPDB report of the address",
        "does_not_show": "whether the sample contacts the address, or what it would send there",
    },
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
        "shows": "what VirusTotal holds for the hash: its engines' detections and file details",
        "does_not_show": (
            "this run's own analysis of the sample; an unknown hash or no detections is no "
            "evidence that the file is clean"
        ),
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

# The identification servers: one analysis program each, in an image of its
# own (``services/die-mcp``, ``services/ilspy-mcp``, ``services/goresym-mcp``),
# shipped switched off. Each tool reads the file its path names, as the
# sidecar's own answer shapes say; none runs the sample. Their kinds are read
# by kind alone: no entry of theirs was stored before declarations were.
_SAMPLE_PATH = {"path": "path"}
_EXECUTABLE_FORMATS = ["pe", "elf", "mach-o"]
_DIE_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "die_scan": {
        "kind": "identification",
        "rows": "/detections/*",
        "values": {
            "name": "/name",
            "type": "/type",
            "version": "/version",
            "file_type": "/file_type",
        },
        "arguments": _SAMPLE_PATH,
        "display_name": "Detect It Easy",
        "shows": (
            "the packers, compilers, linkers, protectors, installers and libraries Detect It "
            "Easy's signatures name in the file, with the format each was found in"
        ),
        "does_not_show": (
            "what the code does, or a packer or compiler no signature describes; a name is a "
            "signature match, not a proof"
        ),
    },
}
# The report sections a decompiled function's writer is shown (Ghidra's
# ``decompile_function``), for a decompiled .NET type or member.
_DECOMPILED_CODE_SECTIONS = list(GHIDRA_TOOLS["decompile_function"]["report_sections"])
_ILSPY_DECOMPILE: dict[str, Any] = {
    "kind": "decompile",
    "arguments": _SAMPLE_PATH,
    "routed_formats": ["pe"],
    "report_sections": _DECOMPILED_CODE_SECTIONS,
    "display_name": "ILSpy",
    "shows": "C# (or IL) that ILSpy decompiled from the assembly's metadata and IL",
    "does_not_show": (
        "what runs at run time: code loaded, decrypted or emitted while the assembly runs, or "
        "native code beside the IL"
    ),
}
_ILSPY_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "dotnet_types": {
        "kind": "type_list",
        "rows": "/types/*",
        "values": {"name": "/name", "type_kind": "/type_kind"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": ["pe"],
        "display_name": "ILSpy",
        "shows": "the classes, interfaces, structs, delegates and enums the assembly defines",
        "does_not_show": "what any of them does, or types built or loaded at run time",
    },
    "dotnet_decompile_type": _ILSPY_DECOMPILE,
    "dotnet_decompile_member": _ILSPY_DECOMPILE,
    "dotnet_decompile_assembly": {
        **_ILSPY_DECOMPILE,
        "kind": "decompile_batch",
        "long_running": True,
        "aggregate_of": ["dotnet_decompile_type", "dotnet_decompile_member"],
    },
    "dotnet_resources": {
        "kind": "resource_listing",
        "rows": "/resources/*",
        "values": {"name": "/name"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": ["pe"],
        "display_name": "ILSpy",
        "shows": "the names of the resources embedded in the assembly",
        "does_not_show": "what a resource holds",
    },
    "dotnet_metadata_table": {
        "kind": "metadata_table",
        "rows": "/rows/*",
        "arguments": _SAMPLE_PATH,
        "routed_formats": ["pe"],
        "display_name": "ILSpy",
        "shows": "every row of one ECMA-335 metadata table as the assembly holds it",
        "does_not_show": "how the rows are used by the code",
    },
}
_GORESYM_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "go_symbols": {
        "kind": "function_list",
        "long_running": True,
        "rows": "/functions/*",
        "places": {"address": "/start"},
        "values": {"name": "/name", "package": "/package"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _EXECUTABLE_FORMATS,
        "display_name": "GoReSym",
        "shows": (
            "the Go version, build id and build info, and each function's name, package and "
            "address range, read from the Go runtime's own tables in the file"
        ),
        "does_not_show": "what a function does, or code that is not Go",
    },
    "go_types": {
        "kind": "type_list",
        "long_running": True,
        "rows": "/types/*",
        "values": {"name": "/Str", "type_kind": "/Kind"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _EXECUTABLE_FORMATS,
        "display_name": "GoReSym",
        "shows": "the Go type structures and interfaces the binary's moduledata lists",
        "does_not_show": "how the types are used, or types of a Go version it misreads",
    },
    "go_strings": {
        "kind": "embedded_strings",
        "long_running": True,
        "holds_strings": True,
        "rows": "/strings/*",
        "values": {"text": "/Str"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _EXECUTABLE_FORMATS,
        "display_name": "GoReSym",
        "shows": "the strings the binary's Go string table holds, each cut where Go cuts it",
        "does_not_show": "strings built, decoded or decrypted at run time",
    },
}

# The rule and document servers, shipped switched off as the identification
# servers are (``services/yarax-mcp``, ``services/oletools-mcp``,
# ``services/webcrack-mcp``). YARA-X matches the operator's own rule files and
# answers in the row shape of ``yara_scan``: its rule matches are signature
# rules, and corroborate as the one YARA layer (``source``), never as a second
# independent one beside ``yara_scan``'s. oletools parses Office and RTF
# documents and runs no macro; webcrack rewrites a script's syntax tree and is
# handed no sandbox to evaluate any of it in.
_YARAX_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "yarax_scan": {
        # Its rows and places are yara_scan's, so a claim citing a match is
        # read as one citing yara_scan's is.
        **_SIGNATURE_RULES,
        "arguments": _SAMPLE_PATH,
        "display_name": "YARA-X",
        "shows": (
            "the operator's own YARA rules (the rule files mounted on the server) that match "
            "the file, with each matching string's offset and the rule's metadata"
        ),
        "does_not_show": (
            "rules that are not in the mounted rule files, or that YARA-X could not compile "
            "(named in rules_not_compiled); a match is the rule author's claim, not a verdict"
        ),
    },
}
_OFFICE_FORMATS = ["ole2", "ooxml"]
_OFFICE_AND_RTF_FORMATS = ["ole2", "ooxml", "rtf"]
_OLETOOLS_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "ole_vba": {
        "kind": "vba_macros",
        "rows": "/indicators/*",
        "values": {"type": "/type", "keyword": "/keyword"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _OFFICE_FORMATS,
        "display_name": "olevba",
        "shows": (
            "the VBA source of each macro module and olevba's keyword analysis of it (auto-run "
            "triggers, suspicious calls, IOCs, encoded strings), Excel 4 macro sheets and VBA "
            "stomping"
        ),
        "does_not_show": (
            "what a macro does when it runs: no macro is run, so code it builds or downloads "
            "at run time is not seen"
        ),
    },
    "ole_macro_risk": {
        "kind": "macro_risk",
        "rows": "/matches/*",
        "values": {"flag": "/flag", "keyword": "/keyword"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _OFFICE_FORMATS,
        "display_name": "MacroRaptor",
        "shows": "whether the macros run on their own and write or execute, by keyword rules",
        "does_not_show": (
            "whether a macro is malicious or what it does: a keyword match on the source, with "
            "no macro run"
        ),
    },
    "ole_indicators": {
        "kind": "document_indicators",
        "rows": "/indicators/*",
        "values": {"indicator": "/id", "value": "/value", "risk": "/risk"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _OFFICE_AND_RTF_FORMATS,
        "display_name": "oleid",
        "shows": (
            "the document's format, encryption, VBA and XLM macros, external relationships, "
            "Flash and object pools, each with oleid's risk rating"
        ),
        "does_not_show": "the content behind an indicator, or anything oleid has no check for",
    },
    "rtf_objects": {
        "kind": "embedded_objects",
        "rows": "/objects/*",
        "places": {"offset": "/start"},
        "values": {
            "class_name": "/class_name",
            "filename": "/filename",
            "payload_sha256": "/payload_sha256",
        },
        "arguments": _SAMPLE_PATH,
        "routed_formats": ["rtf"],
        "display_name": "rtfobj",
        "shows": (
            "the objects embedded in the RTF: each one's OLE class (Package, Equation.3, "
            "OLE2Link and others), the file name and paths a Package names, and its payload's "
            "sha256"
        ),
        "does_not_show": (
            "what an object does when it is opened, or an object the parser cannot find; "
            "nothing is extracted or run"
        ),
    },
    "office_dde": {
        "kind": "dde_links",
        "rows": "/links/*",
        "values": {"instruction": "/text"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _OFFICE_AND_RTF_FORMATS,
        "display_name": "msodde",
        "shows": "the DDE links and field instructions in the document, DDEAUTO commands too",
        "does_not_show": "whether a link would run, or the links of an encrypted document",
    },
}
_WEBCRACK_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "js_deobfuscate": {
        "kind": "deobfuscated_script",
        "long_running": True,
        "rows": "/scripts/*",
        "places": {"offset": "/start"},
        "values": {"language": "/language"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": ["js", "hta", "wsf"],
        "display_name": "webcrack",
        "shows": (
            "the script (or each script block of an HTA or WSF) unminified, unpacked from its "
            "bundle and cleared of self-defending and debugger traps, as readable JavaScript"
        ),
        "does_not_show": (
            "strings an obfuscator's decoder functions compute (decoding them would run the "
            "script, so those calls stay as written); with no sandbox, the control-flow "
            "flattening and dead code of a script guarded by an obfuscator-style string array, "
            "which stay as they are; VBScript, or JScript.Encode scripts"
        ),
    },
}

# The container and Android servers, shipped switched off as the others are
# (``services/unblob-mcp``, ``services/jadx-mcp``). unblob carves and extracts
# what a container or firmware image holds into a directory of its own in its
# container, never beside the sample, and runs nothing it extracts; a written
# file reaches another server only through the job's artefact store, which
# reads it back over ``get_artefact`` (a delivery primitive, never a model's).
# JADX decompiles dex bytecode to Java and loads no class; an APK's manifest,
# permissions and certificates stay ``apk_info``'s.
_UNBLOB_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "container_scan": {
        "kind": "embedded_chunks",
        "rows": "/chunks/*",
        "places": {"offset": "/start_offset"},
        "values": {"handler": "/handler"},
        "arguments": _SAMPLE_PATH,
        "display_name": "unblob",
        "shows": (
            "each chunk of a known format inside the file (archives, compressed streams, file "
            "systems, firmware containers, a payload appended to another file), found by its "
            "own bytes, with its byte range, and the ranges no format claims with their entropy"
        ),
        "does_not_show": (
            "what a chunk holds (nothing is unpacked), or a format unblob has no handler for; "
            "nothing is run"
        ),
    },
    "container_extract": {
        "kind": "extracted_files",
        "long_running": True,
        "rows": "/files/*",
        "values": {"name": "/name", "sha256": "/sha256", "magic": "/magic"},
        "arguments": _SAMPLE_PATH,
        "display_name": "unblob",
        "shows": (
            "every file the container's chunks hold, extracted recursively, each with its place "
            "in the container, size, sha256 and file type; links by what they name, and what "
            "unblob refused (a member whose path or link leaves the extraction, a device file)"
        ),
        "does_not_show": (
            "what an extracted file does: nothing extracted is run or opened beyond its type; "
            "a format unblob has no handler for, an encrypted chunk's contents, or anything "
            "past the sample upload bound the extraction stops at"
        ),
    },
    "get_artefact": {"kind": "artefact_delivery"},
}
_ANDROID_FORMATS = ["apk", "dex"]
_JADX_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "android_classes": {
        "kind": "type_list",
        "long_running": True,
        "rows": "/classes/*",
        "values": {"name": "/name"},
        "arguments": _SAMPLE_PATH,
        "routed_formats": _ANDROID_FORMATS,
        "display_name": "JADX",
        "shows": (
            "the classes the APK's or dex file's bytecode defines, each with its methods and "
            "their signatures, as JADX reads them"
        ),
        "does_not_show": (
            "what any of them does; classes loaded, decrypted or downloaded at run time (no "
            "code is run); the manifest, permissions and certificates, which apk_info reads"
        ),
    },
    "android_decompile_class": {
        "kind": "decompile",
        "arguments": _SAMPLE_PATH,
        "routed_formats": _ANDROID_FORMATS,
        "report_sections": _DECOMPILED_CODE_SECTIONS,
        "display_name": "JADX",
        "shows": "Java source JADX decompiled from one class's dex bytecode, inner classes too",
        "does_not_show": (
            "what runs at run time: code loaded, decrypted or downloaded while the app runs, "
            "or native libraries beside the bytecode; no code is run"
        ),
    },
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
    "anti_analysis_scan": {
        "kind": "anti_analysis_scan",
        "report_sections": ["packing_obfuscation", "evasion_antiforensics"],
    },
    # The pack's scan step was recorded under this name (Ghidra's own tool's)
    # before it was renamed (``pack_steps.LEGACY_STEP_NAMES``): a stored run's
    # entries still read as the kind they were.
    "find_anti_analysis_techniques": {
        "kind": "anti_analysis_scan",
        "report_sections": ["packing_obfuscation", "evasion_antiforensics"],
    },
    "function_matches": {"kind": "function_matches"},
    # Phrases of the directed-text families (``analysis.directed_text``): one
    # row per family and normalised phrase, with where it first stands.
    "find_directed_text": {
        "kind": "directed_text",
        "rows": "/groups/*",
        "places": {"offset": "/first/offset", "place": "/first/place"},
        "values": {"text": "/phrase", "family": "/family"},
        "arguments": {"path": "path"},
    },
    # The pack's own entry for a reputation lookup that did not happen
    # (``triage_pack.REPUTATION_STEP``), which ``run_state`` shows beside a lookup.
    "reputation": {"kind": "reputation_not_asked"},
    "pcap_summary": _PCAP_SUMMARY,
    "sandbox_status": {"kind": "sandbox_status"},
    "sandbox_sections": {"kind": "sandbox_sections"},
    "behaviour_code_links": {"kind": "behaviour_code_links"},
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

# The kinds that reach a service outside the deployment by what they mean,
# each with what it reaches it for. A tool of one of these kinds asks that
# service whatever server it is called through, so the run's disclosure block
# (``analysis.disclosure``) never takes a call of it, or any call through a
# local server that declares one, as staying on the machine.
OUTWARD_KINDS: dict[str, str] = {
    **{kind: "asks a reputation service about the sample" for kind in REPUTATION_KINDS},
    "indicator_report": "asks a service for its report on an indicator",
    "indicator_reputation": "asks a service for an indicator's reputation",
    "submission": "hands a service something to analyse",
    "submission_status": "asks a service how a submission is going",
}

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
        "kinds": [
            "reference",
            "api_catalogue",
            "called_api_catalogue",
            "capabilities",
            "indicator_report",
        ]
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
    "validation._REFERENCE_SECTION_SOURCES": {"kinds": ["api_catalogue", "called_api_catalogue"]},
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
    # The answers whose texts the directed-text pass reads beside the file.
    "triage_pack.directed_text_sources": {"kinds": ["emulated_strings", "decoded_strings"]},
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
    "behaviour_code_links": "_behaviour_code",
    "pcap": "_pcap",
    **{kind: "_reputation" for kind in REPUTATION_KINDS},
}

# ---------------------------------------------------------------------------
# The blocks
# ---------------------------------------------------------------------------

# VirusTotal's agent-token registration (``core.virustotal``): one POST naming
# the agent family and the ``vt-mcp`` release, one ``vtai_`` token back, and
# the agent id and public handle the operator recognises the deployment by in
# VirusTotal's own listing. The note is what the console said beside the
# button before the step was a declaration.
_VIRUSTOTAL_BOOTSTRAP: dict[str, Any] = {
    "url": virustotal.REGISTER_URL,
    "body": {"agent_family": "{family}", "agent_version": virustotal.VT_MCP_VERSION},
    "token_json_path": "/agent_token",
    "token_prefix": "vtai_",
    "family": virustotal.AGENT_FAMILY,
    "facts": {"public_handle": "/public_handle", "agent_id": "/agent_id"},
    "note": (
        "The agent token is free and is issued to this deployment without an account. "
        "VirusTotal enforces its own published quotas on it; a lookup over quota comes "
        "back as a 429 with a retry delay, and the analyst carries on without that answer. "
        "Only the read-only lookups are ticked. The submit tools upload the sample itself "
        "to VirusTotal, where it is shared with their customers, so they stay off until "
        "you tick them in the Tools step."
    ),
}

# The tools of each shipped server that only read the staged file or the
# platform's own reference tables: an identical call answers the same, so
# each is declared ``read_only`` (``ToolFacts.read_only``). A tool that
# writes, carves, unpacks, transforms, delivers, analyses or runs rules over
# the sample, polls a status, or asks an outside service whose answer moves
# (a reputation, a submission) is not, nor one in doubt. The triage pack's
# own steps keep their facts as they were.
ANALYSIS_READ_ONLY: frozenset[str] = frozenset(
    {
        "apk_info",
        "archive_list",
        "capabilities",
        "document_info",
        "elf_info",
        "find_crypto_constants",
        "hashes",
        "identify_file",
        "iocs_from_file",
        "iocs_from_text",
        "macho_info",
        "pe_info",
        "resolve_api_hashes",
        "signing_info",
        "strings",
    }
)
KNOWLEDGE_READ_ONLY: frozenset[str] = frozenset(
    {
        "api_capability",
        "attck_lookup",
        "attck_validate",
        "capabilities",
        "family_lookup",
        "lolbin_lookup",
        "resolve_technique",
    }
)
NETWORK_READ_ONLY: frozenset[str] = frozenset({"capabilities"})

# The routed formats each of the analysis server's format-specific parsers
# serves (``ToolFacts.routed_formats``), as the router names them
# (``extractors.sample_identity.routed_formats``). A parser the sample's format
# never calls on is not something a run loses: a missing Mach-O library on a PE
# sample is no degradation of that run. The table the pipeline read before also
# named ``macho``, ``doc``, ``docx``, ``xls``, ``xlsx`` and ``rtf``, which the
# router never gives a sample (it says ``mach-o``, ``ole2``, ``ooxml``), so no
# sample read them. The triage pack's own steps keep their facts as they were:
# they run only for their own format.
ANALYSIS_ROUTED_FORMATS: dict[str, tuple[str, ...]] = {
    "pe_info": ("pe",),
    "elf_info": ("elf",),
    "macho_info": ("mach-o",),
    "apk_info": ("apk", "dex"),
    "document_info": ("ole2", "ooxml", "pdf"),
}


def _marked_read_only(
    tools: dict[str, dict[str, Any]], names: frozenset[str]
) -> dict[str, dict[str, Any]]:
    missing = sorted(names - set(tools))
    if missing:
        raise KeyError(f"read-only marks for undeclared tools: {missing}")
    return {
        name: {**facts, "read_only": True} if name in names else facts
        for name, facts in tools.items()
    }


def _serving_formats(
    tools: dict[str, dict[str, Any]], formats: Mapping[str, tuple[str, ...]]
) -> dict[str, dict[str, Any]]:
    missing = sorted(set(formats) - set(tools))
    if missing:
        raise KeyError(f"routed formats for undeclared tools: {missing}")
    return {
        name: {**facts, "routed_formats": list(formats[name])} if name in formats else facts
        for name, facts in tools.items()
    }


# What each built-in tool's call does beyond answering (``ToolFacts.effects``):
# whether it runs the sample's code, reaches a network service beyond its own
# server, and what of the sample it sends to a third party. A tool that sends
# the sample's bytes out says so by ``discloses_sample``, which the effects read
# as bytes sent (``analysis.tool_effects.sends_sample_bytes``). Every built-in
# tool declares all three, held so by
# ``tests/unit/analysis/test_each_tool_s_effects_are_declared_and_reported.py``;
# only a tool that runs whatever script or command it is given declares none,
# and says why (``why_undeclared``).
_NO_EFFECT: dict[str, Any] = {"executes": "no", "network": False, "third_party": "no"}
_EMULATES: dict[str, Any] = {**_NO_EFFECT, "executes": "emulation"}
# Reaches the network only to fetch or refresh the reference data it keeps:
# the ATT&CK bundle once it is stale (``memory.attck_loader``) and the
# embedding model's weights on first use (``memory.embeddings``).
_REFRESHES: dict[str, Any] = {**_NO_EFFECT, "network": "on_refresh"}
# Reads the configured case-memory store, wherever the disclosure places it.
_READS_THE_CASE_STORE: dict[str, Any] = {**_NO_EFFECT, "network": "case_store"}
# What the sandbox service the CAPE sidecar fronts (its API, at the address the
# operator configured) is asked: its status, a search by the sample's hash, a
# task's status, report, IOCs or extracted configuration. Whether that service
# is the operator's own is not shipped: the report derives it from where the
# disclosure places the call (``analysis.tool_effects``), and says it cannot be
# told where the disclosure cannot place it.
_ASKS_THE_OPERATOR_SANDBOX: dict[str, Any] = {**_NO_EFFECT, "network": "operator_sandbox"}
# Hands the sample to that sandbox service, which runs it; the bytes going
# out are the tool's ``discloses_sample``.
_SUBMITS_TO_THE_OPERATOR_SANDBOX: dict[str, Any] = {
    "executes": "sandbox",
    "network": "operator_sandbox",
}
# A tool that runs whatever script or command it is given: what it does is
# what it is told, so none of its effects can be declared.
# radare2's analysis: at level 2 and above r2mcp runs ``aaa`` (the provider's
# own account of the levels, ``providers.static.r2``), whose type matching
# (``aaft``) emulates each function with ESIL; the levels below do not.
_ANALYSES: dict[str, Any] = {
    **_NO_EFFECT,
    "executes": "emulation",
    "when": "at analysis level 2 and above, where radare2's aaa type matching (aaft) emulates "
    "each function with ESIL",
}
_RUNS_ANYTHING: dict[str, Any] = {
    "why_undeclared": "it runs whatever script or command it is given, so what it does is "
    "whatever that does"
}
# Asks an outside service about an indicator (a domain, an address, a URL).
_ASKS_ABOUT_AN_INDICATOR: dict[str, Any] = {"executes": "no", "network": True, "third_party": "no"}
# Asks an outside service about the sample by its hash, or by the id of its
# submission there.
_ASKS_ABOUT_THE_SAMPLE: dict[str, Any] = {**_ASKS_ABOUT_AN_INDICATOR, "third_party": "hash"}
# Hands the sample to a third party's sandboxes (VirusTotal's), which may run
# it; the bytes going out are the tool's ``discloses_sample``.
_SUBMITS_THE_SAMPLE: dict[str, Any] = {"executes": "sandbox", "network": True}


def _with_effects(
    tools: Mapping[str, Mapping[str, Any]],
    effects: Mapping[str, Mapping[str, Any]],
    *,
    default: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """``tools`` with each one's ``effects``: its own in ``effects``, else ``default``.

    Every name in ``effects`` is one of ``tools``.
    """
    missing = sorted(set(effects) - set(tools))
    if missing:
        raise KeyError(f"effects for undeclared tools: {missing}")
    out: dict[str, dict[str, Any]] = {}
    for name, facts in tools.items():
        held = effects.get(name, default)
        out[name] = {**facts, "effects": dict(held)} if held is not None else dict(facts)
    return out


def _one_program_block(role: str, tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """A one-program sidecar's declaration: its role, its mount and its tools, read-only."""
    return {
        "roles": [role],
        "sample_mount": "/data/samples",
        "reads_staged_sample": True,
        "tool_facts": _with_effects(
            _marked_read_only(tools, frozenset(tools)), {}, default=_NO_EFFECT
        ),
    }


# Each built-in server's declaration. ``roles``: ``reputation`` on the two
# servers that declare a reputation lookup. ``reads_staged_sample`` on the
# three servers whose path-taking tools read the sample the platform staged
# (``agents.tool_pinning.reads_staged_sample``). ``required_env_allow`` as
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
        "tool_facts": _with_effects(
            _serving_formats(
                _marked_read_only(_ANALYSIS_TOOLS, ANALYSIS_READ_ONLY), ANALYSIS_ROUTED_FORMATS
            ),
            {"floss": _EMULATES},
            default=_NO_EFFECT,
        ),
    },
    "knowledge": {
        "roles": ["reference"],
        "required_env_allow": [
            "MALJAN_INDEX_RETRY_SECONDS",
            "MALJAN_ATTCK_REFRESH_DAYS",
            "MALJAN_SAMPLE_SHA256",
        ],
        "reads_staged_sample": True,
        "tool_facts": _with_effects(
            _marked_read_only(_KNOWLEDGE_TOOLS, KNOWLEDGE_READ_ONLY),
            dict.fromkeys(
                (
                    "attck_lookup",
                    "attck_validate",
                    "family_lookup",
                    "resolve_technique",
                    "similar_cases",
                ),
                _REFRESHES,
            ),
            default=_NO_EFFECT,
        ),
    },
    "network": {
        "roles": ["capture"],
        "required_env_allow": ["MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"],
        "reads_staged_sample": True,
        "tool_facts": _with_effects(
            _marked_read_only(_NETWORK_TOOLS, NETWORK_READ_ONLY), {}, default=_NO_EFFECT
        ),
    },
    "threatintel": {
        "roles": ["reputation"],
        "tool_facts": _with_effects(
            _THREATINTEL_TOOLS,
            {
                "check_domain_reputation": _ASKS_ABOUT_AN_INDICATOR,
                "check_hash": _ASKS_ABOUT_THE_SAMPLE,
                "check_ip_reputation": _ASKS_ABOUT_AN_INDICATOR,
            },
            default=_NO_EFFECT,
        ),
    },
    "virustotal": {
        "roles": ["reputation"],
        "reference_urls": ["https://www.virustotal.com/gui/file/{sha256}"],
        "tool_facts": _with_effects(
            _VIRUSTOTAL_TOOLS,
            {
                "get_analysis": _ASKS_ABOUT_THE_SAMPLE,
                "get_domain_report": _ASKS_ABOUT_AN_INDICATOR,
                "get_file_report": _ASKS_ABOUT_THE_SAMPLE,
                "get_ip_report": _ASKS_ABOUT_AN_INDICATOR,
                "get_submission": _ASKS_ABOUT_THE_SAMPLE,
                "get_url_report": _ASKS_ABOUT_AN_INDICATOR,
                "submit_file": _SUBMITS_THE_SAMPLE,
                "submit_local_file": _SUBMITS_THE_SAMPLE,
            },
        ),
        "credential_bootstrap": _VIRUSTOTAL_BOOTSTRAP,
    },
    # The identification servers, the rule and document servers and the
    # container and Android servers: each reads the sample the worker mirrors
    # under the samples directory its container mounts read-only at
    # /data/samples (``docker/docker-compose.yml``), and none runs it.
    "die": _one_program_block("identifier", _DIE_TOOLS),
    "ilspy": _one_program_block("decompiler", _ILSPY_TOOLS),
    "goresym": _one_program_block("symbol_recovery", _GORESYM_TOOLS),
    "yarax": _one_program_block("rule_matcher", _YARAX_TOOLS),
    "oletools": _one_program_block("document_reader", _OLETOOLS_TOOLS),
    "webcrack": _one_program_block("deobfuscator", _WEBCRACK_TOOLS),
    "unblob": _one_program_block("extractor", _UNBLOB_TOOLS),
    "jadx": _one_program_block("decompiler", _JADX_TOOLS),
}

# The static providers' own blocks (``static.ghidra``, ``static.r2``) and the
# CAPE MCP sidecar's (``sandbox.cape2.mcp``). Ghidra's mount is the container
# path the shipped compose file mounts the samples directory at, which its
# provider's ``mirror_spec`` reads; its ``sample_open`` is
# ``config.GHIDRA_SAMPLE_OPEN``, set where it has always been set; its work
# directory is the shared default (``providers.base.DEFAULT_WORK_DIR``) and
# radare2's is ``r2-work``, which may not be hidden; its non-secret variable, which
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
        "tool_facts": _with_effects(
            GHIDRA_TOOLS,
            {
                "emulate_function": _EMULATES,
                "emulate_hash_batch": _EMULATES,
                "run_ghidra_script": _RUNS_ANYTHING,
                "run_script_inline": _RUNS_ANYTHING,
            },
            default=_NO_EFFECT,
        ),
    },
    "r2": {
        "work_dir": "r2-work",
        "roles": ["decompiler", "disassembler"],
        "prompt_fragment": R2_WORKFLOW,
        "error_patterns": list(R2_ERROR_PATTERNS),
        "auto_name_prefixes": ["fcn.", "loc.", "sub.", "func."],
        "tool_facts": _with_effects(
            R2_TOOLS,
            {"analyze": _ANALYSES, "run_command": _RUNS_ANYTHING},
            default=_NO_EFFECT,
        ),
    },
    # The workflow's ``submit_file`` sends the sample to the sandbox: declared
    # so the run's disclosure block names the upload. It names no kind on
    # purpose. The server answers a failure in one line of prose ("Error: CAPE
    # API unreachable"), and such an answer is filed as a failure only for a
    # tool that declares no kind (``schemas.evidence.build_entry``); a kind
    # would file every failed submission as an answer. A declaration with no
    # kind gives no reading, so it reads the name no other way than the
    # VirusTotal server's ``submit_file``, which the legacy reading by name
    # takes first. Each tool of its workflow declares its effects, and no kind,
    # so every other reading of them is as it was.
    "cape2_mcp": {
        "roles": ["sandbox"],
        "prompt_fragment": CAPE_WORKFLOW,
        "tool_facts": _with_effects(
            {
                "get_cuckoo_status": {},
                "get_task_config": {},
                "get_task_iocs": {},
                "get_task_report": {},
                "get_task_status": {},
                "search_task": {},
                "submit_file": {"discloses_sample": True},
            },
            {"submit_file": _SUBMITS_TO_THE_OPERATOR_SANDBOX},
            default=_ASKS_THE_OPERATOR_SANDBOX,
        ),
    },
}

# The platform's own in-process sources, declared like any server.
_IN_PROCESS_BLOCKS: dict[str, dict[str, Any]] = {
    # The pack's FLOSS step emulates the sample's code in the worker; its
    # function matches read the configured case store, which may be at an
    # address.
    "pack": {
        "label": "Triage pack",
        "platform_owned": True,
        "tool_facts": _with_effects(
            _PACK_TOOLS,
            {"floss": _EMULATES, "function_matches": _READS_THE_CASE_STORE},
            default=_NO_EFFECT,
        ),
    },
    "sandbox": {
        "label": "Sandbox report",
        "roles": ["sandbox"],
        "tool_facts": _with_effects(_SANDBOX_TOOLS, {}, default=_NO_EFFECT),
    },
    "provider:capa_yara": {
        "label": "capa and YARA",
        "roles": ["rule_scanner"],
        "tool_facts": _with_effects(
            {"capa": _CAPABILITY_RULES, "yara_scan": _SIGNATURE_RULES}, {}, default=_NO_EFFECT
        ),
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


# Where each shipped provider-owned block sits in the settings, by the source
# its declarations are read under; a provider registered at runtime adds its
# own (``core.tool_declarations.register_provider_block``).
_PROVIDER_BLOCK_PATHS: dict[str, str] = {
    "provider:ghidra": "static.ghidra",
    "provider:r2": "static.r2",
    "provider:cape2": "sandbox.cape2.mcp",
}


def provider_block_paths() -> dict[str, str]:
    """Each shipped provider-owned block's dotted settings path, by its source text."""
    return dict(_PROVIDER_BLOCK_PATHS)


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
