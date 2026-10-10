"""The declarations the built-in servers, providers and in-process tools ship with.

Data, in the schema of ``maljan.core.tool_declarations``: one block per
built-in source, holding the facts the code's name tables encode today, so
every current behaviour is the default and each consumer can move from its
table to the declaration with the same output. The comment over each block
names the tables a value comes from.

Only the declaration fields are here. A built-in server's connection settings
stay in ``config._builtin_servers``; its declaration is merged from this
module under whatever an operator stored (``tool_declarations.fill_declaration``).

The two static providers' workflow prompts and radare2's error sentences live
here as the text of their declarations, and the adapters read them from here,
so there is one copy of each.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any

from maljan.tools.errors import BAD_ARGUMENT, TOOL_FAILED

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig
    from maljan.core.tool_declarations import SourceRef

# ---------------------------------------------------------------------------
# Model-facing text the declarations carry
# ---------------------------------------------------------------------------

# The Ghidra fragment in two parts. The guidance is about claims — what a
# claim cites, which techniques to look for, and the verification discipline
# with its confidence caps — and goes with every call the analyst makes on a
# Ghidra run, tools or none: a revision or a validation retry that lost it
# could raise an unverified claim past the caps the first turn was held to.
# The workflow is the tool calls, and goes only where Ghidra's tools do.
GHIDRA_GUIDANCE: str = (
    "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
    "string offset (.data+0xNN), API import, or hex pattern. "
    "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
    "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
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
    "9. For the 3–5 most suspicious functions: `decompile_function(address=<addr>)`\n"
    "   then `get_xrefs_to(address=<addr>)` to confirm call-sites.\n\n"
    "=== ADVANCED TOOLS (reach for these when the triage signals call for them) ===\n"
    "- API names resolved by hash (a hashing loop, sparse imports): call\n"
    "  `emulate_hash_batch` to brute-force the obfuscated API names.\n"
    "- Suspected encryption / ransomware: the pack's crypto constants line names the\n"
    "  published constants and where they stand; `find_crypto_constants` on the\n"
    "  analysis server gives its whole answer (Ghidra's `detect_crypto_constants`\n"
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

# The whole fragment, with Ghidra attached: the tools, the guidance, the workflow.
GHIDRA_PROMPT_FRAGMENT: str = (
    "Analyze binary files (e.g. PE, ELF) utilizing Ghidra through your available tools. "
    "You can decompile functions, find cross-references, extract strings, and more. "
    + GHIDRA_GUIDANCE
    + "\n\n"
    + GHIDRA_WORKFLOW
)

R2_PROMPT_FRAGMENT: str = (
    "Analyze binary files (e.g. PE, ELF) utilizing radare2 through your available tools. "
    "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
    "string offset (.data+0xNN), API import, or hex pattern. "
    "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
    "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
    "=== TOOL USAGE WORKFLOW ===\n"
    "1. Call `open_file` with the path you are given, then `analyze` to run the\n"
    "   analysis pass.\n"
    "2. Call `list_imports` and `list_strings` to see what the binary can reach.\n"
    "3. Call `list_functions` and pick the 3-5 that reference crypto, network or\n"
    "   process APIs; `decompile_function` those and `xrefs_to` their addresses.\n"
    "4. Summarise assembly patterns instead of dumping raw hex, and prefer one\n"
    "   summarising call over many narrow ones.\n"
)

# What r2mcp is told after an answer that says no file is open.
R2_OPEN_FILE_FIRST = "call open_file with the path you are given, then call this tool again"

# The replies r2mcp gives in place of an answer, as it writes them. r2mcp sends
# these as an ordinary text result rather than as an MCP error, so without this
# list the ledger filed "Invalid regex used in filter parameter, try a simpler
# expression" as a successful ``list_strings`` whose output was that sentence.
# Each is held against the whole reply, never a line inside one.
R2_ERROR_PATTERNS: tuple[dict[str, Any], ...] = (
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
    },
    {
        "match": r"No file is currently open\..*",
        "code": TOOL_FAILED,
        "remediation": R2_OPEN_FILE_FIRST,
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

# Where an asserting tool's answer names technique ids: under these keys at any
# depth, as ``pipeline.evidence_summary._technique_ids`` reads every source.
TECHNIQUES_ANYWHERE: tuple[dict[str, str], ...] = (
    {"path": "/**/technique_id", "format": "attck"},
    {"path": "/**/attck", "format": "attck"},
    {"path": "/**/technique_ids", "format": "attck"},
    {"path": "/**/tags", "format": "sigma_tag"},
)

_PATH = {"path": "path", "carved": "carved_path"}

_CAPA: dict[str, Any] = {
    "kind": "rule_match",
    "asserts_techniques": True,
    "source": "capa",
    "long_running": True,
    "rows": "/capabilities/*",
    "places": {"addresses": "/addresses"},
    "values": {"rule": "/rule", "namespace": "/namespace"},
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": {"path": "path"},
    "reader": "capa",
}
_YARA: dict[str, Any] = {
    "kind": "rule_match",
    "asserts_techniques": True,
    "source": "yara",
    "rows": "/matches/*",
    "places": {"offset": "/strings/*/offset", "instance_offset": "/strings/*/instances/*/offset"},
    "values": {"rule": "/rule"},
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": _PATH,
    "reader": "yara",
    "words": ["yara", "rule", "rules"],
}


def _sigma(argument: str) -> dict[str, Any]:
    return {
        "kind": "rule_match",
        "asserts_techniques": True,
        "source": "sigma",
        "rows": "/matches/*",
        "values": {"command_line": "/matched_fields/CommandLine"},
        "techniques": list(TECHNIQUES_ANYWHERE),
        "arguments": {argument: argument},
        "reader": "sigma",
        "words": ["sigma", "rule", "rules"],
    }


_STRINGS: dict[str, Any] = {
    "kind": "strings",
    "rows": "/strings/*",
    "places": {"offset": "/offset"},
    "values": {"text": "/text"},
    "arguments": _PATH,
}
_FLOSS: dict[str, Any] = {
    "kind": "decoded_strings",
    "long_running": True,
    "rows": "/strings/*",
    "places": {"call_site": "/called_at_rva", "function": "/function_rva"},
    "values": {"text": "/string", "scheme": "/kind"},
    "arguments": _PATH,
    "reader": "floss",
    "words": ["decoded", "emulation", "floss"],
}
_BLOBS: dict[str, Any] = {
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
    "reader": "resolve_api_hashes",
}


def _file(kind: str, reader: str = "") -> dict[str, Any]:
    facts: dict[str, Any] = {"kind": kind, "arguments": _PATH}
    if reader:
        facts["reader"] = reader
    return facts


_REFERENCE = {"kind": "reference"}
_CAPABILITIES = {"kind": "capabilities"}
_LOLBIN: dict[str, Any] = {
    "kind": "command_match",
    "asserts_techniques": True,
    "source": "lolbin",
    "techniques": list(TECHNIQUES_ANYWHERE),
    "arguments": {"command_lines": "command_lines"},
    "reader": "lolbin",
}
_PCAP_WORDS = ["capture", "packet", "packets", "pcap"]
_PCAP_SUMMARY: dict[str, Any] = {
    "kind": "pcap",
    "arguments": {"path": "pcap_path"},
    "reader": "flows",
    "words": _PCAP_WORDS,
}

# The analysis sidecar's tools. Answer shapes from ``analysis.evidence_roots``
# ``_read_entry``; capa and FLOSS long-running as the sidecar's own manifest
# (``services/analysis-mcp/server.py`` TOOL_NEEDS) declares them.
_ANALYSIS_TOOLS: dict[str, dict[str, Any]] = {
    "apk_info": _file("binary_info", "binary_info"),
    "archive_list": _file("archive_listing"),
    "capa": _CAPA,
    "capabilities": _CAPABILITIES,
    "carve_payloads": _file("carve"),
    "decode_string_blobs": _BLOBS,
    "document_info": _file("binary_info"),
    "elf_info": _file("binary_info", "binary_info"),
    "find_crypto_constants": _file("crypto_constants"),
    "floss": _FLOSS,
    "function_index": {**_file("function_index", "function_index")},
    "hashes": _file("identity"),
    "identify_file": _file("identity"),
    "iocs_from_file": _file("iocs"),
    "iocs_from_text": {"kind": "iocs", "arguments": {"text": "text"}},
    "macho_info": _file("binary_info", "binary_info"),
    "pe_info": _file("binary_info", "pe_info"),
    "put_sample": {"kind": "sample_delivery"},
    "put_sample_begin": {"kind": "sample_delivery"},
    "put_sample_chunk": {"kind": "sample_delivery"},
    "put_sample_finish": {"kind": "sample_delivery"},
    "resolve_api_hashes": _API_HASHES,
    "sigma_match": _sigma("events"),
    "sigma_match_sandbox": _sigma("report"),
    "signing_info": _file("signing"),
    "strings": _STRINGS,
    "transform_bytes": _file("transform", "transform_bytes"),
    "unpack_upx": _file("unpack", "unpack_upx"),
    "yara_scan": _YARA,
}

_KNOWLEDGE_TOOLS: dict[str, dict[str, Any]] = {
    "api_capability": _REFERENCE,
    "attck_lookup": _REFERENCE,
    "attck_validate": _REFERENCE,
    "capabilities": _CAPABILITIES,
    "family_lookup": _REFERENCE,
    "lolbin_lookup": _LOLBIN,
    "resolve_technique": _REFERENCE,
    "similar_cases": _REFERENCE,
}

_NETWORK_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "extract_dns": {"kind": "dns", "arguments": {"path": "pcap_path"}, "reader": "extract_dns"},
    "extract_http": {"kind": "http", "arguments": {"path": "pcap_path"}},
    "pcap_summary": _PCAP_SUMMARY,
    "read_pcap_summary": {**_PCAP_SUMMARY, "kind": "packet_overview"},
}

# The threat-intel sidecar answers in prose: "55/70 detections"
# (``pipeline.triage_pack._DETECTIONS_RE``).
_THREATINTEL_TOOLS: dict[str, dict[str, Any]] = {
    "capabilities": _CAPABILITIES,
    "check_domain_reputation": {"kind": "indicator_reputation", "arguments": {"domain": "domain"}},
    "check_hash": {
        "kind": "reputation",
        "arguments": {"hash": "file_hash"},
        "reputation": {
            "text_pattern": r"(?i)\b(?P<malicious>\d+)\s*/\s*(?P<total>\d+)\s+detections?\b"
        },
    },
    "check_ip_reputation": {"kind": "indicator_reputation", "arguments": {"ip": "ip_address"}},
    "get_threatintel_status": {"kind": "status"},
}

# VirusTotal's own server: the lookups and submit tools of ``core.virustotal``;
# the file report's shape as ``pipeline.triage_pack._reputation_facts``,
# ``_stats_malicious`` and ``_detection_labels`` and
# ``reporting.ledger_report._reputation`` read it.
_VT_REPUTATION: dict[str, Any] = {
    "service": "VirusTotal",
    "stats": "/**/last_analysis_stats",
    "malicious": "/**/last_analysis_stats/malicious",
    "labels": [
        "/**/popular_threat_classification/suggested_threat_label",
        "/**/popular_threat_classification/popular_threat_name/*/value",
        "/**/popular_threat_classification/popular_threat_category/*/value",
    ],
    "detections": "/**/detections",
    "engines": "/**/coverage/engines",
}
_VIRUSTOTAL_TOOLS: dict[str, dict[str, Any]] = {
    "get_analysis": {"kind": "submission_status"},
    "get_domain_report": {"kind": "indicator_reputation"},
    "get_file_report": {
        "kind": "reputation",
        "arguments": {"hash": "hash"},
        "reputation": _VT_REPUTATION,
    },
    "get_ip_report": {"kind": "indicator_reputation"},
    "get_submission": {"kind": "submission_status"},
    "get_url_report": {"kind": "indicator_reputation"},
    "submit_file": {"kind": "submission"},
    "submit_local_file": {"kind": "submission"},
}

# The report sections each reversing tool's answers are shown to, as
# ``reporting.evidence_bundles._SECTION_TOOL_HINTS`` matches them by name.
_SECTIONS: dict[str, list[str]] = {
    "list_imports": ["discovery"],
    "list_strings": [
        "cli_flags",
        "persistence_detail",
        "ransom_note",
        "communications",
        "command_and_control",
        "string_resolution",
        "host_identifiers",
    ],
    "decompile_function": [
        "cli_flags",
        "discovery",
        "persistence_detail",
        "evasion_antiforensics",
        "command_and_control",
        "string_resolution",
        "configuration",
        "commands",
        "payloads",
    ],
    "list_segments": ["packing_obfuscation", "payloads"],
    "find_anti_analysis_techniques": ["packing_obfuscation", "evasion_antiforensics"],
    "detect_malware_behaviors": ["packing_obfuscation", "evasion_antiforensics"],
    "analyze_function_complete": ["cli_flags", "commands"],
    "detect_crypto_constants": ["encryption_scheme", "configuration"],
    "emulate_function": ["encryption_scheme", "string_resolution", "configuration"],
    "emulate_hash_batch": ["encryption_scheme", "string_resolution", "configuration"],
    "analyze_dataflow": ["encryption_scheme", "configuration"],
    "analyze_api_call_chains": [
        "discovery",
        "persistence_detail",
        "communications",
        "command_and_control",
        "string_resolution",
        "commands",
    ],
    "extract_iocs_with_context": [
        "ransom_note",
        "communications",
        "command_and_control",
        "configuration",
        "payloads",
        "host_identifiers",
    ],
}


def _reversing(tools: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``tools`` with each one's report sections added where it has any."""
    return {
        name: ({**facts, "report_sections": _SECTIONS[name]} if name in _SECTIONS else facts)
        for name, facts in tools.items()
    }


_ADDRESS = {"address": "address"}

# Ghidra's tools the code names: the open/select/analyse tools of its
# ``sample_open`` (the open and the analysis long-running, as
# ``providers.sample_open.long_running_tools`` holds them),
# the program and listing tools of ``analysis.evidence_roots``, the function
# tools of ``reporting.ledger_report`` and ``reporting.figures``, the load tool
# of ``agents.static_analyst``, the passes of ``analysis.ghidra_passes`` and
# ``analysis.function_hash_attribution``, and the workflow's tools.
_GHIDRA_TOOLS: dict[str, dict[str, Any]] = _reversing(
    {
        "load_program": {
            "kind": "open_sample",
            "long_running": True,
            "arguments": {"path": "file"},
        },
        "switch_program": {"kind": "select_sample", "arguments": {"program": "program"}},
        "run_analysis": {
            "kind": "analyse_sample",
            "long_running": True,
            "arguments": {"program": "program"},
        },
        "get_current_program_info": {"kind": "program_info"},
        "list_imports": {"kind": "import_listing"},
        "list_exports": {"kind": "export_listing"},
        "list_strings": {"kind": "strings"},
        "list_functions": {"kind": "function_list"},
        "list_segments": {"kind": "segments"},
        "decompile_function": {"kind": "decompile", "arguments": _ADDRESS},
        "disassemble_function": {"kind": "disassembly", "arguments": _ADDRESS},
        "analyze_function_complete": {"kind": "function_analysis", "arguments": _ADDRESS},
        "get_xrefs_to": {"kind": "xrefs", "arguments": _ADDRESS},
        "get_function_xrefs": {"kind": "xrefs", "arguments": _ADDRESS},
        "get_function_callers": {"kind": "callers", "arguments": _ADDRESS},
        "get_function_callees": {"kind": "callees", "arguments": _ADDRESS},
        "detect_malware_behaviors": {"kind": "behaviour_scan"},
        "analyze_api_call_chains": {"kind": "call_chains"},
        "find_anti_analysis_techniques": {"kind": "anti_analysis_scan"},
        "extract_iocs_with_context": {
            "kind": "iocs",
            "rows": "/iocs/*",
            "places": {"address": "/address"},
            "values": {"value": "/value"},
        },
        "detect_crypto_constants": {"kind": "crypto_constants"},
        "emulate_function": {"kind": "emulation", "arguments": _ADDRESS},
        "emulate_hash_batch": {"kind": "emulation"},
        "analyze_dataflow": {"kind": "dataflow", "arguments": _ADDRESS},
        "find_code_gaps": {"kind": "code_gaps"},
        "get_function_hash": {"kind": "function_hash", "arguments": _ADDRESS},
        "get_bulk_function_hashes": {"kind": "function_hashes"},
        "get_full_call_graph": {"kind": "call_graph"},
    }
)

# radare2's tools the code names: the open tool and the function tools of
# ``providers.static.r2``, the workflow's tools, the listings of
# ``analysis.evidence_roots`` and the r2 commands of
# ``reporting.ledger_report._FUNCTION_TOOLS`` / ``_FUNCTION_LIST_TOOLS``.
_R2_TOOLS: dict[str, dict[str, Any]] = _reversing(
    {
        "open_file": {"kind": "open_sample", "arguments": {"path": "file_path"}},
        "analyze": {"kind": "analyse_sample"},
        "show_info": {"kind": "program_info"},
        "list_imports": {"kind": "import_listing"},
        "list_exports": {"kind": "export_listing"},
        "list_strings": {"kind": "strings"},
        "list_functions": {"kind": "function_list"},
        "decompile_function": {"kind": "decompile", "arguments": _ADDRESS},
        "disassemble_function": {"kind": "disassembly", "arguments": _ADDRESS},
        "disassemble": {"kind": "disassembly", "arguments": _ADDRESS},
        "xrefs_to": {"kind": "xrefs", "arguments": _ADDRESS},
        "run_command": {"kind": "command"},
        "pdf": {"kind": "disassembly"},
        "pdc": {"kind": "decompile"},
        "afl": {"kind": "function_list"},
    }
)

# The platform's sandbox report tools (``providers.sandbox_tools``). Shapes as
# ``analysis.evidence_roots`` and ``reporting.ledger_report._BUILDERS`` read
# them; the signatures assert techniques (``evidence_summary.ASSERTING_SOURCES``).
_SANDBOX_TOOLS: dict[str, dict[str, Any]] = {
    "sandbox_report_section": {"kind": "sandbox_report", "reader": "sandbox_section"},
    "sandbox_processes": {
        "kind": "sandbox_processes",
        "rows": "/processes/*",
        "places": {"pid": "/pid"},
        "values": {"command_line": "/command_line", "name": "/name"},
    },
    "sandbox_network": {"kind": "network_flows", "reader": "flows"},
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
    "sandbox_items": {"kind": "sandbox_items", "reader": "items"},
}

# The triage pack's steps (``pipeline.triage_pack``), each recorded under the
# pack's own name. The in-process implementations answer as the sidecar's
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
            "yara_scan",
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
    "api_capability": _REFERENCE,
    "lolbin_lookup": _LOLBIN,
    "find_anti_analysis_techniques": {
        "kind": "anti_analysis_scan",
        "report_sections": _SECTIONS["find_anti_analysis_techniques"],
    },
    "function_matches": {"kind": "function_matches"},
    # The pack's own entry for a reputation lookup that did not happen
    # (``triage_pack._REPUTATION_TOOLS``, ``run_state``).
    "reputation": {"kind": "reputation"},
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
# The blocks
# ---------------------------------------------------------------------------

# Each built-in server's declaration. ``roles``: ``reputation`` on the two
# servers of ``config.REPUTATION_SERVER_KEYS``. ``reads_staged_sample`` on the
# servers of ``agents.tool_pinning.PINNED_SERVERS``. ``required_env_allow`` as
# ``config.REQUIRED_ENV_ALLOW``.
_SERVER_BLOCKS: dict[str, dict[str, Any]] = {
    "analysis": {
        "roles": ["rule_scanner", "strings", "decoder"],
        "required_env_allow": [
            "MALJAN_STAGING_DIR",
            "MALJAN_STAGING_TTL_HOURS",
            "MALJAN_SAMPLE_ROOTS",
        ],
        "reads_staged_sample": True,
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
    "virustotal": {"roles": ["reputation"], "tool_facts": _VIRUSTOTAL_TOOLS},
}

# The static providers' own blocks (``static.ghidra``, ``static.r2``) and the
# CAPE MCP sidecar's (``sandbox.cape2.mcp``). Ghidra's mount is the container
# path its provider mirrors to (``providers.static.ghidra`` ``mirror_spec``);
# its ``sample_open`` is ``config.GHIDRA_SAMPLE_OPEN``, set where it has always
# been set. radare2 reads the worker's own filesystem.
_PROVIDER_BLOCKS: dict[str, dict[str, Any]] = {
    "ghidra": {
        "sample_mount": "/data/samples",
        "roles": ["decompiler", "disassembler"],
        "prompt_fragment": GHIDRA_PROMPT_FRAGMENT,
        "tool_facts": _GHIDRA_TOOLS,
    },
    "r2": {
        "roles": ["decompiler", "disassembler"],
        "prompt_fragment": R2_PROMPT_FRAGMENT,
        "error_patterns": list(R2_ERROR_PATTERNS),
        "tool_facts": _R2_TOOLS,
    },
    "cape2_mcp": {"roles": ["sandbox"]},
}

# The platform's own in-process sources, declared like any server.
_IN_PROCESS_BLOCKS: dict[str, dict[str, Any]] = {
    "pack": {"label": "Triage pack", "tool_facts": _PACK_TOOLS},
    "sandbox": {"label": "Sandbox report", "roles": ["sandbox"], "tool_facts": _SANDBOX_TOOLS},
    "provider:capa_yara": {
        "label": "capa and YARA",
        "roles": ["rule_scanner"],
        "tool_facts": {"capa": _CAPA, "yara_scan": _YARA},
    },
}


def builtin_server_names() -> tuple[str, ...]:
    """The keys of ``mcp.servers`` that ship a declaration."""
    return tuple(_SERVER_BLOCKS)


def server_declaration(key: str) -> dict[str, Any]:
    """The declaration fields a built-in server ships with; ``{}`` for any other key."""
    return _block(_SERVER_BLOCKS.get(key, {}))


def provider_declaration(provider: str) -> dict[str, Any]:
    """The declaration fields a provider-owned block ships: ghidra, r2, cape2_mcp."""
    return _block(_PROVIDER_BLOCKS.get(provider, {}))


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
def in_process_declarations() -> dict[SourceRef, MCPServerConfig]:
    """The platform's in-process sources, each as a block of declaration fields."""
    from maljan.core.config import MCPServerConfig
    from maljan.core.tool_declarations import SourceRef

    return {
        SourceRef.parse(key): MCPServerConfig.model_validate(_block(block))
        for key, block in _IN_PROCESS_BLOCKS.items()
    }
