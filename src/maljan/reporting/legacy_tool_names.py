"""LEGACY READERS: the tool-name tables the report read entries by before tools declared their kind.

This is the one module in ``maljan.reporting`` allowed to name a tool. It is
read only for an entry that recorded no source (``LedgerEntry.source`` is
``None``: every entry written before sources were recorded, and every report
stored before then), so a stored run re-renders byte for byte as it did. An
entry that recorded its source is read by its declaration
(``maljan.reporting.tool_kinds``) and never reaches this module.

The tables are kept as they were written, keyed by the consumer names of
``core.builtin_declarations.CONSUMER_KINDS``; that module's test holds each
one equal, tool by tool over every built-in tool, to the kinds a declared
entry is read by. Nothing new is added here: a new reading is a declaration.

Only ``reporting.tool_kinds`` imports this module, and only on its branches
for an entry with no recorded source (a guard holds both).

Some readers read a source-less entry through :func:`builtin_facts`, the
shipped declaration of the built-in tool of that name, rather than a table.
That equals the old reading only while each kind such a reader selects names
exactly the tools its old table named; ``tests/unit/reporting/
test_an_entry_without_a_source_is_read_as_before.py`` holds every such set
equal, so a built-in declaration that changed a kind fails there first.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import cache
from typing import Any

from maljan.core.tool_declarations import ToolFacts

# ---------------------------------------------------------------------------
# The built-in declarations by bare tool name
# ---------------------------------------------------------------------------


@cache
def _builtin_by_name() -> Mapping[str, ToolFacts]:
    """Every built-in tool's shipped declaration, by its bare name.

    No two built-in sources declare one name with two kinds or two readers
    (``tests/unit/reporting/test_an_entry_without_a_source_is_read_as_before.py``),
    so the name alone gives the declaration a stored entry's tool shipped with.
    """
    from maljan.core import builtin_declarations as shipped

    blocks: list[Mapping[str, Any]] = [
        *(shipped.server_declaration(key) for key in shipped.builtin_server_names()),
        *(shipped.provider_declaration(key) for key in ("ghidra", "r2", "cape2_mcp")),
    ]
    found: dict[str, ToolFacts] = {}
    for cfg in shipped.in_process_declarations().values():
        for name, facts in cfg.tool_facts.items():
            found.setdefault(name, facts)
    for block in blocks:
        for name, raw in (block.get("tool_facts") or {}).items():
            found.setdefault(name, ToolFacts.model_validate(raw))
    return found


def builtin_facts(tool: str) -> ToolFacts | None:
    """The shipped declaration of the built-in tool named ``tool``, for an entry with no source."""
    return _builtin_by_name().get(str(tool or ""))


# ---------------------------------------------------------------------------
# The tables, as they were written
# ---------------------------------------------------------------------------

# ``ledger_report``: reverse-engineering tools that name a function, and the
# function listings.
FUNCTION_TOOLS = frozenset(
    {
        "decompile_function",
        "decompile",
        "disassemble_function",
        "get_function",
        "analyze_function",
        "pdf",
        "pdc",
    }
)
FUNCTION_LIST_TOOLS = frozenset({"list_functions", "get_functions", "afl", "list_methods"})

# ``ledger_report._BUILDERS``: the section builder each tool was drawn with,
# by the builder's name.
BUILDERS: dict[str, str] = {
    "identify_file": "_identity",
    "hashes": "_identity",
    "signing_info": "_signing",
    "pe_info": "_binary_info",
    "elf_info": "_binary_info",
    "macho_info": "_binary_info",
    "apk_info": "_binary_info",
    "strings": "_strings",
    "iocs_from_text": "_iocs",
    "iocs_from_file": "_iocs",
    "yara_scan": "_yara",
    "sigma_match": "_sigma",
    "sigma_match_sandbox": "_sigma",
    "capa": "_capa",
    "sandbox_processes": "_sandbox_processes",
    "sandbox_network": "_sandbox_network",
    "sandbox_signatures": "_sandbox_signatures",
    "sandbox_dropped_files": "_sandbox_dropped",
    "sandbox_registry_ops": "_sandbox_registry",
    "sandbox_api_calls": "_sandbox_apis",
    "sandbox_mutexes": "_sandbox_mutexes",
    "sandbox_services_and_tasks": "_sandbox_services",
    "sandbox_report_section": "_sandbox_section",
    "sandbox_items": "_sandbox_items",
    "sandbox_status": "_sandbox_status",
    "pcap_summary": "_pcap",
    "get_file_report": "_reputation",
    "check_hash": "_reputation",
}

# ``evidence_bundles``: the sandbox tools by prefix, the two network answers,
# the entries that state what the report is rather than what it saw, and the
# sample's own strings.
SANDBOX_TOOL_PREFIXES = ("sandbox_", "pcap_summary")
NETWORK_SANDBOX_TOOLS = frozenset({"sandbox_network", "pcap_summary"})
NOT_OBSERVATIONS = frozenset({"sandbox_status", "sandbox_sections"})
SANDBOX_REPORT_SECTION_TOOL = "sandbox_report_section"
SANDBOX_ITEMS_TOOL = "sandbox_items"
STRING_TOOLS = frozenset({"strings", "floss", "iocs_from_file", "list_strings"})

# ``evidence_bundles._SECTION_TOOL_HINTS``: which captured outputs each
# composer section was shown, by a part of the tool's name.
SECTION_TOOL_HINTS: dict[str, tuple[str, ...]] = {
    "packing_obfuscation": ("list_segments", "find_anti_analysis", "detect_malware_behaviors"),
    "cli_flags": ("decompile_function", "analyze_function_complete", "list_strings"),
    "encryption_scheme": (
        "detect_crypto_constants",
        "emulate_function",
        "emulate_hash_batch",
        "analyze_dataflow",
    ),
    "discovery": ("list_imports", "analyze_api_call_chains", "decompile_function"),
    "persistence_detail": ("list_strings", "decompile_function", "analyze_api_call_chains"),
    "evasion_antiforensics": (
        "find_anti_analysis_techniques",
        "detect_malware_behaviors",
        "decompile_function",
    ),
    "ransom_note": ("list_strings", "extract_iocs_with_context"),
    "communications": ("list_strings", "extract_iocs_with_context", "analyze_api_call_chains"),
    "command_and_control": (
        "list_strings",
        "extract_iocs_with_context",
        "analyze_api_call_chains",
        "decompile_function",
    ),
    "string_resolution": (
        "emulate_hash_batch",
        "emulate_function",
        "analyze_api_call_chains",
        "decompile_function",
        "list_strings",
    ),
    "configuration": (
        "emulate_function",
        "emulate_hash_batch",
        "analyze_dataflow",
        "detect_crypto_constants",
        "extract_iocs_with_context",
        "decompile_function",
    ),
    "commands": ("decompile_function", "analyze_function_complete", "analyze_api_call_chains"),
    "payloads": ("list_segments", "decompile_function", "extract_iocs_with_context"),
    "host_identifiers": ("list_strings", "extract_iocs_with_context"),
}

# ``figures``: the decompiler whose listings were drawn.
CODE_LISTING_TOOL = "decompile_function"

# ``renderers.markdown``: the analysis tools in the order the report listed
# them, the sandbox tools by prefix with the status entry apart, and the
# reputation lookups.
ANALYSIS_TOOLS = ("capa", "yara_scan", "lolbin_lookup", "api_capability", "strings")
MARKDOWN_SANDBOX_TOOLS = ("sandbox_", "pcap_summary")
SANDBOX_STATUS_TOOL = "sandbox_status"
REPUTATION_TOOLS = ("get_file_report", "check_hash", "file_report", "hash_lookup")
# The technique-hit source a stored report's hits of each kind were recorded under.
HIT_SOURCES: dict[str, tuple[str, ...]] = {"capability_rules": ("capa",)}

# ``renderers.stix_renderer``: the recovering tools, the static decoder, the
# string sweep, and the two network records.
EMULATING_TOOL = "floss"
# The emulator a stored record's partial reason names.
EMULATOR_WORD = "FLOSS"
DECODER_TOOL = "decode_string_blobs"
STRING_SWEEP_TOOLS = ("strings", "iocs_from_file", "iocs_from_text")
PLAIN_STRING_TOOLS = ("strings",)
FILE_IOC_TOOLS = ("iocs_from_file",)
NETWORK_RECORD_TOOLS = frozenset({"sandbox_network", "pcap_summary"})
CAPTURE_TOOL = "pcap_summary"
# ``ledger_projection``: the tools whose rule rows became technique hits.
TECHNIQUE_HIT_TOOLS = ("capa",)
# A recovery recorded with no kind (a record stored before kinds were) is read
# by the tool it names: the tool each recovering kind's stored records name,
# and the word a partial reason names each kind's entries by.
STORED_TOOL_BY_KIND: dict[str, str] = {
    "emulated_strings": EMULATING_TOOL,
    "decoded_strings": DECODER_TOOL,
    "strings": PLAIN_STRING_TOOLS[0],
}
STORED_WORD_BY_KIND: dict[str, str] = {
    "emulated_strings": EMULATOR_WORD,
    "decoded_strings": DECODER_TOOL,
    "strings": PLAIN_STRING_TOOLS[0],
}
# Each ordered table, by the consumer it orders.
ORDERED: dict[str, tuple[str, ...]] = {"markdown._ANALYSIS_TOOLS": ANALYSIS_TOOLS}


def _names(values: Any) -> Callable[[str], bool]:
    held = frozenset(values)
    return lambda name: name in held


def _prefixes(values: tuple[str, ...]) -> Callable[[str], bool]:
    return lambda name: name.startswith(values)


# Each reporting consumer's table as a membership test on a bare tool name,
# keyed as ``CONSUMER_KINDS`` keys it.
TABLES: dict[str, Callable[[str], bool]] = {
    "ledger_report._FUNCTION_TOOLS": _names(FUNCTION_TOOLS),
    "ledger_report._FUNCTION_LIST_TOOLS": _names(FUNCTION_LIST_TOOLS),
    "evidence_bundles._STRING_TOOLS": _names(STRING_TOOLS),
    "evidence_bundles._NETWORK_SANDBOX_TOOLS": _names(NETWORK_SANDBOX_TOOLS),
    "evidence_bundles.SANDBOX_TOOL_PREFIXES": _prefixes(SANDBOX_TOOL_PREFIXES),
    "markdown._ANALYSIS_TOOLS": _names(ANALYSIS_TOOLS),
    "markdown._REPUTATION_TOOLS": _names(REPUTATION_TOOLS),
    "markdown._SANDBOX_TOOLS": _prefixes(MARKDOWN_SANDBOX_TOOLS),
    "stix_renderer.recovering": _names(
        (EMULATING_TOOL, DECODER_TOOL, *PLAIN_STRING_TOOLS, *FILE_IOC_TOOLS)
    ),
    "stix_renderer.DECODER_TOOL": _names((DECODER_TOOL,)),
    "stix_renderer._STRING_SWEEP_TOOLS": _names(STRING_SWEEP_TOOLS),
    "figures.code_listing": _names((CODE_LISTING_TOOL,)),
    "ledger_projection.technique_hits": _names(TECHNIQUE_HIT_TOOLS),
}


def in_table(consumer: str, tool: str) -> bool:
    """Whether a consumer's table held ``tool``; a consumer with no table here reads the kinds."""
    test = TABLES.get(consumer)
    if test is not None:
        return test(str(tool or ""))
    from maljan.core.builtin_declarations import CONSUMER_KINDS

    spec = CONSUMER_KINDS[consumer]
    facts = builtin_facts(tool)
    return (facts is not None and facts.kind in spec["kinds"]) or tool in spec.get(
        "legacy_names", ()
    )


def section_hinted(section: str, tool: str) -> bool:
    """Whether a captured output with no source was shown to a composer section, by its name."""
    return any(hint in tool for hint in SECTION_TOOL_HINTS.get(section, ()))


def looked_at_the_file(tool: str) -> bool:
    """Whether the report counted a tool with no source as one that looked at the file itself."""
    return (
        "sandbox" not in tool
        and not tool.startswith(MARKDOWN_SANDBOX_TOOLS)
        and tool not in REPUTATION_TOOLS
    )


def rank(consumer: str, tool: str) -> int:
    """Where the report listed a tool with no source, in a consumer's fixed order."""
    order = ORDERED[consumer]
    return order.index(tool) if tool in order else len(order)


def stored_recovery_kind(tool: str) -> str:
    """The kind a stored recovery naming ``tool`` (with no kind recorded) is read as."""
    return next((kind for kind, name in STORED_TOOL_BY_KIND.items() if name == tool), "")
