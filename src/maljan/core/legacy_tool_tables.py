"""The name tables the reading half read tools by, kept as the record of the legacy reading.

LEGACY MODULE: the one place in the reading half (``pipeline/``,
``analysis/``, ``agents/``) where tools are named. Nothing here decides how an
entry is read: an entry is read by its tool's declared kind
(``maljan.core.declared_reading``), and an entry with no recorded source by the
facts the platform ships for its name, which are exactly these tables
(``builtin_declarations.CONSUMER_KINDS``). The tables stay, verbatim as the
consumers held them, so the tests can hold the declared reading to them tool by
tool.

The guard ``tests/unit/test_the_reading_half_names_no_tool.py`` exempts this
module and no other.
"""

from __future__ import annotations

# ``analysis.evidence_roots``: the tools whose fact is about the file as a whole.
WHOLE_FILE_TOOLS = frozenset({"hashes", "identify_file", "signing_info"})
# A third party's assessment of the whole file (a reputation lookup by hash);
# the triage pack and the run-state block read the same tables, as the record
# of the reputation reading before the declared kind replaced them.
FILE_ASSESSMENT_TOOLS = frozenset({"reputation", "get_file_report", "check_hash"})
# The tools that answer what something is rather than read the sample.
REFERENCE_TOOLS = frozenset(
    {
        "api_capability",
        "attck_validate",
        "attck_lookup",
        "resolve_technique",
        "family_lookup",
        "similar_cases",
        "get_ip_report",
        "get_domain_report",
        "get_url_report",
        "capabilities",
        "knowledge__capabilities",
    }
)
IMPORT_LISTINGS = frozenset({"list_imports", "get_imports"})
EXPORT_LISTINGS = frozenset({"list_exports", "get_exports"})
# The tools that state which program a disassembler's server holds, and that open one.
PROGRAM_TOOLS = frozenset(
    {"get_current_program_info", "get_program_info", "program_info", "get_current_program"}
)
OPEN_TOOLS = frozenset({"open_file", "open_program", "load_program"})

# ``pipeline.evidence_summary``: the tools whose technique id is a statement
# about this sample, and the name a corroboration row gives each.
ASSERTING_SOURCES: dict[str, str] = {
    "capa": "capa",
    "sigma_match": "sigma",
    "sigma_match_sandbox": "sigma",
    "yara_scan": "yara",
    "lolbin_lookup": "lolbin",
    "sandbox_signatures": "sandbox",
}

# ``pipeline.validation``: report sections by the tool that opened them.
REFERENCE_SECTION_SOURCES = frozenset({"tool:api_capability"})
SAMPLE_VALUE_SECTION_SOURCES = frozenset({"tool:strings", "tool:iocs_from_file", "tool:floss"})
RULE_MATCH_SECTION_SOURCES = frozenset({"tool:capa", "tool:yara_scan", "tool:yara"})
# Words a statement uses for an entry that its tool's own name does not carry,
# by a part of the tool's name: the legacy reading of an entry with no source.
TOOL_WORDS: dict[str, tuple[str, ...]] = {
    "pcap": ("capture", "packet", "packets", "pcap"),
    "floss": ("decoded", "emulation", "floss"),
    "sigma": ("sigma", "rule", "rules"),
    "yara": ("yara", "rule", "rules"),
}

# ``agents.function_map``: the answers it ties artefacts to functions from.
FUNCTION_MAP_TOOLS = ("resolve_api_hashes", "decode_string_blobs", "floss", "function_index")

# ``pipeline.triage_pack``: the two rule tools whose pack entries mean the
# evidence-only static provider need not run.
RULE_TOOLS = ("capa", "yara_scan")

# ``agents.network_analyst``: the packet tools its capture turns named, which
# it now reads by declared kind (``_PCAP_STEPS``).
PCAP_TOOLS = ("read_pcap_summary", "extract_dns", "extract_http")

# ``pipeline.evidence_summary``: the one tool whose matches carry a rule's own
# strings, and the one whose rows are the API catalogue's associations.
SIGNATURE_RULE_TOOLS = ("yara_scan",)
API_CATALOGUE_TOOLS = ("api_capability",)


# ``providers.server_guard``: the settings blocks whose ``timeout_seconds`` the
# deployment-wide per-call floor was derived from before each server declared
# its own budget (``MCPServerConfig.call_timeout_seconds``). Read only for a
# server that declares none, so a deployment's stored settings keep every
# server's budget exactly as it was.
LEGACY_CALL_FLOOR_BLOCKS = ("capa", "yara")


def legacy_call_floor(cfg: object) -> float:
    """The per-call floor every server got before servers declared their own budget.

    The longest ``static.<block>.timeout_seconds`` of the blocks above, as
    ``deployment_call_budget`` derived it; ``0`` with none set.
    """
    static = getattr(cfg, "static", None)
    budgets = [
        float(getattr(getattr(static, name, None), "timeout_seconds", 0) or 0)
        for name in LEGACY_CALL_FLOOR_BLOCKS
    ]
    return max([b for b in budgets if b > 0], default=0.0)


# ``core.config.StaticConfig``: how the whole static fragment opened when the
# provider blocks' ``prompt_fragment`` held it (lead, citation, discipline and
# workflow) and the providers ignored the stored leaf. A value stored then,
# edited or not, had no effect on any prompt; one that opens this way is read
# as not set, so the block shows its shipped workflow as dev showed its
# shipped fragment, instead of being placed after the lead a second time.
LEGACY_WHOLE_FRAGMENT_OPENINGS: dict[str, str] = {
    "ghidra": "Analyze binary files (e.g. PE, ELF) utilizing Ghidra through your available tools.",
    "r2": "Analyze binary files (e.g. PE, ELF) utilizing radare2 through your available tools.",
}


def legacy_whole_fragment(block: str, text: object) -> bool:
    """Whether a stored ``static.<block>.prompt_fragment`` is the whole fragment an earlier
    release stored there, which no prompt read."""
    opening = LEGACY_WHOLE_FRAGMENT_OPENINGS.get(block)
    return bool(opening) and str(text or "").lstrip().startswith(opening)  # type: ignore[arg-type]


# ``schemas.sandbox_report``: the report format whose ``orig`` mark a disputed
# lineage row stored before rows recorded their marker's name was read by. A
# report read now names its marker by the format it was read as.
STORED_LINEAGE_MARKER_FORMAT = "triage"
