"""The name tables the reading half read tools by, kept as the record of the legacy reading.

LEGACY MODULE: the one place in the reading half (``pipeline/``,
``analysis/``, ``agents/``) where tools are named. Nothing here decides how an
entry is read: an entry is read by its tool's declared kind
(``maljan.core.declared_reading``), and an entry with no recorded source by the
facts the platform ships for its name, which are exactly these tables
(``builtin_declarations.CONSUMER_KINDS``). The tables stay, verbatim as the
consumers held them, so the tests can hold the declared reading to them tool by
tool, and for the readers whose own group has not moved yet (the reputation
tables, which the one reputation path replaces).

The guard ``tests/unit/test_the_reading_half_names_no_tool.py`` exempts this
module and no other.
"""

from __future__ import annotations

# ``analysis.evidence_roots``: the tools whose fact is about the file as a whole.
WHOLE_FILE_TOOLS = frozenset({"hashes", "identify_file", "signing_info"})
# A third party's assessment of the whole file (a reputation lookup by hash);
# the triage pack reads it too, until the one reputation path replaces it.
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

# ``pipeline.evidence_summary``: the one tool whose matches carry a rule's own
# strings, and the one whose rows are the API catalogue's associations.
SIGNATURE_RULE_TOOLS = ("yara_scan",)
API_CATALOGUE_TOOLS = ("api_capability",)
