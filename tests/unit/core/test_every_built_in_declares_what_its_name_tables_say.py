"""Every built-in tool is declared, and its declaration says what the code's tables say.

The declarations of ``maljan.core.builtin_declarations`` are the facts the name
tables hold today, so each consumer can move from its table to the declaration
with the same output. Each consumer table is held, tool by tool over every
built-in source, equal to the set of kinds ``CONSUMER_KINDS`` names for it; a
table changed without its declaration, or a built-in tool added without a
kind, fails here.
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from maljan.core import virustotal
from maljan.core.builtin_declarations import BUILDER_OF_KIND, CONSUMER_KINDS, READERS
from maljan.core.config import REQUIRED_ENV_ALLOW, Settings
from maljan.core.tool_declarations import PACK, SourceRef, ToolDeclarations, select

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"
TOOLS = ROOT / "tests" / "fixtures" / "tools"
LEDGER = ROOT / "tests" / "fixtures" / "ledger"
BUILT_IN_SERVERS = ("analysis", "knowledge", "network", "threatintel", "virustotal")


@pytest.fixture(scope="module")
def declared() -> ToolDeclarations:
    return ToolDeclarations.from_settings(Settings())


def _tools(declared: ToolDeclarations, source: str) -> dict:
    held = declared.source(source)
    assert held is not None, source
    return dict(held.tools)


def _built_in_tools(declared: ToolDeclarations) -> list[tuple[str, str, object]]:
    """Every (source, tool, facts) the platform ships, built-in sources only."""
    sources = [f"mcp:{key}" for key in BUILT_IN_SERVERS]
    sources += ["provider:ghidra", "provider:r2", "pack", "sandbox", "provider:capa_yara"]
    return [(s, name, facts) for s in sources for name, facts in _tools(declared, s).items()]


def _ghidra_golden() -> list[str]:
    advertised = json.loads((TOOLS / "reverser_ghidra_tool_definitions.json").read_text())
    others: set[str] = set()
    for server in ("knowledge", "virustotal"):
        others |= set(json.loads((GOLDEN / f"{server}.json").read_text())["tools"])
    return [t["name"] for t in advertised if t["name"] not in others]


def _r2_golden() -> list[str]:
    advertised = json.loads((TOOLS / "r2mcp_tool_definitions.json").read_text())
    # ``run_command`` is offered by an r2mcp started with -r (providers.static.r2).
    return [t["name"] for t in advertised] + ["run_command"]


# ---------------------------------------------------------------------------
# Every built-in tool has a kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("server", BUILT_IN_SERVERS)
def test_every_tool_a_built_in_server_advertises_has_a_kind(
    declared: ToolDeclarations, server: str
) -> None:
    advertised = json.loads((GOLDEN / f"{server}.json").read_text(encoding="utf-8"))["tools"]
    tools = _tools(declared, f"mcp:{server}")
    missing = [name for name in advertised if name not in tools]
    assert not missing, f"{server} tools with no declaration: {missing}"


@pytest.mark.parametrize(
    ("source", "golden"), [("provider:ghidra", _ghidra_golden), ("provider:r2", _r2_golden)]
)
def test_every_tool_ghidra_and_radare2_advertise_has_a_kind(
    declared: ToolDeclarations, source: str, golden: Callable[[], list[str]]
) -> None:
    names = golden()
    assert len(names) > 30
    tools = _tools(declared, source)
    assert sorted(tools) == sorted(names)


def test_every_virustotal_tool_the_code_names_is_declared(declared: ToolDeclarations) -> None:
    tools = _tools(declared, "mcp:virustotal")
    assert set(virustotal.LOOKUP_TOOLS) | set(virustotal.SUBMIT_TOOLS) == set(tools)
    assert {n for n, f in tools.items() if f.discloses_sample} == set(virustotal.SUBMIT_TOOLS)


def test_every_sandbox_report_tool_is_declared(declared: ToolDeclarations) -> None:
    from maljan.providers import sandbox_tools

    names = {
        name
        for name, member in inspect.getmembers(sandbox_tools, inspect.isfunction)
        if name.startswith("sandbox_")
        and name != "sandbox_tools"
        and member.__module__ == sandbox_tools.__name__
    }
    assert names == set(_tools(declared, "sandbox"))


def test_every_step_the_triage_pack_records_is_declared(declared: ToolDeclarations) -> None:
    from maljan.analysis import sandbox_sections
    from maljan.analysis.anti_analysis import SCAN_TOOL as ANTI_ANALYSIS_TOOL
    from maljan.core.pack_steps import default_steps
    from maljan.pipeline import sandbox_status
    from maljan.tools import artefact_index, crypto_constants, upx

    steps = {step.called for step in default_steps()}
    steps |= {
        "identify_file",
        "hashes",
        "signing_info",
        "strings",
        "iocs_from_file",
        "yara_scan",
        "capa",
        "sigma_match_sandbox",
        "api_capability",
        "lolbin_lookup",
        "pcap_summary",
        "reputation",
        "function_matches",
        "floss",
        "resolve_api_hashes",
        "decode_string_blobs",
        "sandbox_processes",
        "sandbox_network",
        "sandbox_signatures",
        "sandbox_dropped_files",
        "sandbox_channels",
        sandbox_status.STATUS_TOOL,
        sandbox_sections.SECTIONS_TOOL,
        crypto_constants.TOOL,
        ANTI_ANALYSIS_TOOL,
        artefact_index.TOOL,
        upx.TOOL,
    }
    missing = steps - set(_tools(declared, "pack"))
    assert not missing, f"pack steps with no declaration: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Each consumer table is a set of kinds, tool by tool
# ---------------------------------------------------------------------------


def _strip_tool(names: object) -> set[str]:
    return {str(n).removeprefix("tool:") for n in names}  # type: ignore[attr-defined]


def _tables() -> dict[str, Callable[[str], bool]]:
    """Each consumer table as a membership test on a bare tool name, as the code reads it."""
    from maljan.core import legacy_tool_tables as legacy
    from maljan.reporting import legacy_tool_names

    def names(values: object) -> Callable[[str], bool]:
        held = _strip_tool(values)
        return lambda name: name in held

    return {
        "evidence_roots._WHOLE_FILE_TOOLS": names(legacy.WHOLE_FILE_TOOLS),
        "evidence_roots.FILE_ASSESSMENT_TOOLS": names(legacy.FILE_ASSESSMENT_TOOLS),
        "evidence_roots._REFERENCE_TOOLS": names(legacy.REFERENCE_TOOLS),
        "evidence_roots._IMPORT_LISTINGS": names(legacy.IMPORT_LISTINGS),
        "evidence_roots._EXPORT_LISTINGS": names(legacy.EXPORT_LISTINGS),
        "evidence_roots._PROGRAM_TOOLS": names(legacy.PROGRAM_TOOLS),
        "evidence_roots._OPEN_TOOLS": names(legacy.OPEN_TOOLS),
        "validation._REFERENCE_SECTION_SOURCES": names(legacy.REFERENCE_SECTION_SOURCES),
        "validation._SAMPLE_VALUE_SECTION_SOURCES": names(legacy.SAMPLE_VALUE_SECTION_SOURCES),
        "validation._RULE_MATCH_SECTION_SOURCES": names(legacy.RULE_MATCH_SECTION_SOURCES),
        "triage_pack._REPUTATION_TOOLS": names(legacy.FILE_ASSESSMENT_TOOLS),
        "triage_pack.RULE_TOOLS": names(legacy.RULE_TOOLS),
        "triage_pack.directed_text_sources": names(("floss", "decode_string_blobs")),
        "run_state.reputation": names(legacy.FILE_ASSESSMENT_TOOLS),
        "network_analyst._PCAP_TOOLS": names(legacy.PCAP_TOOLS),
        "function_map": names(legacy.FUNCTION_MAP_TOOLS),
        "evidence_summary.yara_rule_strings": names(legacy.SIGNATURE_RULE_TOOLS),
        "evidence_summary.catalogue_associations": names(legacy.API_CATALOGUE_TOOLS),
        # The reporting consumers read an entry with no recorded source by
        # the tables they always read, kept in one marked module.
        **legacy_tool_names.TABLES,
    }


def _read_inline_tables() -> dict[str, tuple[str, ...]]:
    """The tables the code writes inline, read from the code's own source.

    Not copied: a change to any of these lines changes what this reads, and
    the consumer test then holds the declaration to the new table. The
    reporting ones are read from the legacy module that keeps them.
    """
    from maljan.reporting import legacy_tool_names

    return {
        "figures.code_listing": (legacy_tool_names.CODE_LISTING_TOOL,),
        "ledger_projection.technique_hits": legacy_tool_names.TECHNIQUE_HIT_TOOLS,
        "stix_renderer.recovering": (
            legacy_tool_names.EMULATING_TOOL,
            legacy_tool_names.DECODER_TOOL,
            *legacy_tool_names.PLAIN_STRING_TOOLS,
            *legacy_tool_names.FILE_IOC_TOOLS,
        ),
    }


def test_the_inline_tables_are_read_as_the_code_writes_them_today() -> None:
    assert _read_inline_tables() == {
        "figures.code_listing": ("decompile_function",),
        "ledger_projection.technique_hits": ("capa",),
        "stix_renderer.recovering": ("floss", "decode_string_blobs", "strings", "iocs_from_file"),
    }


def _kinds(consumer: str) -> set[str]:
    spec = CONSUMER_KINDS[consumer]
    if "same_as" in spec:
        spec = CONSUMER_KINDS[spec["same_as"]]
    return set(spec["kinds"])


def test_every_consumer_table_has_its_kinds_and_every_kinds_entry_a_table() -> None:
    assert set(_tables()) == set(CONSUMER_KINDS)


@pytest.mark.parametrize("consumer", sorted(CONSUMER_KINDS))
def test_each_consumer_table_is_exactly_its_kinds_over_every_built_in_tool(
    declared: ToolDeclarations, consumer: str
) -> None:
    in_table = _tables()[consumer]
    kinds = _kinds(consumer)
    assert any(in_table(name) for _s, name, _f in _built_in_tools(declared)), consumer
    differ = [
        (source, name, facts.kind)  # type: ignore[attr-defined]
        for source, name, facts in _built_in_tools(declared)
        if in_table(name) != (facts.kind in kinds)  # type: ignore[attr-defined]
    ]
    assert not differ, differ


@pytest.mark.parametrize("consumer", sorted(CONSUMER_KINDS))
def test_a_tables_legacy_names_are_no_built_in_tools(
    declared: ToolDeclarations, consumer: str
) -> None:
    built_in = {name for _s, name, _f in _built_in_tools(declared)}
    legacy = set(CONSUMER_KINDS[consumer].get("legacy_names", ()))
    assert not legacy & built_in
    in_table = _tables()[consumer]
    assert all(in_table(name) for name in legacy)


def test_the_stored_run_tools_land_where_the_tables_put_them(declared: ToolDeclarations) -> None:
    show_info = declared.declaration_for(("provider:r2", "show_info"))
    assert show_info is not None and show_info.kind not in _kinds("evidence_roots._PROGRAM_TOOLS")
    for source in ("provider:ghidra", "provider:r2"):
        listing = declared.declaration_for((source, "list_strings"))
        assert listing is not None
        assert listing.kind in _kinds("evidence_bundles._STRING_TOOLS")
        assert listing.kind not in _kinds("validation._SAMPLE_VALUE_SECTION_SOURCES")
        assert listing.kind not in BUILDER_OF_KIND
    iocs = declared.declaration_for(("provider:ghidra", "extract_iocs_with_context"))
    assert iocs is not None
    assert iocs.kind not in _kinds("evidence_bundles._STRING_TOOLS")
    assert iocs.kind not in BUILDER_OF_KIND


# The built-in tools shipped after the name tables were kept as they were
# (``reporting.legacy_tool_names``): no entry of one was stored without a
# source, so none has a name reading, and its declared kind alone draws it.
SHIPPED_AFTER_THE_NAME_TABLES = {"behaviour_code_links": "_behaviour_code"}


def test_the_section_builders_are_drawn_by_kind(declared: ToolDeclarations) -> None:
    from maljan.reporting import legacy_tool_names

    assert not set(SHIPPED_AFTER_THE_NAME_TABLES) & set(legacy_tool_names.BUILDERS)
    differ = []
    for source, name, facts in _built_in_tools(declared):
        expected = legacy_tool_names.BUILDERS.get(name) or SHIPPED_AFTER_THE_NAME_TABLES.get(name)
        by_kind = BUILDER_OF_KIND.get(facts.kind)  # type: ignore[attr-defined]
        if expected != by_kind:
            differ.append((source, name, expected, by_kind))
    assert not differ, differ


# ``analysis/evidence_roots.py:1088`` ``_read_entry``: the branches that read
# an answer shape the declared paths do not express, by the tool names they
# are keyed on, and the shape each is named by.
EVIDENCE_ROOT_READERS = {
    "pe_info": "pe_header",
    "floss": "emulated_strings_with_call_sites",
    "function_index": "function_table",
    "transform_bytes": "byte_transform",
    "unpack_upx": "unpacked_image",
    "sandbox_network": "flow_table",
    "pcap_summary": "flow_table",
    "read_pcap_summary": "packet_lines",
    "extract_dns": "dns_query_lines",
    "sandbox_items": "report_items",
}


def test_the_readers_are_the_evidence_roots_shapes(declared: ToolDeclarations) -> None:
    for source, name, facts in _built_in_tools(declared):
        assert facts.reader == EVIDENCE_ROOT_READERS.get(name, ""), (source, name)  # type: ignore[attr-defined]


def test_no_reader_is_named_after_a_tool_or_a_server(declared: ToolDeclarations) -> None:
    names = {name for _s, name, _f in _built_in_tools(declared)}
    names |= set(BUILT_IN_SERVERS) | {"ghidra", "r2", "radare2", "capa", "yara", "floss", "sigma"}
    names |= {"pack", "sandbox", "capa_yara", "cape2", "virustotal", "threatintel"}
    readers = {facts.reader for _s, _n, facts in _built_in_tools(declared)} - {""}  # type: ignore[attr-defined]
    assert readers <= set(READERS)
    assert not set(READERS) & names


# ---------------------------------------------------------------------------
# Server facts
# ---------------------------------------------------------------------------


def test_the_asserting_sources_are_the_declared_asserting_tools(declared: ToolDeclarations) -> None:
    from maljan.core.legacy_tool_tables import ASSERTING_SOURCES

    for source, name, facts in _built_in_tools(declared):
        if name in ASSERTING_SOURCES:
            assert facts.asserts_techniques, (source, name)  # type: ignore[attr-defined]
            assert facts.source == ASSERTING_SOURCES[name], (source, name)  # type: ignore[attr-defined]
        else:
            assert not facts.asserts_techniques, (source, name)  # type: ignore[attr-defined]


def test_the_reputation_servers_are_the_servers_with_the_reputation_role(
    declared: ToolDeclarations,
) -> None:
    from maljan.core.reputation import lookup_servers

    keys = {ref.key for ref in declared.servers_with_role("reputation") if ref.kind == "mcp"}
    assert keys == lookup_servers(declared) == {"threatintel", "virustotal"}


def test_the_pinned_servers_are_the_servers_that_read_the_staged_sample(
    declared: ToolDeclarations,
) -> None:
    # The servers the name list held before the declaration was read.
    reading = {d.source.key for d in declared.sources() if d.reads_staged_sample}
    assert reading == {"analysis", "knowledge", "network"}


def test_the_platforms_own_sources_are_the_resolving_servers(declared: ToolDeclarations) -> None:
    from maljan.agents.evidence_recorder import _RESOLVING_SERVERS

    owned = {d.source for d in declared.sources() if d.platform_owned}
    assert owned == {PACK, SourceRef("mcp", "analysis")}
    assert _RESOLVING_SERVERS == {"pipeline", "analysis"}


def test_the_required_environment_is_the_declared_one(declared: ToolDeclarations) -> None:
    for key in BUILT_IN_SERVERS:
        held = declared.source(f"mcp:{key}")
        assert held is not None
        assert held.required_env_allow == REQUIRED_ENV_ALLOW.get(key, ())


def test_the_non_secret_variable_names_are_the_events_ones(declared: ToolDeclarations) -> None:
    from maljan.core.builtin_declarations import shipped_variable_names
    from maljan.pipeline.events import scrub

    declared_names = {n for d in declared.sources() for n in d.variable_names}
    assert declared_names == set(shipped_variable_names())
    for name in declared_names:
        assert scrub(f"check {name} and the mount") == f"check {name} and the mount"


def test_the_work_directories_are_the_providers(declared: ToolDeclarations) -> None:
    from pathlib import Path

    from maljan.core.config import StaticR2Config
    from maljan.providers.base import DEFAULT_WORK_DIR

    assert declared.source("provider:ghidra").work_dir == DEFAULT_WORK_DIR  # type: ignore[union-attr]
    r2_dir = Path(StaticR2Config().mirror_dir).name
    assert declared.source("provider:r2").work_dir == r2_dir  # type: ignore[union-attr]


def test_the_auto_name_prefixes_are_the_validation_patterns(declared: ToolDeclarations) -> None:
    from maljan.pipeline.validation import _GENERIC_FUNCTION_NAME

    alternation = re.search(r"\(\?:([a-z|]+)\)", _GENERIC_FUNCTION_NAME.pattern)
    assert alternation is not None
    stems = set(alternation.group(1).split("|"))
    prefixes = {p for d in declared.sources() for p in d.auto_name_prefixes}
    assert {p[:-1].lower() for p in prefixes} == stems
    for prefix in prefixes:
        assert _GENERIC_FUNCTION_NAME.search(f"{prefix}401000")


def test_virustotals_reference_url_is_linked_on_a_run_that_asked_it(
    declared: ToolDeclarations,
) -> None:
    from types import SimpleNamespace

    from maljan.reporting.references import declared_references

    held = declared.source("mcp:virustotal")
    assert held is not None
    assert held.reference_urls == ("https://www.virustotal.com/gui/file/{sha256}",)
    hashes = SimpleNamespace(sha256="a" * 64, md5=None, sha1=None)
    asked = [{"source": "mcp:virustotal", "server": "virustotal", "tool": "get_file_report"}]
    linked = declared_references(asked, hashes, declared=declared)
    assert [ref.url for ref in linked] == [f"https://www.virustotal.com/gui/file/{'a' * 64}"]
    assert declared_references([], hashes, declared=declared) == []


def test_ghidras_open_tools_are_its_long_running_tools(declared: ToolDeclarations) -> None:
    from maljan.providers.sample_open import long_running_tools

    held = declared.source("provider:ghidra")
    assert held is not None
    long_running = {name for name, facts in held.tools.items() if facts.long_running}
    assert long_running == set(long_running_tools(held.sample_open))


def test_the_analysis_servers_long_running_tools_and_budgets_are_its_manifests() -> None:
    from maljan.core.builtin_declarations import server_declaration

    manifest = (ROOT / "services" / "analysis-mcp" / "server.py").read_text(encoding="utf-8")
    facts = server_declaration("analysis")["tool_facts"]
    assert {n for n, f in facts.items() if f.get("long_running")} == {"capa", "floss"}
    assert manifest.count("long_running=True") == 2
    assert facts["yara_scan"]["timeout_seconds"] == int(
        re.search(r"^YARA_TIMEOUT_S = (\d+)", manifest, re.M).group(1)  # type: ignore[union-attr]
    )


def test_the_report_sections_are_the_section_hints_by_name(declared: ToolDeclarations) -> None:
    from maljan.reporting.legacy_tool_names import SECTION_TOOL_HINTS as _SECTION_TOOL_HINTS

    for source, name, facts in _built_in_tools(declared):
        hinted = [s for s, hs in _SECTION_TOOL_HINTS.items() if any(h in name for h in hs)]
        assert list(facts.report_sections) == hinted, (source, name)  # type: ignore[attr-defined]


def test_the_tool_words_are_the_validation_words(declared: ToolDeclarations) -> None:
    from maljan.pipeline.validation import _tool_words

    for source, name, facts in _built_in_tools(declared):
        parts = {part for part in name.split("_") if len(part) >= 3}
        assert _tool_words(name) == parts | set(facts.words), (source, name)  # type: ignore[attr-defined]


def test_the_categories_are_the_mcp_clients_tags(declared: ToolDeclarations) -> None:
    from maljan.agents.mcp_client import MCPLangChainToolkit
    from maljan.core.undeclared_tools import categories_of, category_tag

    for source in ("provider:ghidra", "provider:r2"):
        tools = _tools(declared, source)
        toolkit = MCPLangChainToolkit(categories=categories_of(tools))
        for name, facts in tools.items():
            shown = toolkit._tag_description(name, "x")
            assert shown.startswith(f"[{facts.category.upper()}]"), (source, name)
            # The declared tag is the one the name alone would give an
            # undeclared tool: the declarations were written from that table.
            assert category_tag(name) == facts.category.upper(), (source, name)


def test_the_rule_match_display_names_are_the_assertion_words(declared: ToolDeclarations) -> None:
    from maljan.pipeline.validation import _RULE_MATCH_ASSERTION_RE

    names = {
        facts.display_name.lower()
        for _s, _n, facts in _built_in_tools(declared)
        if facts.kind in _kinds("validation._RULE_MATCH_SECTION_SOURCES")  # type: ignore[attr-defined]
    }
    alternation = re.search(r"\\b\(\?:([a-z|]+)\)\\b", _RULE_MATCH_ASSERTION_RE.pattern)
    assert alternation is not None
    assert names == set(alternation.group(1).split("|"))


def test_ghidra_and_radare2_carry_their_workflows_and_radare2_its_errors(
    declared: ToolDeclarations,
) -> None:
    from maljan.core.builtin_declarations import CAPE_WORKFLOW, R2_WORKFLOW
    from maljan.providers.base import CLAIM_GUIDANCE
    from maljan.providers.static import ghidra, r2

    held = declared.source("provider:ghidra")
    assert held is not None and held.prompt_fragment == ghidra.GHIDRA_WORKFLOW
    assert ghidra.GHIDRA_PROMPT_FRAGMENT == (
        ghidra.GHIDRA_LEAD + ghidra.GHIDRA_GUIDANCE + "\n\n" + held.prompt_fragment
    )
    held_r2 = declared.source("provider:r2")
    assert held_r2 is not None
    assert held_r2.prompt_fragment == R2_WORKFLOW
    assert r2.R2StaticProvider.R2_PROMPT_FRAGMENT == (
        r2.R2StaticProvider.R2_LEAD + CLAIM_GUIDANCE + "\n\n" + R2_WORKFLOW
    )
    assert held_r2.error_patterns == r2._R2_PATTERNS
    held_cape = declared.source("provider:cape2")
    assert held_cape is not None and held_cape.prompt_fragment == CAPE_WORKFLOW


# ---------------------------------------------------------------------------
# The paths read what today's readers read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "tool"),
    [
        ("mcp:analysis", "capa"),
        ("mcp:analysis", "sigma_match"),
        ("mcp:analysis", "yara_scan"),
        ("sandbox", "sandbox_signatures"),
    ],
)
def test_the_declared_technique_paths_read_what_the_summary_reads(
    declared: ToolDeclarations, source: str, tool: str
) -> None:
    from maljan.analysis.technique_ids import sigma_technique_ids, technique_ids_in
    from maljan.pipeline.evidence_summary import _technique_ids

    answer = json.loads((LEDGER / f"{tool}.json").read_text(encoding="utf-8"))
    facts = declared.declaration_for((source, tool))
    assert facts is not None
    read: set[str] = set()
    for field in facts.techniques:
        for value in select(answer, field.path):
            if field.format == "sigma_tag":
                read |= set(sigma_technique_ids({"tags": value}))
            else:
                read |= set(technique_ids_in(value))
    assert read == _technique_ids(answer)


def test_the_technique_depth_bound_is_the_summarys(declared: ToolDeclarations) -> None:
    from maljan.pipeline.evidence_summary import _technique_ids

    facts = declared.declaration_for(("mcp:analysis", "capa"))
    assert facts is not None
    for depth in range(0, 10):
        node: object = {"technique_id": "T1055"}
        for _ in range(depth):
            node = {"x": node}
        by_path = any(select(node, f.path) for f in facts.techniques)
        assert by_path == bool(_technique_ids(node)), depth


def test_the_declared_reputation_paths_read_the_virustotal_answer(
    declared: ToolDeclarations,
) -> None:
    from maljan.core.reputation import read_answer

    answer = json.loads((LEDGER / "get_file_report.json").read_text(encoding="utf-8"))
    facts = declared.declaration_for(("mcp:virustotal", "get_file_report"))
    assert facts is not None and facts.reputation is not None
    stats = answer["data"]["last_analysis_stats"]
    read = read_answer(facts, output=json.dumps(answer), server="virustotal")
    assert read.malicious == stats["malicious"]
    assert read.suspicious == stats["suspicious"]
    assert read.stats == {k: v for k, v in stats.items() if isinstance(v, int)}
    assert read.total == sum(v for v in stats.values() if isinstance(v, int))
    assert read.engines == answer["coverage"]["engines"]
    assert read.detections == [" ".join(d.split()) for d in answer["data"]["detections"]]
    assert read.last_seen == answer["analysis_date"]
    assert read.link == answer["report_url"]
    assert read.service == "VirusTotal"
    assert read.summary == ""


def test_both_threat_intel_prose_forms_are_read(declared: ToolDeclarations) -> None:
    facts = declared.declaration_for(("mcp:threatintel", "check_hash"))
    assert facts is not None and facts.reputation is not None
    mock = "VirusTotal: 55/70 Detections for this hash"
    live = "VirusTotal: 42/71 malicious, 3/71 suspicious"
    assert facts.reputation.counts_in_text(mock) == (55, 70, None)
    assert facts.reputation.counts_in_text(live) == (42, 71, 3)


@pytest.mark.parametrize(("tool", "rows"), [("strings", 1), ("capa", 1), ("yara_scan", 1)])
def test_the_declared_rows_read_the_stored_answers(
    declared: ToolDeclarations, tool: str, rows: int
) -> None:
    answer = json.loads((LEDGER / f"{tool}.json").read_text(encoding="utf-8"))
    facts = declared.declaration_for(("mcp:analysis", tool))
    assert facts is not None
    read = facts.row_values(answer)
    assert len(read) >= rows
    assert all(any(values for values in row.values()) for row in read)


def test_qu1cksc0pes_declaration_reads_as_a_server_block() -> None:
    from maljan.core.config import MCPServerConfig

    data = json.loads((ROOT / "docs/examples/profiles/qu1cksc0pe.declaration.json").read_text())
    block = MCPServerConfig.model_validate({"command": "x", **data})
    assert set(block.tool_facts) == {
        "analyze_file",
        "check_resources",
        "check_signatures",
        "detect_language",
        "detect_packer",
        "extract_iocs",
    }
    assert all(f.arguments == {"path": "file_path"} for f in block.tool_facts.values())
