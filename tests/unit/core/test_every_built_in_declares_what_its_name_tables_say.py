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
from maljan.core.config import REPUTATION_SERVER_KEYS, REQUIRED_ENV_ALLOW, Settings
from maljan.core.tool_declarations import PACK, SANDBOX, SourceRef, ToolDeclarations, select

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
    from maljan.analysis.ghidra_passes import ANTI_ANALYSIS_TOOL
    from maljan.pipeline import sandbox_status, triage_pack
    from maljan.tools import artefact_index, crypto_constants, upx

    steps = {tool for tool, _call in triage_pack._FORMAT_TOOLS.values()}
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
    from maljan.agents import function_map, network_analyst, static_analyst
    from maljan.analysis import evidence_roots
    from maljan.pipeline import triage_pack, validation
    from maljan.reporting import evidence_bundles, ledger_report
    from maljan.reporting.renderers import markdown, stix_renderer

    def names(values: object) -> Callable[[str], bool]:
        held = _strip_tool(values)
        return lambda name: name in held

    def prefixes(values: tuple[str, ...]) -> Callable[[str], bool]:
        return lambda name: name.startswith(values)

    return {
        "evidence_roots._WHOLE_FILE_TOOLS": names(evidence_roots._WHOLE_FILE_TOOLS),
        "evidence_roots._REFERENCE_TOOLS": names(evidence_roots._REFERENCE_TOOLS),
        "evidence_roots._IMPORT_LISTINGS": names(evidence_roots._IMPORT_LISTINGS),
        "evidence_roots._EXPORT_LISTINGS": names(evidence_roots._EXPORT_LISTINGS),
        "evidence_roots._PROGRAM_TOOLS": names(evidence_roots._PROGRAM_TOOLS),
        "evidence_roots._OPEN_TOOLS": names(evidence_roots._OPEN_TOOLS),
        "evidence_bundles._STRING_TOOLS": names(evidence_bundles._STRING_TOOLS),
        "evidence_bundles._NETWORK_SANDBOX_TOOLS": names(evidence_bundles._NETWORK_SANDBOX_TOOLS),
        "evidence_bundles.SANDBOX_TOOL_PREFIXES": prefixes(evidence_bundles.SANDBOX_TOOL_PREFIXES),
        "ledger_report._FUNCTION_TOOLS": names(ledger_report._FUNCTION_TOOLS),
        "ledger_report._FUNCTION_LIST_TOOLS": names(ledger_report._FUNCTION_LIST_TOOLS),
        "validation._REFERENCE_SECTION_SOURCES": names(validation._REFERENCE_SECTION_SOURCES),
        "validation._SAMPLE_VALUE_SECTION_SOURCES": names(validation._SAMPLE_VALUE_SECTION_SOURCES),
        "validation._RULE_MATCH_SECTION_SOURCES": names(validation._RULE_MATCH_SECTION_SOURCES),
        "markdown._ANALYSIS_TOOLS": names(markdown._ANALYSIS_TOOLS),
        "markdown._REPUTATION_TOOLS": names(markdown._REPUTATION_TOOLS),
        "markdown._SANDBOX_TOOLS": prefixes(markdown._SANDBOX_TOOLS),
        "triage_pack._REPUTATION_TOOLS": names(triage_pack._REPUTATION_TOOLS),
        "triage_pack.RULE_TOOLS": names(triage_pack.RULE_TOOLS),
        "run_state.reputation": names(_read_inline_tables()["run_state.reputation"]),
        "network_analyst._PCAP_TOOLS": names(t for t, _ in network_analyst._PCAP_TOOLS),
        "function_map": names(
            (
                function_map._HASH_TOOL,
                function_map._BLOB_TOOL,
                function_map._FLOSS_TOOL,
                function_map._INDEX_TOOL,
            )
        ),
        "stix_renderer.recovering": names(_read_inline_tables()["stix_renderer.recovering"]),
        "stix_renderer.DECODER_TOOL": names((stix_renderer.DECODER_TOOL,)),
        "stix_renderer._STRING_SWEEP_TOOLS": names(stix_renderer._STRING_SWEEP_TOOLS),
        "figures.code_listing": names(_read_inline_tables()["figures.code_listing"]),
        "ledger_projection.technique_hits": names(
            _read_inline_tables()["ledger_projection.technique_hits"]
        ),
        "static_analyst._LOAD_TOOL": names((static_analyst._LOAD_TOOL,)),
    }


def _read_inline_tables() -> dict[str, tuple[str, ...]]:
    """The four tables the code writes inline, read from the code's own source.

    Not copied: a change to any of these lines changes what this reads, and
    the consumer test then holds the declaration to the new table.
    """
    import ast
    import inspect

    from maljan.pipeline import run_state
    from maljan.reporting import figures, ledger_projection
    from maljan.reporting.renderers import stix_renderer

    def literal(pattern: str, text: str) -> tuple[str, ...]:
        found = re.findall(pattern, text)
        assert len(found) == 1, (pattern, found)
        value = ast.literal_eval(found[0])
        return tuple(value) if isinstance(value, tuple) else (value,)

    state = inspect.getsource(run_state)
    shown = inspect.getsource(figures)
    projection = inspect.getsource(ledger_projection)
    hits = projection.index("static.api_technique_hits.append(")
    before_hits = projection[:hits]
    payloads = re.findall(r"_payloads\(ledger, ([^)]*)\)", before_hits)[-1]
    recovering = inspect.getsource(stix_renderer.emulation_from_ledger)
    branches = re.findall(r"tool == (\"[a-z_]+\"|DECODER_TOOL)", recovering)
    return {
        "run_state.reputation": literal(
            r"reputation = \[e for e in pack if e\.tool in (\([^)]*\))\]", state
        ),
        "figures.code_listing": literal(r'o\.get\("tool_name"\) != ("[a-z_]+")', shown),
        "ledger_projection.technique_hits": tuple(ast.literal_eval(f"({payloads},)")),
        "stix_renderer.recovering": tuple(
            stix_renderer.DECODER_TOOL if b == "DECODER_TOOL" else ast.literal_eval(b)
            for b in branches
        ),
    }


def test_the_inline_tables_are_read_as_the_code_writes_them_today() -> None:
    assert _read_inline_tables() == {
        "run_state.reputation": ("get_file_report", "check_hash", "reputation"),
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


def test_the_section_builders_are_drawn_by_kind(declared: ToolDeclarations) -> None:
    from maljan.reporting import ledger_report

    differ = []
    for source, name, facts in _built_in_tools(declared):
        builder = ledger_report._BUILDERS.get(name)
        expected = builder.__name__ if builder is not None else None
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
    "read_pcap_summary": "flow_table",
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
    from maljan.pipeline.evidence_summary import ASSERTING_SOURCES

    for source in (PACK, SourceRef("mcp", "analysis"), SourceRef("mcp", "knowledge"), SANDBOX):
        held = declared.source(source)
        assert held is not None
        for name, facts in held.tools.items():
            if name in ASSERTING_SOURCES:
                assert facts.asserts_techniques and facts.source == ASSERTING_SOURCES[name], name
            else:
                assert not facts.asserts_techniques, (str(source), name)


def test_the_reputation_servers_are_the_servers_with_the_reputation_role(
    declared: ToolDeclarations,
) -> None:
    keys = {ref.key for ref in declared.servers_with_role("reputation") if ref.kind == "mcp"}
    assert keys == set(REPUTATION_SERVER_KEYS)


def test_the_pinned_servers_are_the_servers_that_read_the_staged_sample(
    declared: ToolDeclarations,
) -> None:
    from maljan.agents.tool_pinning import PINNED_SERVERS

    reading = {d.source.key for d in declared.sources() if d.reads_staged_sample}
    assert reading == set(PINNED_SERVERS)


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
    from maljan.pipeline.events import _OWN_VARIABLE_NAMES

    declared_names = {n for d in declared.sources() for n in d.variable_names}
    assert declared_names == set(_OWN_VARIABLE_NAMES)


def test_the_work_directories_are_the_workers(declared: ToolDeclarations) -> None:
    from app.worker.sample_files import R2_WORK_SUBDIR, WORK_SUBDIR

    assert declared.source("provider:ghidra").work_dir == WORK_SUBDIR  # type: ignore[union-attr]
    assert declared.source("provider:r2").work_dir == R2_WORK_SUBDIR  # type: ignore[union-attr]


def test_the_auto_name_prefixes_are_the_validation_patterns(declared: ToolDeclarations) -> None:
    from maljan.pipeline.validation import _GENERIC_FUNCTION_NAME

    alternation = re.search(r"\(\?:([a-z|]+)\)", _GENERIC_FUNCTION_NAME.pattern)
    assert alternation is not None
    stems = set(alternation.group(1).split("|"))
    prefixes = {p for d in declared.sources() for p in d.auto_name_prefixes}
    assert {p[:-1].lower() for p in prefixes} == stems
    for prefix in prefixes:
        assert _GENERIC_FUNCTION_NAME.search(f"{prefix}401000")


def test_virustotals_reference_url_is_the_reports(declared: ToolDeclarations) -> None:
    from maljan.reporting.detection_signatures import __file__ as signatures_file

    held = declared.source("mcp:virustotal")
    assert held is not None
    assert held.reference_urls == ("https://www.virustotal.com/gui/file/{sha256}",)
    assert "https://www.virustotal.com/gui/file/{sha256}" in Path(signatures_file).read_text()


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
    from maljan.reporting.evidence_bundles import _SECTION_TOOL_HINTS

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

    tag = MCPLangChainToolkit._tag_description
    for source in ("provider:ghidra", "provider:r2"):
        for name, facts in _tools(declared, source).items():
            shown = tag(None, name, "x")  # type: ignore[arg-type]
            assert shown.startswith(f"[{facts.category.upper()}]"), (source, name)


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


def test_ghidra_and_radare2_carry_their_prompts_and_radare2_its_errors(
    declared: ToolDeclarations,
) -> None:
    from maljan.providers.static import ghidra, r2

    held = declared.source("provider:ghidra")
    assert held is not None and held.prompt_fragment == ghidra.GHIDRA_PROMPT_FRAGMENT
    held_r2 = declared.source("provider:r2")
    assert held_r2 is not None
    assert held_r2.prompt_fragment == r2.R2StaticProvider.R2_PROMPT_FRAGMENT
    assert held_r2.error_patterns == r2._R2_PATTERNS


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
    from maljan.pipeline.triage_pack import _stats_malicious

    answer = json.loads((LEDGER / "get_file_report.json").read_text(encoding="utf-8"))
    facts = declared.declaration_for(("mcp:virustotal", "get_file_report"))
    assert facts is not None and facts.reputation is not None
    malicious = select(answer, facts.reputation.malicious)
    assert (malicious[0] if malicious else None) == _stats_malicious(answer)
    engines = select(answer, facts.reputation.engines)
    assert engines and engines[0] == answer["coverage"]["engines"]


def test_both_threat_intel_prose_forms_are_read(declared: ToolDeclarations) -> None:
    from maljan.pipeline.triage_pack import _DETECTIONS_RE

    facts = declared.declaration_for(("mcp:threatintel", "check_hash"))
    assert facts is not None and facts.reputation is not None
    mock = "VirusTotal: 55/70 Detections for this hash"
    live = "VirusTotal: 42/71 malicious, 3/71 suspicious"
    assert facts.reputation.counts_in_text(mock) == (55, 70)
    assert facts.reputation.counts_in_text(live) == (42, 71)
    assert _DETECTIONS_RE.search(mock) and not _DETECTIONS_RE.search(live)
    console = (ROOT / "apps/web/src/components/analysis/reputation.ts").read_text()
    assert "malicious" in console


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
