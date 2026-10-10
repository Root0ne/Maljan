"""Every built-in tool is declared, and its declaration says what the code's tables say.

The declarations of ``maljan.core.builtin_declarations`` are the facts the name
tables hold today, so each consumer can move from its table to the declaration
with the same output. Each test below holds one table against the declarations
it is to be replaced by; a table changed without its declaration, or a built-in
tool added without a kind, fails here.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from maljan.core import virustotal
from maljan.core.config import REPUTATION_SERVER_KEYS, REQUIRED_ENV_ALLOW, Settings
from maljan.core.tool_declarations import PACK, SANDBOX, SourceRef, ToolDeclarations, select

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"
LEDGER = ROOT / "tests" / "fixtures" / "ledger"


@pytest.fixture(scope="module")
def declared() -> ToolDeclarations:
    return ToolDeclarations.from_settings(Settings())


def _tools(declared: ToolDeclarations, source: str) -> dict:
    held = declared.source(source)
    assert held is not None, source
    return dict(held.tools)


BUILT_IN_SERVERS = ("analysis", "knowledge", "network", "threatintel", "virustotal")


@pytest.mark.parametrize("server", BUILT_IN_SERVERS)
def test_every_tool_a_built_in_server_advertises_has_a_kind(
    declared: ToolDeclarations, server: str
) -> None:
    advertised = json.loads((GOLDEN / f"{server}.json").read_text(encoding="utf-8"))["tools"]
    tools = _tools(declared, f"mcp:{server}")
    missing = [name for name in advertised if name not in tools]
    assert not missing, f"{server} tools with no declaration: {missing}"


def test_every_virustotal_tool_the_code_names_is_declared(declared: ToolDeclarations) -> None:
    tools = _tools(declared, "mcp:virustotal")
    assert set(virustotal.LOOKUP_TOOLS) | set(virustotal.SUBMIT_TOOLS) == set(tools)


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


def test_the_required_environment_is_the_declared_one(declared: ToolDeclarations) -> None:
    for key in BUILT_IN_SERVERS:
        held = declared.source(f"mcp:{key}")
        assert held is not None
        assert held.required_env_allow == REQUIRED_ENV_ALLOW.get(key, ())


def test_ghidras_open_tools_are_its_long_running_tools(declared: ToolDeclarations) -> None:
    from maljan.providers.sample_open import long_running_tools

    held = declared.source("provider:ghidra")
    assert held is not None
    long_running = {name for name, facts in held.tools.items() if facts.long_running}
    assert long_running == set(long_running_tools(held.sample_open))


def test_the_analysis_servers_long_running_tools_are_its_manifests() -> None:
    from maljan.core.builtin_declarations import server_declaration

    manifest = (ROOT / "services" / "analysis-mcp" / "server.py").read_text(encoding="utf-8")
    declared = {
        name
        for name, facts in server_declaration("analysis")["tool_facts"].items()
        if facts.get("long_running")
    }
    assert declared == {"capa", "floss"}
    assert manifest.count("long_running=True") == len(declared)


def test_the_report_sections_are_the_section_hints_by_name(declared: ToolDeclarations) -> None:
    from maljan.reporting.evidence_bundles import _SECTION_TOOL_HINTS

    for source in ("provider:ghidra", "provider:r2", "pack"):
        for name, facts in _tools(declared, source).items():
            hinted = [s for s, hs in _SECTION_TOOL_HINTS.items() if any(h in name for h in hs)]
            assert facts.report_sections == hinted, (source, name)


def test_the_tool_words_are_the_validation_words() -> None:
    from maljan.core.builtin_declarations import server_declaration
    from maljan.pipeline.validation import _tool_words

    for server in ("analysis", "network"):
        for name, facts in server_declaration(server)["tool_facts"].items():
            parts = {part for part in name.split("_") if len(part) >= 3}
            assert _tool_words(name) == parts | set(facts.get("words", ())), name


def test_ghidra_and_radare2_carry_their_prompts_and_radare2_its_errors(
    declared: ToolDeclarations,
) -> None:
    from maljan.providers.static import ghidra, r2

    held = declared.source("provider:ghidra")
    assert held is not None and held.prompt_fragment == ghidra.GHIDRA_PROMPT_FRAGMENT
    held_r2 = declared.source("provider:r2")
    assert held_r2 is not None
    assert held_r2.prompt_fragment == r2.R2StaticProvider.R2_PROMPT_FRAGMENT
    assert [(p.match, p.code, p.remediation or None) for p in held_r2.error_patterns] == [
        (pattern.pattern, code, remediation) for pattern, code, remediation in r2._R2_ERROR_REPLIES
    ]


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


def test_the_threat_intel_prose_count_is_the_packs(declared: ToolDeclarations) -> None:
    import re

    from maljan.pipeline.triage_pack import _DETECTIONS_RE

    facts = declared.declaration_for(("mcp:threatintel", "check_hash"))
    assert facts is not None and facts.reputation is not None
    text = "VirusTotal: 55/70 Detections for this hash"
    found = re.search(facts.reputation.text_pattern, text)
    assert found is not None and int(found["malicious"]) == 55
    assert _DETECTIONS_RE.search(text)


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
