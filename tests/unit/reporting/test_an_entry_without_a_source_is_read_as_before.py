"""An entry that recorded no source is read exactly as the report always read it.

Every entry written before sources were recorded, and every report stored
then, is read by the tool-name tables kept in ``reporting.legacy_tool_names``.
The tables are held here, as the report wrote them before it read kinds, so
the legacy module cannot drift from them; and each kind a reader now selects
by is held to select, over the built-in tools' names, exactly the names it
selected before.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.builtin_declarations import BUILDER_OF_KIND
from maljan.reporting import legacy_tool_names as legacy
from maljan.reporting import tool_kinds
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import NetworkIP, RecoveredValue
from maljan.reporting.renderers.stix_renderer import (
    FILE_ONLY_PROCESS,
    MARKED_ONLY_PROCESS,
    disputed_flow_reason,
    emulation_from_ledger,
    recovered_by_words,
)
from maljan.schemas.evidence import build_entry

# The tables as ``ledger_report``, ``evidence_bundles``, ``figures``,
# ``renderers.markdown`` and ``renderers.stix_renderer`` wrote them.
BEFORE_NAMES: dict[str, frozenset[str]] = {
    "ledger_report._FUNCTION_TOOLS": frozenset(
        {
            "decompile_function",
            "decompile",
            "disassemble_function",
            "get_function",
            "analyze_function",
            "pdf",
            "pdc",
        }
    ),
    "ledger_report._FUNCTION_LIST_TOOLS": frozenset(
        {"list_functions", "get_functions", "afl", "list_methods"}
    ),
    "evidence_bundles._STRING_TOOLS": frozenset(
        {"strings", "floss", "iocs_from_file", "list_strings"}
    ),
    "evidence_bundles._NETWORK_SANDBOX_TOOLS": frozenset({"sandbox_network", "pcap_summary"}),
    "markdown._ANALYSIS_TOOLS": frozenset(
        {"capa", "yara_scan", "lolbin_lookup", "api_capability", "strings"}
    ),
    "markdown._REPUTATION_TOOLS": frozenset(
        {"get_file_report", "check_hash", "file_report", "hash_lookup"}
    ),
    "stix_renderer.recovering": frozenset(
        {"floss", "decode_string_blobs", "strings", "iocs_from_file"}
    ),
    "stix_renderer.DECODER_TOOL": frozenset({"decode_string_blobs"}),
    "stix_renderer._STRING_SWEEP_TOOLS": frozenset({"strings", "iocs_from_file", "iocs_from_text"}),
    "figures.code_listing": frozenset({"decompile_function"}),
    "ledger_projection.technique_hits": frozenset({"capa"}),
}
BEFORE_PREFIXES: dict[str, tuple[str, ...]] = {
    "evidence_bundles.SANDBOX_TOOL_PREFIXES": ("sandbox_", "pcap_summary"),
    "markdown._SANDBOX_TOOLS": ("sandbox_", "pcap_summary"),
}
BEFORE_ANALYSIS_ORDER = ("capa", "yara_scan", "lolbin_lookup", "api_capability", "strings")
BEFORE_BUILDERS: dict[str, str] = {
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

# ``ledger_projection``: each reader's tool names before, and the kinds (and
# answer shape) it reads now.
PROJECTION_READERS: list[tuple[tuple[str, ...], tuple[str, ...], str | None]] = [
    (("identify_file", "hashes", "signing_info"), ("identity", "signing"), None),
    (("pe_info",), ("format_info",), "pe_header"),
    (("pe_info", "elf_info", "macho_info", "apk_info"), ("format_info",), None),
    (("signing_info",), ("signing",), None),
    (("iocs_from_file", "iocs_from_text"), ("file_iocs", "text_iocs"), None),
    (("capa",), ("capability_rules",), None),
    (("api_capability",), ("api_catalogue",), None),
    (("resolve_api_hashes",), ("api_hash_resolution",), None),
    (("sandbox_processes",), ("sandbox_processes",), None),
    (("sandbox_signatures",), ("sandbox_signatures",), None),
    (("sandbox_registry_ops",), ("sandbox_registry",), None),
    (("sandbox_api_calls",), ("sandbox_api_calls",), None),
    (("sandbox_mutexes",), ("sandbox_mutexes",), None),
    (("sandbox_dropped_files",), ("sandbox_dropped_files",), None),
    (("sandbox_report_section",), ("sandbox_report_section",), None),
    (("pcap_summary",), ("pcap",), None),
    (("sandbox_network",), ("sandbox_network",), None),
    (("sandbox_services_and_tasks",), ("sandbox_services",), None),
    (("sigma_match", "sigma_match_sandbox"), ("event_rules",), None),
]


def _builtin_names() -> set[str]:
    return set(legacy._builtin_by_name())


def _universe() -> set[str]:
    names = _builtin_names()
    for held in BEFORE_NAMES.values():
        names |= held
    return names | {"sandbox_anything", "pcap_summary_extra", "list_strings_x", "x"}


@pytest.mark.parametrize("consumer", sorted(BEFORE_NAMES))
def test_each_name_table_is_kept_as_it_was(consumer: str) -> None:
    for name in _universe():
        assert legacy.in_table(consumer, name) == (name in BEFORE_NAMES[consumer]), name


@pytest.mark.parametrize("consumer", sorted(BEFORE_PREFIXES))
def test_each_prefix_table_is_kept_as_it_was(consumer: str) -> None:
    for name in _universe():
        assert legacy.in_table(consumer, name) == name.startswith(BEFORE_PREFIXES[consumer]), name


def test_the_builders_and_the_analysis_order_are_kept_as_they_were() -> None:
    assert legacy.BUILDERS == BEFORE_BUILDERS
    assert legacy.ANALYSIS_TOOLS == BEFORE_ANALYSIS_ORDER
    for name, builder in BEFORE_BUILDERS.items():
        assert tool_kinds.builder_of({"tool": name}) == builder
        facts = legacy.builtin_facts(name)
        assert facts is not None and BUILDER_OF_KIND.get(facts.kind) == builder


def test_no_two_built_in_sources_declare_one_name_two_ways() -> None:
    """One name, one reading; a declaration that names neither a kind nor a reader gives none.

    Such a declaration states other facts only (that the tool sends the
    sample out, its display name), and every kind-based reading treats it as
    undeclared, so it cannot read a name a second way. What it must not do is
    become the legacy reading of a name another source declares a kind for,
    which takes the first source in its order (``shipped_by_name``).
    """
    from maljan.core.config import Settings
    from maljan.core.declared_reading import shipped_by_name
    from maljan.core.tool_declarations import ToolDeclarations

    seen: dict[str, tuple[str, str]] = {}
    unread: set[str] = set()
    for source in ToolDeclarations.from_settings(Settings()).sources():
        for name, facts in source.tools.items():
            if not facts.kind and not facts.reader:
                unread.add(name)
                continue
            shape = (facts.kind, facts.reader)
            assert seen.setdefault(name, shape) == shape, name
    for name in unread & set(seen):
        taken = shipped_by_name()[name]
        assert (taken.kind, taken.reader) == seen[name], name


@pytest.mark.parametrize(("before", "kinds", "reader"), PROJECTION_READERS)
def test_each_projection_reader_selects_the_names_it_selected(
    before: tuple[str, ...], kinds: tuple[str, ...], reader: str | None
) -> None:
    selected = set()
    for name in _builtin_names():
        facts = legacy.builtin_facts(name)
        assert facts is not None
        if facts.kind in kinds and (reader is None or facts.reader == reader):
            selected.add(name)
    assert selected == set(before)


def test_the_recovery_record_reads_the_names_it_read() -> None:
    kinds = {"emulated_strings", "decoded_strings", "strings", "file_iocs"}
    read = {n for n in _builtin_names() if (f := legacy.builtin_facts(n)) and f.kind in kinds}
    assert read == BEFORE_NAMES["stix_renderer.recovering"]


def _entry(n: int, tool: str, answer: Any) -> Any:
    return build_entry(
        entry_id=f"ev_{n:04d}",
        seq=n,
        agent="pipeline",
        tool=tool,
        args={},
        server=None,
        output=json.dumps(answer),
    )


C2 = "c2.example-evil.net"


def test_a_record_built_from_entries_with_no_source_is_written_as_before() -> None:
    floss = {"strings": [{"string": f"http://{C2}/a", "kind": "decoded", "function_rva": "0x1"}]}
    record = emulation_from_ledger([_entry(3, "analysis__floss", floss)])
    (how,) = record.recovered_by[C2]
    assert how.tool == "floss" and not how.kind and not how.named
    assert "kind" not in how.model_dump() and "named" not in how.model_dump()
    assert (
        recovered_by_words(record, "domain", C2) == "floss, ev_0003 (decoded string, routine 0x1)"
    )


def test_a_stored_record_reads_its_tool_by_name() -> None:
    stored = RecoveredValue(tool="floss", entry="ev_0002", scheme="stack", functions=["0x9"])
    from maljan.reporting.models import EmulatedStrings

    record = EmulatedStrings(values={C2: "ev_0002"}, recovered_by={C2: [stored]})
    assert (
        recovered_by_words(record, "domain", C2) == "floss, ev_0002 (stack string, in function 0x9)"
    )


def test_a_stored_disputed_row_names_the_only_sandbox_that_marked_one() -> None:
    row = NetworkIP(address="192.0.2.7", marked_only_processes=["a.exe (procid 3)"])
    assert row.marked_by is None
    assert "marked_by" not in row.model_dump()
    said = disputed_flow_reason(row.marked_only_processes, ["b.exe (procid 4)"], row.marked_by)
    assert MARKED_ONLY_PROCESS in said and FILE_ONLY_PROCESS in said
    assert "which Triage marks as the sample's" in said


def test_a_stored_flow_marked_orig_is_read_as_marked() -> None:
    from maljan.reporting.ledger_projection import network_from_ledger

    answer = {
        "tcp": [
            {"dst": "192.0.2.9", "procid": 5, "lineage_disputed": "orig", "process": "x.exe"},
        ]
    }
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args={},
        server=None,
        output=json.dumps(answer),
    )
    network = network_from_ledger([entry])
    assert network is not None
    (ip,) = [ip for ip in network.ips if ip.address == "192.0.2.9"]
    assert ip.marked_only_processes == ["x.exe (procid 5)"]
    assert ip.marked_by is None


# ---------------------------------------------------------------------------
# The sections a source-less ledger rebuilds into
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "reporting"
BENCHMARK = Path(".superpowers") / "sdd" / "mandate-2026-09-17" / "benchmark" / "deepseek"
# ``build_sections`` over each stored run's whole ledger as dev f96cb89f drew it, but for the
# one "Functions examined" item that named the tool twice (``list_functions (list_functions)``)
# and the decompiled functions it cut at 400 characters, now whole (T-389: run5's 56 and run4's
# 83 batch functions; nothing else changed): the section count and the digest of the sections'
# JSON (sorted keys).
STORED_REBUILDS = {
    "run7": (89, "5622126326362a4b"),
    "run5": (102, "26962def958da05d"),
    "run4": (92, "a1b9e99cea2318db"),
    "local8": (40, "38eef84aca43089b"),
}


def _dumped(sections: list[Any]) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in sections]


def test_a_source_less_ledger_rebuilds_the_sections_dev_drew() -> None:
    from tests.unit.reporting._source_less_ledger import source_less_ledger

    expected = json.loads((GOLDEN / "sections_of_a_source_less_ledger.json").read_text())
    assert _dumped(build_sections(source_less_ledger())) == expected


def _benchmark() -> Path | None:
    """The stored runs: in this checkout, or in the checkout a worktree belongs to."""
    for base in (ROOT, *(p for p in ROOT.parents if (p / ".claude" / "worktrees").is_dir())):
        if (base / BENCHMARK).is_dir():
            return base / BENCHMARK
    return None


@pytest.mark.parametrize("run", sorted(STORED_REBUILDS))
def test_a_stored_run_s_ledger_rebuilds_the_sections_dev_drew(run: str) -> None:
    from maljan.schemas.evidence import LedgerEntry

    root = _benchmark()
    if root is None or not (root / run / "evidence.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    fields = set(LedgerEntry.model_fields)
    items = json.loads((root / run / "evidence.json").read_text())["items"]
    ledger = [
        LedgerEntry.model_validate(
            {**{k: v for k, v in item.items() if k in fields}, "id": item["entry_id"]}
        )
        for item in items
    ]
    sections = build_sections(ledger)
    text = json.dumps(_dumped(sections), sort_keys=True)
    assert (len(sections), hashlib.sha256(text.encode()).hexdigest()[:16]) == STORED_REBUILDS[run]
