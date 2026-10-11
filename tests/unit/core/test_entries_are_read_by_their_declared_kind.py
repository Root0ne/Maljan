"""The reading half reads an entry by its tool's declared kind, as it read the name tables.

Every built-in tool, as an entry that recorded its source and as one that did
not, is read by each switched consumer exactly as the old name table read it
(``core.legacy_tool_tables``); a name two built-in sources share carries one
reading; and the stored answers of the ledger fixtures give the same roots,
asserted techniques and corroboration whether or not their entries recorded a
source.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core import legacy_tool_tables as legacy
from maljan.core.config import Settings
from maljan.core.declared_reading import (
    bare_name,
    facts_of,
    facts_record,
    reads_as,
    shipped_by_name,
)
from maljan.core.tool_declarations import ToolDeclarations
from maljan.schemas.evidence import build_entry

ROOT = Path(__file__).resolve().parents[3]
LEDGER = ROOT / "tests" / "fixtures" / "ledger"
BUILT_IN_SOURCES = (
    "mcp:analysis",
    "mcp:knowledge",
    "mcp:network",
    "mcp:threatintel",
    "mcp:virustotal",
    "provider:ghidra",
    "provider:r2",
    "pack",
    "sandbox",
    "provider:capa_yara",
)

# Each switched consumer and the table it read by name.
TABLES: dict[str, frozenset[str]] = {
    "evidence_roots._WHOLE_FILE_TOOLS": legacy.WHOLE_FILE_TOOLS,
    "evidence_roots.FILE_ASSESSMENT_TOOLS": legacy.FILE_ASSESSMENT_TOOLS,
    "evidence_roots._REFERENCE_TOOLS": legacy.REFERENCE_TOOLS,
    "evidence_roots._IMPORT_LISTINGS": legacy.IMPORT_LISTINGS,
    "evidence_roots._EXPORT_LISTINGS": legacy.EXPORT_LISTINGS,
    "evidence_roots._PROGRAM_TOOLS": legacy.PROGRAM_TOOLS,
    "evidence_roots._OPEN_TOOLS": legacy.OPEN_TOOLS,
    "function_map": frozenset(legacy.FUNCTION_MAP_TOOLS),
    "triage_pack.RULE_TOOLS": frozenset(legacy.RULE_TOOLS),
    "evidence_summary.yara_rule_strings": frozenset(legacy.SIGNATURE_RULE_TOOLS),
    "evidence_summary.catalogue_associations": frozenset(legacy.API_CATALOGUE_TOOLS),
    "validation._REFERENCE_SECTION_SOURCES": frozenset(
        n.removeprefix("tool:") for n in legacy.REFERENCE_SECTION_SOURCES
    ),
    "validation._SAMPLE_VALUE_SECTION_SOURCES": frozenset(
        n.removeprefix("tool:") for n in legacy.SAMPLE_VALUE_SECTION_SOURCES
    ),
    "validation._RULE_MATCH_SECTION_SOURCES": frozenset(
        n.removeprefix("tool:") for n in legacy.RULE_MATCH_SECTION_SOURCES
    ),
}


@pytest.fixture(scope="module")
def held() -> ToolDeclarations:
    return ToolDeclarations.from_settings(Settings())


def _built_in(held: ToolDeclarations) -> list[tuple[str, str]]:
    out = []
    for source in BUILT_IN_SOURCES:
        declared = held.source(source)
        assert declared is not None, source
        out += [(source, name) for name in declared.tools]
    return out


def _entry(tool: str, source: str | None, output: str = "{}") -> object:
    return build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool=tool, args={}, server=None,
        output=output, source=source,
    )  # fmt: skip


@pytest.mark.parametrize("consumer", sorted(TABLES))
def test_every_built_in_tool_is_read_as_its_table_read_it(
    held: ToolDeclarations, consumer: str
) -> None:
    table = TABLES[consumer]
    differ = []
    for source, tool in _built_in(held):
        written = {
            "tool": tool,
            "source": source,
            "facts": facts_record(source, tool, declared=held),
        }
        recorded = reads_as(written, consumer)
        stored = reads_as({"tool": tool}, consumer)
        if recorded != (tool in table) or stored != (tool in table):
            differ.append((source, tool, recorded, stored))
    assert not differ, differ


@pytest.mark.parametrize("consumer", sorted(TABLES))
def test_a_stored_entry_of_a_legacy_name_is_read_as_before(consumer: str) -> None:
    for name in TABLES[consumer]:
        assert reads_as({"tool": name}, consumer)
    assert not reads_as({"tool": "a_tool_nobody_ships"}, consumer)


def test_the_asserting_tools_are_the_old_table(held: ToolDeclarations) -> None:
    from maljan.pipeline.evidence_summary import asserting_source

    for source, tool in _built_in(held):
        for entry in (_entry(tool, source), _entry(tool, None)):
            assert asserting_source(entry) == legacy.ASSERTING_SOURCES.get(tool), (source, tool)


def test_a_name_two_built_in_sources_share_has_one_reading(held: ToolDeclarations) -> None:
    seen: dict[str, tuple[object, ...]] = {}
    for source, tool in _built_in(held):
        facts = held.declaration_for((source, tool))
        assert facts is not None
        reading = (facts.kind, facts.reader, facts.asserts_techniques, facts.source,
                   facts.techniques, facts.words)  # fmt: skip
        assert seen.setdefault(tool, reading) == reading, (source, tool)
        assert shipped_by_name()[tool].kind == facts.kind


def test_a_collision_prefix_is_taken_off_a_stored_name_only() -> None:
    assert bare_name("knowledge__capabilities") == "capabilities"
    assert facts_of({"tool": "knowledge__capabilities"}) is not None
    # Written under a source that declares nothing for it: no facts, whatever the name.
    assert facts_of({"tool": "capa", "source": "mcp:x", "facts": {"v": 1}}) is None
    # Written before facts were stored: the legacy reading of its name.
    assert facts_of({"tool": "capa", "source": "mcp:x"}) is not None


def _fixture_ledger(stamp: bool) -> list[object]:
    sources = {"sandbox_": "sandbox"}
    out = []
    for index, path in enumerate(sorted(LEDGER.glob("*.json")), start=1):
        tool = path.stem
        source = None
        if stamp:
            source = next((s for p, s in sources.items() if tool.startswith(p)), "mcp:analysis")
            if tool in ("get_file_report",):
                source = "mcp:virustotal"
            elif tool in ("pcap_summary",):
                source = "mcp:network"
        out.append(
            build_entry(
                entry_id=f"ev_{index:04d}",
                seq=index,
                agent="static",
                tool=tool,
                args={"path": "/s/sample.exe"},
                server=None,
                output=path.read_text(encoding="utf-8"),
                source=source,
            )  # fmt: skip
        )
    return out


def test_the_stored_answers_read_the_same_with_or_without_a_recorded_source() -> None:
    from maljan.analysis.evidence_roots import RunRoots
    from maljan.pipeline import evidence_summary, validation

    readings = []
    for stamp in (False, True):
        ledger = _fixture_ledger(stamp)
        assert all((e.source is not None) == stamp for e in ledger)  # type: ignore[attr-defined]
        roots = RunRoots(ledger)
        readings.append(
            json.dumps(
                {
                    "roots": {k: v.roots for k, v in roots.entries.items()},
                    "reasons": {k: v.reason for k, v in roots.entries.items()},
                    "collect": evidence_summary.collect(None, ledger),
                    "yara": evidence_summary.yara_rule_strings(ledger),
                    "corroboration": validation.corroboration(None, ledger),
                    "words": {
                        k: sorted(validation.EntryTexts.from_ledger(ledger).words_of(k))
                        for k in roots.entries
                    },
                },
                sort_keys=True,
                default=str,
            )
        )
    assert readings[0] == readings[1]
    assert '"capa"' in readings[0] and "T1055" in readings[0]
