"""The report reads a tool by the kind it declares, from any server, never by its name.

An invented reverser and an invented rule scanner, declared only as data in
``mcp.servers``, get every treatment the built-in tools of the same kinds get:
the composer's technical sections, "Functions examined", the code-listing
figures, the rule tables, the technique hits, the recovery record. A tool on a
server that declares nothing for it is read by the one name reading of a code
listing the agent side reads it by (``core.undeclared_tools``), and by nothing
else: sharing a built-in's name gives it nothing more.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.declared_reading import facts_record
from maljan.core.tool_declarations import ToolDeclarations
from maljan.reporting import tool_kinds
from maljan.reporting.evidence_bundles import _SECTION_KINDS, _filter_tool_outputs, bundle_for
from maljan.reporting.figures import build_code_listings
from maljan.reporting.ledger_projection import static_from_ledger
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import EvidenceIndexRow, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import (
    DECODED_FROM_THE_BYTES_TEMPLATE,
    disputed_flow_reason,
    emulation_from_ledger,
    emulation_kwargs,
    recovered_by_words,
)
from maljan.schemas.evidence import build_entry

# The invented reverser: one tool of every kind a technical section reads.
REVERSER_TOOLS: dict[str, dict[str, Any]] = {
    "pseudo_c": {"kind": "decompile"},
    "asm_of": {"kind": "function_disassembly"},
    "texts": {"kind": "listing_strings"},
    "regions": {"kind": "segments"},
    "consts": {"kind": "crypto_constants"},
    "run_it": {"kind": "emulation"},
    "flows": {"kind": "dataflow"},
    "chains": {"kind": "call_chains"},
    "where_iocs": {"kind": "iocs_with_context"},
    "imports_of": {"kind": "import_listing"},
    "tricks": {"kind": "anti_analysis_scan"},
    "behaves": {"kind": "behaviour_scan"},
    "whole_fn": {"kind": "function_analysis"},
    "doc_fn": {"kind": "documentation_completeness"},
    "fns": {"kind": "function_list"},
}

# The invented rule scanner, emulator and decoder, each answering in its own shape.
SCANNER_TOOLS: dict[str, dict[str, Any]] = {
    "match_rules": {
        "kind": "capability_rules",
        "asserts_techniques": True,
        "source": "myrules",
        "rows": "/hits/*",
        "values": {"rule": "/name", "namespace": "/area"},
        "techniques": [{"path": "/ttp", "format": "attck"}],
        "display_name": "MyRules",
    },
    "emu_strings": {
        "kind": "emulated_strings",
        "rows": "/out/*",
        "values": {"text": "/s", "scheme": "/how"},
        "places": {"call_site": "/at", "function": "/fn"},
        "display_name": "MyEmu",
    },
    "unblob": {
        "kind": "decoded_strings",
        "rows": "/found/*",
        "values": {"text": "/t"},
        "display_name": "Unblob",
    },
}


@pytest.fixture(autouse=True)
def _forget_the_held_declarations() -> Iterator[None]:
    yield
    _HELD.clear()


@pytest.fixture
def declared(monkeypatch: pytest.MonkeyPatch) -> Iterator[ToolDeclarations]:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "myrev": {"command": "x", "tool_facts": REVERSER_TOOLS},
                    "myscan": {"command": "y", "tool_facts": SCANNER_TOOLS},
                    "plain": {"command": "z"},
                }
            }
        }
    )
    held = ToolDeclarations.from_settings(settings)
    _HELD[:] = [held]
    yield held


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), **over)


# The declarations the invented servers' entries are written under. An entry
# stores its tool's facts when it is written (``core.declared_reading``), and
# the report reads only those: nothing here reads the process's settings.
_HELD: list[ToolDeclarations] = []


def _facts(source: str, tool: str) -> dict[str, Any] | None:
    return facts_record(source, tool, declared=_HELD[0]) if _HELD else None


def _output(source: str, tool: str, n: int = 0) -> dict[str, Any]:
    return {
        "agent_id": "static",
        "tool_name": tool,
        "args": {},
        "symbol": f"fn_{n}",
        "output": f"answer of {tool}",
        "seq": n,
        "source": source,
        "facts": _facts(source, tool),
    }


def _entry(n: int, tool: str, answer: Any, source: str | None) -> Any:
    entry = build_entry(
        entry_id=f"ev_{n:04d}",
        seq=n,
        agent="static",
        tool=tool,
        args={},
        server=None,
        output=json.dumps(answer),
        source=source,
    )
    if source is not None:
        entry.facts = _facts(source, tool)
    return entry


# ---------------------------------------------------------------------------
# The composer's technical sections
# ---------------------------------------------------------------------------


def _received(section: str, outputs: list[dict[str, Any]]) -> set[str]:
    bundle = bundle_for(section, _report(), {"static": outputs})
    return {o["tool"] for o in bundle["tool_outputs"]}


@pytest.mark.parametrize("section", sorted(_SECTION_KINDS))
def test_an_invented_reverser_feeds_every_technical_section_as_ghidra_does(
    declared: ToolDeclarations, section: str
) -> None:
    ghidra = declared.source("provider:ghidra")
    assert ghidra is not None
    ghidra_outputs = [_output("provider:ghidra", name) for name in ghidra.tools]
    mine = [_output("mcp:myrev", name) for name in REVERSER_TOOLS]

    from_ghidra = _received(section, ghidra_outputs)
    from_mine = _received(section, mine)
    assert from_ghidra and from_mine
    kinds_ghidra = {ghidra.tools[name].kind for name in from_ghidra}
    kinds_mine = {REVERSER_TOOLS[name]["kind"] for name in from_mine}
    assert kinds_mine == kinds_ghidra


@pytest.mark.parametrize("section", sorted(_SECTION_KINDS))
def test_a_ghidra_output_with_its_source_reaches_every_section_its_name_did(
    declared: ToolDeclarations, section: str
) -> None:
    ghidra = declared.source("provider:ghidra")
    assert ghidra is not None
    unsourced = [{**_output("", name), "source": None} for name in ghidra.tools]
    sourced = [_output("provider:ghidra", name) for name in ghidra.tools]
    by_name = _received(section, unsourced)
    by_kind = _received(section, sourced)
    assert by_name <= by_kind
    # What the kinds add is a function's disassembly, beside its decompilation.
    assert {ghidra.tools[name].kind for name in by_kind - by_name} <= {"function_disassembly"}


def test_an_undeclared_listing_reaches_the_code_sections_and_nothing_else_does(
    declared: ToolDeclarations,
) -> None:
    outputs = [_output("mcp:plain", "decompile_function"), _output("mcp:plain", "list_strings")]
    for section, kinds in _SECTION_KINDS.items():
        expected = {"decompile_function"} if "decompile" in kinds else set()
        assert _received(section, outputs) == expected


def test_a_declared_report_section_routes_a_tool_of_any_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "odd": {
                        "command": "x",
                        "tool_facts": {
                            "notes": {"kind": "notes", "report_sections": ["ransom_note"]}
                        },
                    }
                }
            }
        }
    )
    held = ToolDeclarations.from_settings(settings)
    _HELD[:] = [held]
    outputs = [_output("mcp:odd", "notes")]
    assert _received("ransom_note", outputs) == {"notes"}
    assert _received("configuration", outputs) == set()


# ---------------------------------------------------------------------------
# Functions examined, figures, rule tables
# ---------------------------------------------------------------------------


def test_an_invented_reverser_s_calls_are_functions_examined(declared: ToolDeclarations) -> None:
    ledger = [
        _entry(1, "pseudo_c", {"code": "int f(void)"}, "mcp:myrev"),
        _entry(2, "fns", {"functions": ["f"]}, "mcp:myrev"),
        _entry(3, "decompile_function", {"code": "int g(void)"}, "mcp:plain"),
    ]
    sections = {s.key: s for s in build_sections(ledger)}
    examined = sections["functions_examined"]
    # A tool on a server that declares nothing for it, whose name says it
    # decompiles, is read as the function map reads it.
    assert examined.evidence_ids == ["ev_0001", "ev_0002", "ev_0003"]
    assert "tool_decompile_function" not in sections


def test_an_invented_decompiler_s_listing_is_drawn(declared: ToolDeclarations) -> None:
    report = _report(
        technical_evidence={
            "static": [
                {**_output("mcp:myrev", "pseudo_c"), "output": "int f(void) { return 1; }"},
                {**_output("mcp:plain", "decompile_function"), "output": "int g(void);"},
            ]
        }
    )
    figures = build_code_listings(report)
    assert [f.caption for f in figures] == ["Decompiled fn_0", "Decompiled fn_0"]


def test_an_invented_rule_scanner_fills_the_capability_table_in_its_own_shape(
    declared: ToolDeclarations,
) -> None:
    answer = {"hits": [{"name": "resolve by hash", "area": "linking/runtime", "ttp": "T1027"}]}
    sections = {s.key: s for s in build_sections([_entry(1, "match_rules", answer, "mcp:myscan")])}
    table = sections["capa_capabilities"]
    assert table.title == "MyRules capabilities"
    assert table.rows == [["linking/runtime", "resolve by hash", "T1027", ""]]
    assert table.source == "tool:match_rules"


def test_a_built_in_rule_name_on_a_server_that_declares_nothing_is_a_generic_block(
    declared: ToolDeclarations,
) -> None:
    answer = {"capabilities": [{"rule": "x", "namespace": "y"}]}
    sections = {s.key for s in build_sections([_entry(1, "capa", answer, "mcp:plain")])}
    assert "capa_capabilities" not in sections
    assert any(key.startswith("tool_capa") for key in sections)


def test_an_operator_tool_of_a_built_in_kind_in_another_shape_is_still_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {"mine": {"command": "x", "tool_facts": {"who": {"kind": "identity"}}}}
            }
        }
    )
    held = ToolDeclarations.from_settings(settings)
    _HELD[:] = [held]
    sections = build_sections([_entry(1, "who", {"elsewhere": "a thing"}, "mcp:mine")])
    assert any("ev_0001" in s.evidence_ids for s in sections)


def _operator_build_seconds(n: int) -> float:
    ledger = [_entry(i, "who", {"elsewhere": f"thing {i}"}, "mcp:mine") for i in range(1, n + 1)]
    started = time.perf_counter()
    build_sections(ledger)
    return time.perf_counter() - started


def test_building_an_operator_tool_s_sections_is_linear(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {"mine": {"command": "x", "tool_facts": {"who": {"kind": "identity"}}}}
            }
        }
    )
    held = ToolDeclarations.from_settings(settings)
    _HELD[:] = [held]
    _operator_build_seconds(200)
    small = min(_operator_build_seconds(2_000) for _ in range(2))
    large = min(_operator_build_seconds(20_000) for _ in range(2))
    assert large < small * 25


def test_an_invented_rule_scanner_s_hits_carry_its_declared_name(
    declared: ToolDeclarations,
) -> None:
    answer = {"hits": [{"name": "resolve by hash", "area": "linking/runtime", "ttp": "T1027"}]}
    static = static_from_ledger([_entry(1, "match_rules", answer, "mcp:myscan")])
    assert static is not None
    assert static.api_technique_hits == [
        {
            "technique_id": "T1027",
            "name": "resolve by hash",
            "matched_apis": ["linking/runtime"],
            "source": "myrules",
            "kind": "capability_rules",
        }
    ]
    assert tool_kinds.hit_of_kind(static.api_technique_hits[0], "capability_rules")


# ---------------------------------------------------------------------------
# The recovery record and the published wording
# ---------------------------------------------------------------------------

C2 = "c2.example-evil.net"


def test_an_invented_emulator_s_recovery_is_stated_under_its_display_name(
    declared: ToolDeclarations,
) -> None:
    row = {"s": f"https://{C2}/gate", "how": "decoded", "at": "0x40", "fn": "0x10"}
    # A page of its rows: the record says it may not be whole, naming the emulator.
    answer = {"out": [row, {"s": "plain", "how": "static"}], "truncated": True}
    record = emulation_from_ledger([_entry(7, "emu_strings", answer, "mcp:myscan")])
    words = recovered_by_words(record, "domain", C2)
    assert words == "MyEmu, ev_0007 (decoded string, routine 0x10, called at 0x40)"
    assert "no MyEmu entry listed every string it recovered" in record.partial


def test_an_invented_decoder_s_value_names_the_decoder(declared: ToolDeclarations) -> None:
    answer = {"found": [{"t": f"http://{C2}/x"}]}
    record = emulation_from_ledger([_entry(9, "unblob", answer, "mcp:myscan")])
    report = _report(verdict="Malware", overall_confidence=0.9)
    said = emulation_kwargs(report, "domain", C2, record)
    assert said["recovered"].startswith(
        f"{DECODED_FROM_THE_BYTES_TEMPLATE.format(tool='Unblob')}, ev_0009"
    )


def test_a_lineage_dispute_names_the_sandbox_that_marked_it() -> None:
    said = disputed_flow_reason(["x.exe (procid 5)"], [], "AcmeBox")
    assert "which AcmeBox marks as the sample's" in said
    assert "Triage" not in said


# ---------------------------------------------------------------------------
# Linear time
# ---------------------------------------------------------------------------


def _routing_seconds(n: int) -> float:
    outputs = [_output("mcp:myrev", name, i) for i in range(n) for name in ("pseudo_c", "texts")]
    started = time.perf_counter()
    _filter_tool_outputs({"static": outputs}, "command_and_control")
    return time.perf_counter() - started


def test_routing_outputs_by_kind_is_linear(declared: ToolDeclarations) -> None:
    _routing_seconds(200)
    small = min(_routing_seconds(2_000) for _ in range(3))
    large = min(_routing_seconds(20_000) for _ in range(3))
    assert large < small * 30


def test_an_index_row_carries_the_source_only_when_recorded() -> None:
    assert "source" not in EvidenceIndexRow(id="ev_0001", tool="strings").model_dump()
    row = EvidenceIndexRow(id="ev_0001", tool="strings", source="pack")
    assert row.model_dump()["source"] == "pack"


# ---------------------------------------------------------------------------
# A re-render reads what the worker read
# ---------------------------------------------------------------------------


def _operator_settings() -> Settings:
    return Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "myrep": {
                        "command": "x",
                        "tool_facts": {
                            "lookup_hash": {
                                "kind": "reputation",
                                "reputation": {
                                    "service": "AcmeIntel",
                                    "stats": "/stats",
                                    "malicious": "/stats/malicious",
                                },
                                "display_name": "AcmeIntel",
                            }
                        },
                    },
                    "myrev": {"command": "y", "tool_facts": REVERSER_TOOLS},
                    "myscan": {"command": "z", "tool_facts": SCANNER_TOOLS},
                }
            }
        }
    )


def _rendered(report_json: str) -> tuple[str, str, list[str], list[str]]:
    from maljan.reporting.renderers.html import HtmlRenderer
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport.model_validate_json(report_json)
    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(MalwareReport.model_validate_json(report_json), nonce="fixed")
    bundle = bundle_for("command_and_control", report, report.technical_evidence)
    figures = [f.caption for f in build_code_listings(report)]
    return markdown, html, sorted(o["tool"] for o in bundle["tool_outputs"]), figures


def test_a_run_with_an_operator_server_renders_the_same_where_its_settings_are_absent() -> None:
    from maljan.core import declared_reading
    from maljan.core.config import get_settings, install_settings
    from maljan.reporting.models import EvidenceIndexRow

    previous = get_settings()
    # Written in the worker, under the operator's settings: each entry stores
    # its tool's facts, and the index rows and captured outputs carry them.
    install_settings(_operator_settings())
    declared_reading.forget()
    try:
        ledger = [
            build_entry(
                entry_id="ev_0001",
                seq=1,
                agent="pipeline",
                tool="lookup_hash",
                args={},
                server="myrep",
                output=json.dumps({"stats": {"malicious": 52, "undetected": 23}}),
                source="mcp:myrep",
            ),
            build_entry(
                entry_id="ev_0002",
                seq=2,
                agent="static",
                tool="pseudo_c",
                args={},
                server="myrev",
                output="int beacon(void) { return 1; }",
                source="mcp:myrev",
            ),
            build_entry(
                entry_id="ev_0003",
                seq=3,
                agent="static",
                tool="match_rules",
                args={},
                server="myscan",
                output=json.dumps({"hits": [{"name": "c2", "area": "comm", "ttp": "T1071"}]}),
                source="mcp:myscan",
            ),
        ]
        assert all(entry.facts and entry.facts.get("kind") for entry in ledger)
        report = _report(
            sections=build_sections(ledger),
            evidence_index=[
                EvidenceIndexRow(
                    id=e.id, agent=e.agent, tool=e.tool, source=e.source, facts=e.facts
                )
                for e in ledger
            ],
            technical_evidence={"static": [e.to_captured().model_dump() for e in ledger]},
        )
        stored = report.model_dump_json()
        in_the_worker = _rendered(stored)
    finally:
        install_settings(previous)
        declared_reading.forget()
    # Re-rendered by the API, which has none of the operator's servers.
    install_settings(Settings())
    declared_reading.forget()
    try:
        in_the_api = _rendered(stored)
    finally:
        install_settings(previous)
        declared_reading.forget()

    assert in_the_api == in_the_worker
    markdown, _html, outputs, figures = in_the_api
    assert "lookup_hash" in markdown
    assert "no reputation lookup in this run" not in markdown
    assert "pseudo_c" in outputs
    assert figures == ["Decompiled function"]


def _operator_ledger() -> list[Any]:
    return [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="pipeline",
            tool="lookup_hash",
            args={},
            server="myrep",
            output=json.dumps({"stats": {"malicious": 52, "undetected": 23}}),
            source="mcp:myrep",
        ),
        build_entry(
            entry_id="ev_0002",
            seq=2,
            agent="static",
            tool="pseudo_c",
            args={},
            server="myrev",
            output="int beacon(void) { return 1; }",
            source="mcp:myrev",
        ),
        build_entry(
            entry_id="ev_0003",
            seq=3,
            agent="static",
            tool="match_rules",
            args={},
            server="myscan",
            output=json.dumps({"hits": [{"name": "c2 over http", "area": "comm", "ttp": "T1071"}]}),
            source="mcp:myscan",
        ),
    ]


def test_the_built_report_carries_each_entry_s_facts_to_what_the_api_renders() -> None:
    """The report built from the ledger, as the worker builds it, re-renders the same anywhere.

    The builder copies each entry's stored facts onto its evidence index row,
    and the report step copies them onto the captured outputs
    (``LedgerEntry.to_captured``); the API, which has no operator settings,
    reads only those.
    """
    from maljan.core import declared_reading
    from maljan.core.config import get_settings, install_settings
    from maljan.reporting.builder import MalwareReportBuilder
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    previous = get_settings()
    install_settings(_operator_settings())
    declared_reading.forget()
    try:
        ledger = _operator_ledger()
        report = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name="fixture.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.9,
            malware_category="loader",
            evidence_ledger=ledger,
        ).build_deterministic()
        # As the report step attaches the captured tool evidence.
        report.technical_evidence = {"static": [e.to_captured().model_dump() for e in ledger]}
        stored = report.model_dump_json()
        in_the_worker = MarkdownRenderer().render(MalwareReport.model_validate_json(stored))
    finally:
        install_settings(previous)
        declared_reading.forget()

    install_settings(Settings())
    declared_reading.forget()
    try:
        served = MalwareReport.model_validate_json(stored)
        in_the_api = MarkdownRenderer().render(served)
        bundle = bundle_for("command_and_control", served, served.technical_evidence)
        figures = [f.caption for f in build_code_listings(served)]
    finally:
        install_settings(previous)
        declared_reading.forget()

    assert in_the_api == in_the_worker
    reputation = next(line for line in in_the_api.splitlines() if line.startswith("| Reputation |"))
    assert "lookup_hash, ev_0001" in reputation
    assert "no reputation lookup in this run" not in in_the_api
    assert "pseudo_c" in {o["tool"] for o in bundle["tool_outputs"]}
    assert figures == ["Decompiled function"]
    rows = {row.id: row for row in report.evidence_index}
    assert all(rows[e.id].facts == e.facts and rows[e.id].source == e.source for e in ledger)
