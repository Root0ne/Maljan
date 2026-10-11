"""The report reads a tool by the kind it declares, from any server, never by its name.

An invented reverser and an invented rule scanner, declared only as data in
``mcp.servers``, get every treatment the built-in tools of the same kinds get:
the composer's technical sections, "Functions examined", the code-listing
figures, the rule tables, the technique hits, the recovery record. A tool that
shares a built-in's name on a server that declares nothing gets nothing from
the built-in.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

import pytest

from maljan.core.config import Settings
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
    monkeypatch.setattr(tool_kinds, "declarations", lambda: held)
    yield held


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), **over)


def _output(source: str, tool: str, n: int = 0) -> dict[str, Any]:
    return {
        "agent_id": "static",
        "tool_name": tool,
        "args": {},
        "symbol": f"fn_{n}",
        "output": f"answer of {tool}",
        "seq": n,
        "source": source,
    }


def _entry(n: int, tool: str, answer: Any, source: str | None) -> Any:
    return build_entry(
        entry_id=f"ev_{n:04d}",
        seq=n,
        agent="static",
        tool=tool,
        args={},
        server=None,
        output=json.dumps(answer),
        source=source,
    )


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


def test_a_built_in_name_on_a_server_that_declares_nothing_is_shown_nowhere(
    declared: ToolDeclarations,
) -> None:
    outputs = [_output("mcp:plain", "decompile_function"), _output("mcp:plain", "list_strings")]
    for section in _SECTION_KINDS:
        assert _received(section, outputs) == set()


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
    monkeypatch.setattr(tool_kinds, "declarations", lambda: held)
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
    assert examined.evidence_ids == ["ev_0001", "ev_0002"]
    # The built-in's name on a server that declares nothing is a generic block.
    assert sections["tool_decompile_function"].evidence_ids == ["ev_0003"]


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
    assert [f.caption for f in figures] == ["Decompiled fn_0"]


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
    monkeypatch.setattr(tool_kinds, "declarations", lambda: held)
    sections = build_sections([_entry(1, "who", {"label": "a thing"}, "mcp:mine")])
    assert any("ev_0001" in s.evidence_ids for s in sections)


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
        }
    ]
    assert "myrules" in tool_kinds.sources_of_kind("capability_rules")


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
