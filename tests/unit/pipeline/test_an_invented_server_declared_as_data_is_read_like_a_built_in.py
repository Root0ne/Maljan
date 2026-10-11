"""A server declared only as data is read end to end as a built-in of the same kind is.

``scanner`` is an invented rule matcher whose ``scan`` tool declares the kind
of the built-in signature scan and asserts techniques; its ``locate`` tool
declares a kind no reader knows, with rows and places. ``lookalike`` names a
tool ``capa`` and declares nothing. The scan's entry asserts its technique,
is placed as a built-in scan's entry is, opens a rule-match section, names its
matcher in a sentence that only reports a match, fills the function map's
input of its kind and is a rule layer; ``locate`` is placed by its declared
rows; the look-alike ``capa`` gets nothing from the built-in ``capa``.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings
from maljan.schemas.evidence import build_entry

SCAN_ANSWER = (
    '{"matches": [{"rule": "Loader_Generic", "meta": {"technique_id": "T1055"}, '
    '"strings": [{"identifier": "$a", "offset": 4160}]}], "rule_count": 1, "filtered": 0}'
)
CAPA_ANSWER = (
    '{"capabilities": [{"namespace": "x", "rule": "inject code", '
    '"attck": ["Defense Evasion::Process Injection [T1055]"], "addresses": ["0x401000"]}]}'
)
LOCATE_ANSWER = '{"hits": [{"where": "0x401040", "label": "cfg"}]}'

SCANNER = {
    "command": "invented-scanner",
    "enabled": True,
    "tool_facts": {
        "scan": {
            "kind": "signature_rules",
            "asserts_techniques": True,
            "source": "scanner",
            "rows": "/matches/*",
            "places": {"offset": "/strings/*/offset"},
            "values": {"rule": "/rule"},
            "techniques": [{"path": "/**6/technique_id"}],
            "words": ["scanner"],
            "display_name": "ScanEngine",
        },
        "locate": {
            "kind": "located_values",
            "rows": "/hits/*",
            "places": {"address": "/where"},
            "values": {"text": "/label"},
        },
        "recover": {"kind": "emulated_strings"},
    },
}


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    held = Settings()
    held.mcp.servers["scanner"] = MCPServerConfig.model_validate(SCANNER)
    held.mcp.servers["lookalike"] = MCPServerConfig.model_validate({"command": "lookalike"})
    monkeypatch.setattr(config_module, "_settings_instance", held)
    return held


def _entry(entry_id: str, tool: str, source: str, output: str, **args: Any) -> Any:
    seq = int(entry_id.rsplit("_", 1)[1])
    return build_entry(
        entry_id=entry_id, seq=seq, agent="static", tool=tool, args=args, server=None,
        output=output, source=source,
    )  # fmt: skip


def _ledger() -> list[Any]:
    return [
        _entry("ev_0001", "scan", "mcp:scanner", SCAN_ANSWER),
        _entry("ev_0002", "yara_scan", "mcp:analysis", SCAN_ANSWER),
        _entry("ev_0003", "capa", "mcp:lookalike", CAPA_ANSWER),
        _entry("ev_0004", "locate", "mcp:scanner", LOCATE_ANSWER),
    ]


def test_the_scan_asserts_its_technique_and_the_lookalike_does_not(settings: Settings) -> None:
    from maljan.pipeline.evidence_summary import asserting_labels, collect, technique_evidence

    ledger = _ledger()
    assert ("scan", None) in collect(None, ledger)["T1055"]
    assert all(name != "capa" for name, _ in collect(None, ledger)["T1055"])
    assert technique_evidence(None, ledger)["T1055"] == ["ev_0001", "ev_0002"]
    assert asserting_labels(ledger) == {"scan": "scanner", "yara_scan": "yara"}


def test_the_corroboration_names_the_scan_by_its_declared_source(settings: Settings) -> None:
    from maljan.pipeline.validation import corroboration

    row = corroboration(None, _ledger())["T1055"]
    assert row["asserted_by"] == ["scanner", "yara"]


def test_the_scan_is_placed_as_a_built_in_scan_is(settings: Settings) -> None:
    from maljan.analysis.evidence_roots import NOTHING_TO_PLACE, RunRoots

    roots = RunRoots(_ledger())
    scan, builtin = roots.entries["ev_0001"], roots.entries["ev_0002"]
    assert scan.roots == builtin.roots and scan.roots
    assert scan.by_technique == builtin.by_technique
    lookalike = roots.entries["ev_0003"]
    assert lookalike.roots == []
    assert lookalike.reason == NOTHING_TO_PLACE.format(tool="capa")
    located = roots.entries["ev_0004"]
    assert located.roots and "cfg" in located.by_value


def test_a_section_opened_by_the_scan_is_a_rule_match(settings: Settings) -> None:
    from maljan.pipeline.validation import (
        _RULE_MATCH_SECTIONS,
        CapabilityGrounding,
        _section_reads_as,
    )

    class Section:
        def __init__(self, source: str, cited: str) -> None:
            self.source, self.evidence_ids = source, [cited]

    by_id = {e.id: e for e in _ledger()}
    assert _section_reads_as(Section("tool:scan", "ev_0001"), _RULE_MATCH_SECTIONS, by_id)
    assert not _section_reads_as(Section("tool:capa", "ev_0003"), _RULE_MATCH_SECTIONS, by_id)
    # Handed no ledger, a section is read by the name it records.
    assert _section_reads_as(Section("tool:capa", "ev_0003"), _RULE_MATCH_SECTIONS, {})

    class Report:
        sections = [
            type("S", (), {"key": "k", "title": "keylogging", "source": "tool:scan",
                           "evidence_ids": ["ev_0001"], "rows": [], "text": ""})(),
        ]  # fmt: skip

    grounding = CapabilityGrounding.from_report(Report(), None, ledger=_ledger())
    assert "keylogging" not in grounding.evidence_text
    assert "scanengine" in grounding.matchers


def test_a_sentence_reporting_the_scans_match_claims_nothing(settings: Settings) -> None:
    from maljan.pipeline.validation import _says_only_that_a_rule_matched, matcher_names

    names = matcher_names()
    assert {"capa", "yara", "scanengine"} <= set(names)
    assert _says_only_that_a_rule_matched("ScanEngine flagged Loader_Generic", names)
    assert not _says_only_that_a_rule_matched("ScanEngine flagged Loader_Generic")


def test_the_words_a_statement_names_the_scan_by_are_declared(settings: Settings) -> None:
    from maljan.pipeline.validation import entry_words

    ledger = _ledger()
    assert "scanner" in entry_words(ledger[0])
    assert "rules" not in entry_words(ledger[0])


def test_the_function_map_and_index_read_inputs_by_kind(settings: Settings) -> None:
    from maljan.agents.function_map import _map_kind
    from maljan.pipeline.triage_pack import _index_slot

    recover = _entry("ev_0005", "recover", "mcp:scanner", '{"strings": []}')
    floss_lookalike = _entry("ev_0006", "floss", "mcp:lookalike", '{"strings": []}')
    assert _map_kind(recover) == "emulated_strings"
    assert _map_kind(floss_lookalike) == ""
    assert _index_slot(recover) == "floss"
    assert _index_slot(floss_lookalike) == ""


def test_the_scan_is_a_rule_layer(settings: Settings) -> None:
    from maljan.analysis.run_summary import _rule_layers

    assert "scanner" in _rule_layers()
