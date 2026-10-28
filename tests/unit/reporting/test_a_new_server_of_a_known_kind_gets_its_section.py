"""A new server's tool of a known kind and answer shape is drawn as the built-in is.

The report keys a tool's section on what its answer is (its declared kind and
the fields its declaration reads), never on the tool's or the server's name.
A tool on an invented server that declares the same kind and answer shape as
a built-in one gets the same section (its key, columns and rows), titled by
its own display name, and the same treatment downstream: the renderer's rule
tables, the run comparison's detection rows, the reputation counts. No code
names the new server or its tools. A tool its server declares nothing for is
drawn in full, in the generic block of its own, as before.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.declared_reading import facts_record
from maljan.core.reputation import reputation_of
from maljan.core.tool_declarations import ToolDeclarations
from maljan.reporting.ledger_report import RULE_TABLES, build_sections, section_key_of_kind
from maljan.reporting.models import EvidenceSection
from maljan.reporting.renderers.markdown import _capability_rules, _capability_tool
from maljan.reporting.run_diff import RunRecord, detection_sections, diff_runs
from maljan.schemas.evidence import build_entry

# The built-in tool of each kind the invented server's tool copies, by source.
BUILT_IN: dict[str, tuple[str, str]] = {
    "signature_rules": ("pack", "yara_scan"),
    "event_rules": ("pack", "sigma_match_sandbox"),
    "capability_rules": ("pack", "capa"),
    "reputation": ("mcp:virustotal", "get_file_report"),
}

# The invented server's tool of each kind: a name nothing in the code knows.
INVENTED: dict[str, str] = {
    "signature_rules": "sweep_patterns",
    "event_rules": "events_against_rules",
    "capability_rules": "what_it_can_do",
    "reputation": "ask_about_hash",
}
SERVER = "never_seen_before"
DISPLAY = "Brandnew"

# One answer per kind, in the shape the built-in tool of the kind answers.
ANSWERS: dict[str, dict[str, Any]] = {
    "signature_rules": {
        "matches": [
            {"rule": "Packed_UPX", "tags": ["packer"], "strings": [{"offset": 64}]},
            {"rule": "Has_Url", "tags": [], "strings": [{"offset": 512}]},
        ]
    },
    "event_rules": {
        "matches": [
            {
                "rule": "r-1",
                "title": "Run key written",
                "level": "high",
                "tags": ["attack.persistence", "attack.t1547.001"],
                "matched_fields": {"TargetObject": "HKCU\\Run\\x"},
            }
        ]
    },
    "capability_rules": {
        "capabilities": [
            {
                "namespace": "host-interaction/process/create",
                "rule": "create process",
                "attck": ["Execution::Native API [T1106]"],
                "mbc": [],
            }
        ]
    },
    "reputation": {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 41,
                    "suspicious": 0,
                    "undetected": 20,
                    "harmless": 0,
                },
                "meaningful_name": "sample.exe",
            }
        }
    },
}


@pytest.fixture
def declared() -> Iterator[ToolDeclarations]:
    """The shipped declarations, and the invented server declaring the built-ins' facts."""
    shipped = ToolDeclarations.from_settings(Settings())
    facts: dict[str, Any] = {}
    for kind, (source, tool) in BUILT_IN.items():
        held = shipped.source(source)
        assert held is not None and tool in held.tools, (source, tool)
        copied = held.tools[tool].model_dump(mode="json", exclude_defaults=True)
        copied["display_name"] = DISPLAY
        facts[INVENTED[kind]] = copied
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    SERVER: {"command": "x", "tool_facts": facts},
                    "says_nothing": {"command": "y"},
                }
            }
        }
    )
    yield ToolDeclarations.from_settings(settings)


def _entry(declared: ToolDeclarations, source: str, tool: str, answer: Any, n: int = 1) -> Any:
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
    entry.facts = facts_record(source, tool, declared=declared)
    return entry


def _drawn(sections: list[EvidenceSection]) -> list[tuple[Any, ...]]:
    """Each section past the identity block, as what it holds: key, kind, columns, rows, items."""
    return [
        (s.key, s.kind, list(s.columns), [list(r) for r in s.rows], list(s.items))
        for s in sections
        if s.key != "identity"
    ]


@pytest.mark.parametrize("kind", sorted(RULE_TABLES))
def test_a_new_rule_tool_is_drawn_in_its_kind_s_table(
    declared: ToolDeclarations, kind: str
) -> None:
    source, tool = BUILT_IN[kind]
    built_in = build_sections([_entry(declared, source, tool, ANSWERS[kind])])
    mine = build_sections([_entry(declared, f"mcp:{SERVER}", INVENTED[kind], ANSWERS[kind])])

    assert _drawn(mine) == _drawn(built_in)
    (table,) = [s for s in mine if s.key == section_key_of_kind(kind)]
    assert table.rows, kind
    assert table.title.startswith(DISPLAY)
    assert table.columns == [column.heading for column in RULE_TABLES[kind].columns]
    assert table.evidence_ids == ["ev_0001"]


def test_the_renderer_and_the_comparison_read_the_new_tool_s_tables(
    declared: ToolDeclarations,
) -> None:
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

    ledger = [
        _entry(declared, f"mcp:{SERVER}", INVENTED[kind], ANSWERS[kind], n)
        for n, kind in enumerate(sorted(RULE_TABLES), start=1)
    ]
    sections = build_sections(ledger)
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), sections=sections
    )

    rules = _capability_rules(report)
    assert [rule["rule"] for rule, _ids in rules] == ["create process"]
    assert _capability_tool(report) == DISPLAY

    keys = {s.key for s in sections}
    assert set(detection_sections()) <= keys
    record = RunRecord(report_id="a", job_id="a", malware_report=report.model_dump(mode="json"))
    other = RunRecord(report_id="b", job_id="b", malware_report={"sections": []})
    diff = diff_runs(record, other)
    (detection,) = [s for s in diff["sections"] if s["key"] == "detection"]
    labels = {row["label"] for row in detection["rows"]}
    assert f"{DISPLAY.lower()}: Packed_UPX" in labels
    assert f"{DISPLAY.lower()}: Run key written" in labels
    assert f"{DISPLAY.lower()}: create process" in labels


def test_a_new_reputation_lookup_gets_the_counts_the_built_in_gets(
    declared: ToolDeclarations,
) -> None:
    source, tool = BUILT_IN["reputation"]
    built_in_entry = _entry(declared, source, tool, ANSWERS["reputation"])
    mine_entry = _entry(declared, f"mcp:{SERVER}", INVENTED["reputation"], ANSWERS["reputation"])

    theirs, mine = reputation_of(built_in_entry), reputation_of(mine_entry)
    assert mine is not None and theirs is not None
    assert (mine.malicious, mine.engine_count()) == (theirs.malicious, theirs.engine_count())

    def rows(entry: Any) -> list[list[str]]:
        (section,) = [s for s in build_sections([entry]) if s.key == f"tool_{entry.tool}"]
        return [list(r) for r in section.rows]

    # One generic block per tool, as the answer is its tool's own shape, and
    # the engine counts the lookup's kind adds to it, the same for both.
    assert rows(mine_entry) == rows(built_in_entry)
    assert ["engines malicious", "41"] in rows(mine_entry)


def test_an_undeclared_tool_keeps_its_whole_answer_in_its_own_block(
    declared: ToolDeclarations,
) -> None:
    answer = ANSWERS["signature_rules"]
    entry = _entry(declared, "mcp:says_nothing", "sweep_patterns", answer)
    sections = build_sections([entry])

    keys = [s.key for s in sections if s.key != "identity"]
    assert section_key_of_kind("signature_rules") not in keys
    assert keys == ["tool_sweep_patterns", "tool_sweep_patterns_matches"]
    (table,) = [s for s in sections if s.key == "tool_sweep_patterns_matches"]
    assert [row[0] for row in table.rows] == ["Packed_UPX", "Has_Url"]
