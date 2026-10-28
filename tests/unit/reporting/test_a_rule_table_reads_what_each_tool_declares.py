"""A rule table reads each row where its tool's declaration says, and names each row's tool.

Every column of a rule table first reads the value a tool declares under the
column's name, so a tool whose rows are shaped otherwise fills every column by
declaring where. A table that holds the rows of more than one tool says which
tool each row came from, and every reader of the table (the run comparison,
the narrative's rule pointer, the capability note) names each of them. Only
what the tool's source declared counts: a kind its own server merely claimed,
or one only its server said for a source that does not trust it, draws no
rule table. A stored report's emulator table is found by the kind and fields
its entry declares, from any server.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from maljan.core.declared_reading import FACTS_VERSION, SERVED_CLAIMS_KEY, SERVED_KEY
from maljan.reporting.ledger_report import (
    RULE_MATCHES_TITLE,
    TOOL_COLUMN,
    build_sections,
    rule_table_tools,
    section_key_of_kind,
)
from maljan.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.narrative_agent import rule_pointer
from maljan.reporting.renderers.markdown import _capability_tool
from maljan.reporting.renderers.stix_renderer import emulation_record
from maljan.reporting.run_diff import RunRecord, diff_runs
from maljan.schemas.evidence import build_entry

SIGNATURES = section_key_of_kind("signature_rules")


def _entry(n: int, tool: str, source: str, facts: dict[str, Any], answer: Any) -> Any:
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
    entry.facts = {"v": FACTS_VERSION, **facts}
    return entry


def _table(sections: list[EvidenceSection], key: str) -> EvidenceSection:
    (table,) = [s for s in sections if s.key == key]
    return table


def _report(sections: list[EvidenceSection], **over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), sections=sections, **over
    )


def _detection_rows(sections: list[EvidenceSection]) -> list[dict[str, Any]]:
    record = RunRecord(
        report_id="a", job_id="a", malware_report=_report(sections).model_dump(mode="json")
    )
    other = RunRecord(report_id="b", job_id="b", malware_report={"sections": []})
    (detection,) = [s for s in diff_runs(record, other)["sections"] if s["key"] == "detection"]
    return list(detection["rows"])


# ---------------------------------------------------------------------------
# Every column reads its declared value first
# ---------------------------------------------------------------------------


def test_a_signature_rule_row_is_read_where_its_tool_declares() -> None:
    entry = _entry(
        1,
        "scan",
        "mcp:shapes",
        {
            "kind": "signature_rules",
            "rows": "/hits/*",
            "values": {"rule": "/name", "where": "/loc", "tags": "/labels"},
            "display_name": "Shapes",
        },
        {"hits": [{"name": "B", "loc": "0x10", "labels": ["lb"]}]},
    )
    table = _table(build_sections([entry]), SIGNATURES)
    assert table.columns == ["Rule", "Tags", "Where"]
    assert table.rows == [["B", "lb", "0x10"]]


def test_an_event_rule_row_is_read_where_its_tool_declares() -> None:
    entry = _entry(
        1,
        "events",
        "mcp:shapes",
        {
            "kind": "event_rules",
            "rows": "/fired/*",
            "values": {"title": "/caption", "level": "/sev", "matched_fields": "/hit_on"},
            "display_name": "Shapes",
        },
        {"fired": [{"caption": "Run key", "sev": "high", "hit_on": "TargetObject"}]},
    )
    table = _table(build_sections([entry]), section_key_of_kind("event_rules"))
    assert table.columns == ["Rule", "Level", "Technique", "Matched fields"]
    assert table.rows == [["Run key", "high", "", "TargetObject"]]


def test_a_capability_row_is_read_where_its_tool_declares() -> None:
    entry = _entry(
        1,
        "abilities",
        "mcp:shapes",
        {
            "kind": "capability_rules",
            "rows": "/found/*",
            "values": {"rule": "/what", "namespace": "/area", "mbc": "/behaviour"},
            "display_name": "Shapes",
        },
        {"found": [{"what": "create process", "area": "host/process", "behaviour": "E1"}]},
    )
    table = _table(build_sections([entry]), section_key_of_kind("capability_rules"))
    assert table.columns == ["Namespace", "Rule", "ATT&CK", "MBC"]
    assert table.rows == [["host/process", "create process", "", "E1"]]


# ---------------------------------------------------------------------------
# Only what the source declared draws a rule table
# ---------------------------------------------------------------------------

_MATCHES = {"matches": [{"rule": "Evil_Rule", "tags": ["x"], "strings": [1]}]}


def test_a_kind_its_server_only_claimed_draws_no_rule_table() -> None:
    claimed = _entry(
        1,
        "t1",
        "mcp:evil",
        {SERVED_CLAIMS_KEY: {"kind": "signature_rules", "rows": "/matches/*"}},
        _MATCHES,
    )
    sections = build_sections([claimed])
    assert SIGNATURES not in [s.key for s in sections]
    assert _detection_rows(sections) == []


def test_a_kind_only_an_untrusted_server_said_draws_no_rule_table() -> None:
    said = _entry(
        1,
        "t2",
        "mcp:evil",
        {
            "kind": "signature_rules",
            "rows": "/matches/*",
            "display_name": "Evil",
            SERVED_KEY: ["kind", "display_name"],
        },
        _MATCHES,
    )
    sections = build_sections([said])
    assert SIGNATURES not in [s.key for s in sections]
    assert _detection_rows(sections) == []


# ---------------------------------------------------------------------------
# A table of several tools names each row's tool
# ---------------------------------------------------------------------------


def _two_tools() -> list[Any]:
    alpha = _entry(
        1,
        "scan_a",
        "mcp:a",
        {"kind": "signature_rules", "display_name": "Alpha", "rows": "/matches/*"},
        {"matches": [{"rule": "Evil_Rule", "tags": ["x"], "strings": [1]}]},
    )
    beta = _entry(
        2,
        "scan_b",
        "mcp:b",
        {
            "kind": "signature_rules",
            "display_name": "Beta",
            "rows": "/hits/*",
            "values": {"rule": "/name", "where": "/loc", "tags": "/labels"},
        },
        {"hits": [{"name": "B_rule", "loc": "0x10", "labels": ["lb"]}]},
    )
    return [alpha, beta]


def test_one_tool_s_table_has_no_tool_column() -> None:
    table = _table(build_sections(_two_tools()[:1]), SIGNATURES)
    assert TOOL_COLUMN not in table.columns
    assert table.title == "Alpha rule matches"


def test_a_table_of_two_tools_names_each_row_s_tool() -> None:
    sections = build_sections(_two_tools())
    table = _table(sections, SIGNATURES)

    assert table.columns == ["Rule", "Tags", "Where", TOOL_COLUMN]
    assert table.rows == [["Evil_Rule", "x", "1", "Alpha"], ["B_rule", "lb", "0x10", "Beta"]]
    assert table.title == "Alpha and Beta rule matches"
    assert table.evidence_ids == ["ev_0001", "ev_0002"]
    assert rule_table_tools(table, RULE_MATCHES_TITLE) == ["Alpha", "Beta"]

    labels = [row["label"] for row in _detection_rows(sections)]
    assert labels == ["alpha: Evil_Rule", "beta: B_rule"]
    assert "alpha/beta" in rule_pointer(SimpleNamespace(sections=sections))


def test_the_capability_note_names_every_tool_of_its_table() -> None:
    facts = {"kind": "capability_rules", "rows": "/capabilities/*"}
    answer = {"capabilities": [{"namespace": "n", "rule": "r"}]}
    ledger = [
        _entry(1, "one", "mcp:a", {**facts, "display_name": "Alpha"}, answer),
        _entry(2, "two", "mcp:b", {**facts, "display_name": "Beta"}, answer),
    ]
    assert _capability_tool(_report(build_sections(ledger))) == "Alpha and Beta"
    assert _capability_tool(_report(build_sections(ledger[:1]))) == "Alpha"


# ---------------------------------------------------------------------------
# A stored report's emulator table, from any server
# ---------------------------------------------------------------------------


def test_a_new_server_s_emulator_table_is_read_by_its_declared_fields() -> None:
    facts = {
        "v": FACTS_VERSION,
        "kind": "emulated_strings",
        "rows": "/out/*",
        "values": {"text": "/txt", "scheme": "/how"},
    }
    for source in ({"source": "tool:rec"}, {}):
        section = EvidenceSection(
            key="tool_rec_out",
            title="Rec: out",
            kind="table",
            columns=["how", "txt"],
            rows=[["decoded", "evil.example.net"], ["static", "x"]],
            evidence_ids=["ev_0001"],
            **source,
        )
        row = EvidenceIndexRow(
            id="ev_0001", agent="pipeline", tool="rec", ok=True, source="mcp:newsrv", facts=facts
        )
        record = emulation_record(_report([section], evidence_index=[row]))
        assert record.values == {"evil.example.net": "ev_0001"}, source
