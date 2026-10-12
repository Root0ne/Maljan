"""An undeclared tool's output goes where the analysts cited it, in the composer and the console.

The composer shows a technical section the captured outputs of the kinds it
reads. A tool its source declares nothing for has no kind, so its output
reached no section. Now a section whose claims cite the output's entry is
shown it: the analyst's citation routes it. Routing only: the grounding the
composer checks a section against is built from the report, the analysts'
answers and the ledger, never from a bundle, so a citation adds no grounding.

The console places a section an operator's tool produced by the kind its tool
declared, else by the analyst whose call it cites, so it is drawn on a tab and
not only in the EVIDENCE footer. Built-in sections keep their placement, and a
stored run of built-in tools places nothing.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.reporting.evidence_bundles import _SECTION_KINDS, bundle_for
from maljan.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.section_tabs import section_tabs

OPERATOR = "mcp:invented"
UNDECLARED = {"v": 1}


def _capture(
    tool: str, seq: int, *, source: str | None = OPERATOR, facts: Any = UNDECLARED
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "agent_id": "static",
        "tool_name": tool,
        "args": {},
        "symbol": None,
        "output": f"{tool} answered",
        "seq": seq,
    }
    if source is not None:
        out["source"] = source
    if facts is not None:
        out["facts"] = facts
    return out


def _row(
    entry_id: str, tool: str, *, agent: str = "static", role: str | None = "static", **over: Any
) -> EvidenceIndexRow:
    return EvidenceIndexRow(
        id=entry_id,
        agent=agent,
        tool=tool,
        source=over.get("source", OPERATOR),
        facts=over.get("facts", UNDECLARED),
        agent_role=role,
    )


def _isr(*claims: tuple[str, str]) -> dict[str, Any]:
    return {
        "static": SimpleNamespace(
            agent_id="static",
            claims=[
                SimpleNamespace(claim=c, evidence_ref=ref, confidence=0.8) for c, ref in claims
            ],
        )
    }


def _report(captures: list[dict[str, Any]], rows: list[EvidenceIndexRow]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"static": captures},
        evidence_index=rows,
    )


def _shown(section: str, report: MalwareReport, isr: dict[str, Any]) -> list[str]:
    return [o["tool"] for o in bundle_for(section, report, None, isr)["tool_outputs"]]


# ---------------------------------------------------------------------------
# The composer
# ---------------------------------------------------------------------------


def test_a_cited_undeclared_output_reaches_exactly_the_sections_its_claim_feeds() -> None:
    report = _report([_capture("read_autoruns", 4)], [_row("ev_0005", "read_autoruns")])
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    fed = {
        section for section in _SECTION_KINDS if _shown(section, report, isr) == ["read_autoruns"]
    }
    fed_by_the_claim = {
        section
        for section in _SECTION_KINDS
        if any(
            "ev_0005" in c["evidence_ref"] for c in bundle_for(section, report, None, isr)["claims"]
        )
    }
    assert fed == fed_by_the_claim
    assert "persistence_detail" in fed
    assert "discovery" not in fed


def test_an_uncited_undeclared_output_reaches_no_section() -> None:
    report = _report([_capture("read_autoruns", 4)], [_row("ev_0005", "read_autoruns")])
    isr = _isr(("The sample persists through a run key.", "ev_0009"))
    for section in _SECTION_KINDS:
        assert _shown(section, report, isr) == []


def test_a_citation_in_the_claim_text_routes_as_one_in_the_evidence() -> None:
    report = _report([_capture("read_autoruns", 4)], [_row("ev_0005", "read_autoruns")])
    isr = _isr(("The sample persists through a run key (ev_0005).", "the autoruns listing"))
    assert _shown("persistence_detail", report, isr) == ["read_autoruns"]


@pytest.mark.parametrize(
    "row",
    [
        _row("ev_0005", "another_tool"),
        _row("ev_0005", "read_autoruns", agent="dynamic"),
    ],
)
def test_an_output_the_index_does_not_hold_under_its_entry_is_not_routed(row: Any) -> None:
    report = _report([_capture("read_autoruns", 4)], [row])
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    assert _shown("persistence_detail", report, isr) == []


def test_a_report_with_no_index_row_for_the_entry_routes_nothing() -> None:
    report = _report([_capture("read_autoruns", 4)], [])
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    assert _shown("persistence_detail", report, isr) == []


@pytest.mark.parametrize("seq", [None, "4", -1, True])
def test_an_output_that_carries_no_call_number_is_not_routed(seq: Any) -> None:
    capture = _capture("read_autoruns", 0)
    if seq is None:
        del capture["seq"]
    else:
        capture["seq"] = seq
    report = _report(
        [capture], [_row("ev_0001", "read_autoruns"), _row("ev_0005", "read_autoruns")]
    )
    isr = _isr(("The sample persists through a run key.", "ev_0001 ev_0005"))
    assert _shown("persistence_detail", report, isr) == []


def test_a_declared_output_is_routed_by_its_kind_alone() -> None:
    declared = {"v": 1, "kind": "crypto_constants"}
    report = _report(
        [_capture("find_constants", 4, facts=declared)],
        [_row("ev_0005", "find_constants", facts=declared)],
    )
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    assert _shown("persistence_detail", report, isr) == []
    assert _shown("encryption_scheme", report, isr) == ["find_constants"]


def test_an_output_with_no_recorded_source_is_routed_by_its_name_as_before() -> None:
    report = _report(
        [_capture("read_autoruns", 4, source=None, facts=None)],
        [_row("ev_0005", "read_autoruns", source=None, facts=None)],
    )
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    assert _shown("persistence_detail", report, isr) == []


def test_routing_leaves_the_claims_and_the_report_unchanged() -> None:
    report = _report([_capture("read_autoruns", 4)], [_row("ev_0005", "read_autoruns")])
    before = report.model_dump_json()
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    cited = bundle_for("persistence_detail", report, None, isr)
    uncited = bundle_for("persistence_detail", report, None, _isr(("persists", "ev_0009")))
    assert report.model_dump_json() == before
    assert cited["facts"] == uncited["facts"]
    assert cited["binary"] == uncited["binary"]


def test_the_sections_with_no_tool_outputs_still_show_none() -> None:
    report = _report([_capture("read_autoruns", 4)], [_row("ev_0005", "read_autoruns")])
    isr = _isr(("The sample persists through a run key.", "ev_0005"))
    for section in ("executive_summary", "introduction", "execution_flow", "mitigations"):
        assert bundle_for(section, report, None, isr)["tool_outputs"] == []


# ---------------------------------------------------------------------------
# The console tab
# ---------------------------------------------------------------------------


def _section(key: str, ids: list[str], source: str = "tool:x") -> EvidenceSection:
    return EvidenceSection(key=key, title=key, evidence_ids=ids, source=source, text="t")


def _placed(sections: list[EvidenceSection], rows: list[EvidenceIndexRow]) -> dict[str, str]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=sections,
        evidence_index=rows,
    )
    by_model = section_tabs(report)
    assert section_tabs(json.loads(report.model_dump_json())) == by_model
    return by_model


def test_an_undeclared_section_is_placed_by_the_role_of_the_agent_whose_call_it_cites() -> None:
    section = [_section("tool_x", ["ev_0001"])]
    assert _placed(section, [_row("ev_0001", "x")]) == {"tool_x": "static"}
    # A renamed or cloned agent places by its declared role, never its name.
    assert _placed(section, [_row("ev_0001", "x", agent="reverser", role="static")]) == {
        "tool_x": "static"
    }
    assert _placed(section, [_row("ev_0001", "x", agent="pcap_reader", role="network")]) == {
        "tool_x": "network"
    }
    # The judge's own lookups are drawn where the sample's identity is.
    assert _placed(section, [_row("ev_0001", "x", agent="judge", role="judge")]) == {
        "tool_x": "identity"
    }
    # An agent named like a tab, whose role names none, places nothing.
    assert _placed(section, [_row("ev_0001", "x", agent="static", role="generic")]) == {}


@pytest.mark.parametrize(
    ("facts", "tab"),
    [
        ({"v": 1, "kind": "sandbox_processes"}, "dynamic"),
        ({"v": 1, "kind": "pcap"}, "network"),
        ({"v": 1, "kind": "reputation"}, "identity"),
        ({"v": 1, "kind": "decompile"}, "static"),
        ({"v": 1, "kind": "signature_rules"}, "static"),
    ],
)
def test_an_accepted_declaration_places_the_section_by_its_kind(facts: Any, tab: str) -> None:
    rows = [_row("ev_0001", "x", agent="lead", role="lead", facts=facts)]
    assert _placed([_section("tool_x", ["ev_0001"])], rows) == {"tool_x": tab}


@pytest.mark.parametrize(
    "facts",
    [{"v": 1, "kind": "unclassified"}, {"v": 1, "kind": "a_kind_no_tab_reads"}, {"v": 1}],
)
def test_a_kind_no_tab_reads_falls_back_to_the_agent_s_role(facts: Any) -> None:
    rows = [_row("ev_0001", "x", agent="mine", role="dynamic", facts=facts)]
    assert _placed([_section("tool_x", ["ev_0001"])], rows) == {"tool_x": "dynamic"}


@pytest.mark.parametrize(
    ("sections", "rows"),
    [
        # An entry written without a role (a stored run), declaring nothing.
        ([_section("tool_x", ["ev_0001"])], [_row("ev_0001", "x", role=None)]),
        # Two roles' calls in one section.
        (
            [_section("tool_x", ["ev_0001", "ev_0002"])],
            [_row("ev_0001", "x"), _row("ev_0002", "x", role="dynamic")],
        ),
        # A cited entry the index does not hold.
        ([_section("tool_x", ["ev_0001", "ev_0009"])], [_row("ev_0001", "x")]),
        # A built-in source keeps the key map's placement.
        ([_section("tool_x", ["ev_0001"])], [_row("ev_0001", "x", source="mcp:analysis")]),
        # An entry written before sources.
        ([_section("tool_x", ["ev_0001"])], [_row("ev_0001", "x", source=None, facts=None)]),
        # A section an analyst wrote, not one built from tool answers.
        ([_section("artifact_x", ["ev_0001"], source="agent:static")], [_row("ev_0001", "x")]),
    ],
)
def test_what_neither_reading_places_is_left_to_the_key_map(
    sections: list[EvidenceSection], rows: list[EvidenceIndexRow]
) -> None:
    assert _placed(sections, rows) == {}


def test_no_agent_name_places_a_section() -> None:
    """Placement reads the stored role, never an agent's name, through the role vocabulary."""
    import ast
    import inspect
    from typing import get_args

    from maljan.core.config import AnalystRole
    from maljan.reporting import section_tabs as module

    assert set(module.TAB_OF_ROLE) <= set(get_args(AnalystRole))
    tree = ast.parse(inspect.getsource(module))
    read_fields = {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "_field"
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Constant)
    }
    assert "agent" not in read_fields
    assert "agent_role" in read_fields


def test_an_entry_records_its_agent_s_declared_role(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.agents.evidence_recorder import EvidenceRecorder

    recorder = EvidenceRecorder("reverser", agent_role="static")
    entry = recorder.record(tool="x", args={}, output="answer", server="invented")
    assert entry.agent_role == "static"
    assert json.loads(entry.model_dump_json())["agent_role"] == "static"
    bare = EvidenceRecorder("pack").record(tool="x", args={}, output="answer", server=None)
    assert "agent_role" not in json.loads(bare.model_dump_json())


def test_an_agent_reads_its_role_from_its_definition_whatever_its_name() -> None:
    from maljan.agents.composition import role_of
    from maljan.core.config import Settings

    settings = Settings()
    assert role_of(settings, "judge") == "judge"
    assert role_of(settings, "static") == "static"
    assert role_of(settings, "no_such_agent") is None
    clone = settings.agents.definitions["static"].model_copy()
    settings.agents.definitions["reverser"] = clone
    assert role_of(settings, "reverser") == "static"


@pytest.mark.parametrize("odd", [None, {}, {"sections": "x"}, {"sections": [1, {"key": 3}]}])
def test_a_stored_report_of_an_odd_shape_places_nothing(odd: Any) -> None:
    assert section_tabs(odd) == {}


@pytest.mark.parametrize("run", ["run7", "run5", "run4", "local8"])
def test_a_stored_run_of_built_in_tools_places_nothing(run: str) -> None:
    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    assert section_tabs(json.loads((root / run / "report.json").read_text())) == {}


def test_the_served_report_carries_the_placements() -> None:
    import asyncio

    from app.api.v1.reports import _detail

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=[_section("tool_x", ["ev_0001"])],
        evidence_index=[_row("ev_0001", "x", agent="dynamic", role="dynamic")],
    )

    def _row_of(malware_report: Any) -> Any:
        return SimpleNamespace(
            id=uuid.uuid4(),
            job_id=uuid.uuid4(),
            verdict="Suspicious",
            overall_confidence=None,
            malware_category=None,
            stix_bundle=None,
            mitre_techniques=None,
            agent_reports=None,
            negotiation_log=None,
            run_summary=None,
            malware_report=malware_report,
            incomplete_reason=None,
            agent_findings=[],
            transcript=[],
            created_at="2026-01-01T00:00:00Z",
        )

    placed = asyncio.run(_detail(MagicMock(), _row_of(json.loads(report.model_dump_json()))))
    assert placed.section_tabs == {"tool_x": "dynamic"}
    assert placed.malware_report == json.loads(report.model_dump_json())
    plain = asyncio.run(_detail(MagicMock(), _row_of(None)))
    assert plain.section_tabs is None
