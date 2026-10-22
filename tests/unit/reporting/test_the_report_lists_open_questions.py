"""The report's "Open questions" section: right or absent, and never read as an absence.

Each question an analyst left open is one row: who left it, the question, why
it stayed open, what would answer it, which agents of this run called a tool
of the kind it names, and the ids it rests on. A run in which no analyst left
one open has no section at all. The section is the analysts' words, so its
source is its own: no capability is grounded by it, no value is held by the
entries it cites, and no corroboration reads it.

Every question, address and agent here is made up for the test.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.reporting.ledger_report import (
    ANALYST_SECTION_SOURCES,
    build_sections,
    section_is_grounded,
)
from maljan.reporting.models import (
    OPEN_QUESTION_SOURCE,
    EvidenceSection,
    is_open_question_section,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, OpenQuestion


def _entry(entry_id: str, agent: str, tool: str, server: str = "ghidra") -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent=agent, server=server, tool=tool, args={}, output="x", ok=True
    )


_LEDGER = [
    _entry("ev_0001", "reverser", "decompile_function"),
    _entry("ev_0002", "static", "pe_info", server="analysis"),
]


def _isrs(*questions: OpenQuestion, agent: str = "static") -> dict[str, AgentISR]:
    return {agent: AgentISR(agent_id=agent, domain="static", open_questions=list(questions))}


def _section(sections: list[EvidenceSection]) -> EvidenceSection | None:
    return next((s for s in sections if s.key == "open_questions"), None)


class TestTheSection:
    def test_no_question_left_open_is_no_section(self) -> None:
        sections = build_sections(_LEDGER, _isrs())

        assert _section(sections) is None

    def test_each_question_is_a_row_with_who_could_answer_from_the_ledger(self) -> None:
        question = OpenQuestion(
            question="What the beacon interval is",
            why_open="obfuscated",
            detail="the config is encrypted",
            would_answer="a decompile of the config routine",
            tool_kind="decompile",
            evidence_ids=["ev_0002"],
        )

        section = _section(build_sections(_LEDGER, _isrs(question)))

        assert section is not None
        assert section.title == "Open questions"
        assert section.columns == [
            "Agent",
            "Question",
            "Why open",
            "What would answer it",
            "Who could answer",
            "Evidence",
        ]
        assert section.rows == [
            [
                "static",
                "What the beacon interval is",
                "obfuscated: the config is encrypted",
                "a decompile of the config routine (tool kind decompile)",
                "reverser",
                "ev_0002",
            ]
        ]
        assert section.evidence_ids == ["ev_0002"]

    def test_a_question_naming_no_kind_or_a_kind_nobody_called_names_nobody(self) -> None:
        unnamed = OpenQuestion(question="Who wrote it", why_open="other")
        uncalled = OpenQuestion(
            question="What it unpacks to", why_open="no_capable_tool", tool_kind="unpack"
        )

        section = _section(build_sections(_LEDGER, _isrs(unnamed, uncalled)))

        assert section is not None
        assert [row[4] for row in section.rows] == ["", ""]

    def test_a_specialist_s_question_handed_to_the_lead_names_the_specialist(self) -> None:
        question = OpenQuestion(
            question="Where the key is derived", why_open="out_of_turns", source="reverser"
        )

        section = _section(build_sections(_LEDGER, _isrs(question, agent="lead")))

        assert section is not None and section.rows[0][0] == "reverser"


class TestItIsNeverReadAsWhatTheRunFound:
    def test_its_source_is_its_own_and_grounded(self) -> None:
        question = OpenQuestion(question="Who wrote it", why_open="other")
        section = _section(build_sections(_LEDGER, _isrs(question)))

        assert section is not None
        assert section.source == OPEN_QUESTION_SOURCE
        assert not section.source.startswith(ANALYST_SECTION_SOURCES)
        assert section_is_grounded(section)
        assert is_open_question_section(section)

    def test_its_words_ground_no_capability(self) -> None:
        from maljan.pipeline.validation import CapabilityGrounding

        question = EvidenceSection(
            key="open_questions",
            title="Open questions",
            kind="table",
            columns=["Agent", "Question"],
            rows=[["static", "Does it keylog through SetWindowsHookEx"]],
            source=OPEN_QUESTION_SOURCE,
        )
        other = question.model_copy(update={"key": "notes", "source": "finding"})

        def _grounding(section: EvidenceSection) -> CapabilityGrounding:
            report = SimpleNamespace(sections=[section], ttp_mappings=[], capability_matrix=[])
            return CapabilityGrounding.from_report(report)

        read = _grounding(other)
        assert not read.unread
        assert "keylog" in read.evidence_text.lower() and "notes" in read.evidence_keys
        skipped = _grounding(question)
        assert not skipped.unread
        assert "keylog" not in skipped.evidence_text.lower()
        assert "open_questions" not in skipped.evidence_keys


class TestTheMarkdownAppendix:
    def test_it_is_assessed_and_said_to_be_unknowns(self) -> None:
        from maljan.reporting.renderers.markdown import OPEN_QUESTIONS_NOTE, _evidence_heading

        section = EvidenceSection(
            key="open_questions", title="Open questions", kind="table", source=OPEN_QUESTION_SOURCE
        )

        assert _evidence_heading(section).endswith("_Assessed_")
        assert "unknowns, not absences" in OPEN_QUESTIONS_NOTE


def _report_citing(entry_id: str, tool: str, *sections: EvidenceSection) -> Any:
    from maljan.reporting.models import (
        EvidenceIndexRow,
        FileHashes,
        MalwareReport,
        NetworkIOCs,
        NetworkIP,
        SampleIdentity,
    )

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[EvidenceIndexRow(id=entry_id, tool=tool, agent="dynamic")],
        sections=list(sections),
        network=NetworkIOCs(
            ips=[NetworkIP(address="198.51.100.7", source="sandbox", sample_process_tree=True)]
        ),
    )


def _cited(source: str, entry_id: str = "ev_0004") -> EvidenceSection:
    return EvidenceSection(
        key="open_questions" if source == OPEN_QUESTION_SOURCE else "findings",
        title="Open questions",
        kind="table",
        columns=["Agent", "Question"],
        rows=[["dynamic", "Whether 203.0.113.7 is contacted after the sleep"]],
        evidence_ids=[entry_id],
        source=source,
    )


class TestNoHolderReadsIt:
    def test_the_entry_it_cites_holds_no_value_and_records_nothing(self) -> None:
        from maljan.reporting.evidence_bundles import sandbox_entry_ids, value_entries

        asked = _report_citing("ev_0004", "sandbox_network", _cited(OPEN_QUESTION_SOURCE))
        found = _report_citing("ev_0004", "sandbox_network", _cited("finding"))

        assert value_entries(found, ["203.0.113.7"]) == {"203.0.113.7": ["ev_0004"]}
        assert "ev_0004" in sandbox_entry_ids(found)
        assert value_entries(asked, ["203.0.113.7"]) == {}
        assert "ev_0004" not in sandbox_entry_ids(asked)

    def test_the_entry_it_cites_corroborates_nothing(self) -> None:
        from maljan.reporting.renderers.stix_renderer import _corroborating_values

        tool = EvidenceSection(
            key="tool_sandbox_network",
            title="Sandbox network",
            kind="kv",
            rows=[["hosts", "203.0.113.7"]],
            evidence_ids=["ev_0004"],
            source="tool:sandbox_network",
        )
        asked = _report_citing("ev_0004", "sandbox_network", tool, _cited(OPEN_QUESTION_SOURCE))
        found = _report_citing("ev_0004", "sandbox_network", tool, _cited("finding"))

        assert "203.0.113.7" in _corroborating_values(found)
        assert "203.0.113.7" not in _corroborating_values(asked)
