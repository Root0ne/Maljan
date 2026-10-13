"""The composer and the narrative round ground a report by the kinds the run's entries declare.

Each hands the run's evidence to the grounding, so a section an invented rule
matcher opened is a rule match whose words ground nothing, and its matcher's
display name is one a sentence may report a match by; a section a look-alike
tool named like a built-in opened is ordinary evidence. Both rounds are driven
through their real entry point, stopped right after the grounding is read.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings
from maljan.pipeline.validation import CapabilityGrounding, EntryTexts
from maljan.reporting.models import MalwareReport
from maljan.schemas.evidence import build_entry

SCANNER = {
    "command": "invented-scanner",
    "enabled": True,
    "tool_facts": {
        "scan": {
            "kind": "signature_rules",
            "asserts_techniques": True,
            "source": "scanner",
            "techniques": [{"path": "/**6/technique_id"}],
            "display_name": "ScanEngine",
        }
    },
}


class _Stop(Exception):
    pass


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch) -> EntryTexts:
    held = Settings()
    held.mcp.servers["scanner"] = MCPServerConfig.model_validate(SCANNER)
    held.mcp.servers["lookalike"] = MCPServerConfig.model_validate({"command": "x"})
    monkeypatch.setattr(config_module, "_settings_instance", held)
    ledger = [
        build_entry(
            entry_id="ev_0001", seq=1, agent="static", tool="scan", args={}, server=None,
            output='{"matches": []}', source="mcp:scanner",
        ),
        build_entry(
            entry_id="ev_0002", seq=2, agent="static", tool="capa", args={}, server=None,
            output='{"capabilities": []}', source="mcp:lookalike",
        ),
    ]  # fmt: skip
    return EntryTexts.from_ledger(ledger)


def _report() -> MalwareReport:
    def section(key: str, tool: str, cited: str, title: str) -> dict[str, Any]:
        return {"key": key, "title": title, "source": f"tool:{tool}", "evidence_ids": [cited]}

    return MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "sections": [
                section("scan_rules", "scan", "ev_0001", "keylogging via polling"),
                section("lookalike", "capa", "ev_0002", "credential dumping"),
            ],
        }
    )


def _caught() -> tuple[Any, list[CapabilityGrounding]]:
    """A spy on the real grounding that keeps what it read and stops the round there."""
    real = CapabilityGrounding.from_report
    held: list[CapabilityGrounding] = []

    def spy(report: Any, isr_reports: Any = None, ledger: Any = None) -> CapabilityGrounding:
        held.append(real(report, isr_reports, ledger=ledger))
        raise _Stop

    return spy, held


def _assert_grounded(grounding: CapabilityGrounding) -> None:
    assert "keylogging" not in grounding.evidence_text
    assert "credential dumping" in grounding.evidence_text
    assert "scanengine" in grounding.matchers


def test_the_composer_grounds_by_the_declared_kinds(evidence: EntryTexts) -> None:
    from maljan.reporting.composer import ReportComposer

    spy, held = _caught()
    composer = ReportComposer(llm=None, per_section_timeout=5)  # type: ignore[arg-type]
    with patch.object(CapabilityGrounding, "from_report", side_effect=spy):
        with pytest.raises(_Stop):
            asyncio.run(composer.compose(_report(), {}, evidence=evidence))
    (grounding,) = held
    _assert_grounded(grounding)


def test_the_narrative_round_grounds_by_the_declared_kinds(evidence: EntryTexts) -> None:
    from maljan.reporting.narrative_agent import NarrativeAgent

    spy, held = _caught()
    agent = NarrativeAgent(llm=None)  # type: ignore[arg-type]
    with patch.object(CapabilityGrounding, "from_report", side_effect=spy):
        with pytest.raises(_Stop):
            asyncio.run(agent.generate(_report(), {}, evidence=evidence))
    (grounding,) = held
    _assert_grounded(grounding)


def test_without_the_evidence_the_lookalike_would_be_read_by_name(evidence: EntryTexts) -> None:
    grounding = CapabilityGrounding.from_report(_report(), {})
    assert "credential dumping" not in grounding.evidence_text
    assert "scanengine" not in grounding.matchers
