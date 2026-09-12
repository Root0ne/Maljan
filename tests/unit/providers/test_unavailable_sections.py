"""An empty section from a sandbox that cannot fill it is not a clean sample."""

from __future__ import annotations

from typing import Any

from maljan.providers.sandbox_tools import sandbox_processes, sandbox_report_section
from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry


def _behavior(report: dict[str, Any]) -> DynamicBehavior | None:
    """What the report's dynamic block holds after an analyst reads it.

    Two calls, the ones a dynamic analyst makes: the process list, and the
    report's own declaration of what this sandbox could not provide.
    """
    counter = EvidenceCounter()
    ledger = [
        entry("sandbox_processes", sandbox_processes(report), counter, agent="dynamic"),
        entry(
            "sandbox_report_section",
            sandbox_report_section(report, "unavailable"),
            counter,
            agent="dynamic",
        ),
    ]
    return dynamic_from_ledger(ledger)


def test_a_cape_report_declares_nothing_unavailable():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
    }
    behavior = _behavior(report)
    assert behavior is not None and behavior.unavailable == []


def test_the_unavailable_list_travels_from_the_report_into_the_model():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
        "unavailable": ["apistats", "calls", "registry", "generic_events"],
    }
    behavior = _behavior(report)
    assert behavior is not None
    assert behavior.unavailable == ["apistats", "calls", "registry", "generic_events"]


def test_a_report_with_only_unavailable_sections_still_has_no_behaviour():
    """Nothing observed is nothing observed, whatever the sandbox could not watch."""
    behavior = _behavior({"unavailable": ["apistats"]})
    assert behavior is not None
    assert behavior.process_tree == []
    assert behavior.unavailable == ["apistats"]


def _minimal_report_with_gaps() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        dynamic=DynamicBehavior(
            process_tree=[],
            registry_mods=[],
            file_operations=[],
            notable_apis=[],
            sandbox_signatures=[],
            unavailable=["apistats", "registry"],
        ),
    )


def test_the_markdown_renderer_names_the_gaps():
    report = _minimal_report_with_gaps()
    text = MarkdownRenderer().render(report)
    assert "Not provided by this sandbox" in text
    assert "apistats" in text and "registry" in text


def test_the_html_report_names_the_gaps():
    report = _minimal_report_with_gaps()
    html = HtmlRenderer().render(report)
    assert "Not provided by this sandbox" in html
    assert "apistats" in html and "registry" in html


def test_a_cape_shaped_report_names_no_gaps_in_markdown():
    """CAPE fills every section: no ``unavailable`` key, nothing to disclaim."""
    behavior = _behavior(
        {
            "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
            "signatures": [],
            "network": {},
        }
    )
    assert behavior is not None
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        dynamic=behavior,
    )
    text = MarkdownRenderer().render(report)
    assert "Not provided by this sandbox" not in text
