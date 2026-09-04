"""An empty section from a sandbox that cannot fill it is not a clean sample."""

from __future__ import annotations

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer


def test_a_cape_report_declares_nothing_unavailable():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
    }
    behavior = build_dynamic_behavior(report)
    assert behavior is not None and behavior.unavailable == []


def test_the_unavailable_list_travels_from_the_report_into_the_model():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
        "unavailable": ["apistats", "calls", "registry", "generic_events"],
    }
    behavior = build_dynamic_behavior(report)
    assert behavior is not None
    assert behavior.unavailable == ["apistats", "calls", "registry", "generic_events"]


def test_a_report_with_only_unavailable_sections_is_still_none():
    """Nothing observed and nothing available is still no dynamic behaviour."""
    assert build_dynamic_behavior({"unavailable": ["apistats"]}) is None


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
