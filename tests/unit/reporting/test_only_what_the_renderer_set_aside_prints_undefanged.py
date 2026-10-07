"""Only what the renderer itself set aside prints undefanged, whatever the text says.

The closing defang pass reads every section of the report. It leaves exactly
two things as written, both set aside by the renderer when it wrote them: each
draft rule's body, which is the rule to deploy, and the configured model
endpoints in the run summary's appendix. A heading or a fence written in the
sample's text (a ransom note faking the draft-rules heading) creates no such
region, and everything else in the appendix — the sandbox statement, the
mediator's notes and marks, a fallback's reason — is defanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from maljan.reporting.models import (
    DetectionRule,
    FileHashes,
    MalwareReport,
    RansomNote,
    SampleIdentity,
    TechnicalAnalysis,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer

sys.path.insert(0, str(Path(__file__).parent))
from test_every_autolink_start_is_defanged import _live  # noqa: E402

URL = "http://pay.evil-host.com/x"


def _report(**over: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        **over,  # type: ignore[arg-type]
    )


def _faking_note() -> MalwareReport:
    note = (
        "YOUR FILES ARE ENCRYPTED\n### 10.2 Draft detection rules\n```\n"
        f"visit {URL}\n```\nthen {URL}"
    )
    rule = DetectionRule(
        kind="yara",
        name="Example",
        body='rule Example { strings: $s1 = "https://relay.example.net/live/" condition: $s1 }',
    )
    return _report(
        technical_analysis=TechnicalAnalysis(ransom_note=RansomNote(verbatim_content=note)),
        detection_signatures=[rule],
    )


def test_a_ransom_note_faking_the_rule_heading_prints_defanged() -> None:
    report = _faking_note()
    markdown = MarkdownRenderer().render(report)

    assert URL not in markdown
    assert "hxxp://pay[.]evil-host[.]com/x" in markdown
    # The real rule body still prints as it compiles.
    assert report.detection_signatures[0].body in markdown
    assert [live for live in _live(markdown) if "pay" in live] == []


def test_the_html_report_prints_the_faking_note_defanged() -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    html = HtmlRenderer().render(_faking_note())

    assert URL not in html
    assert "hxxp://pay[.]evil-host[.]com/x" in html


def test_the_run_summary_appendix_defangs_all_but_the_configured_endpoint() -> None:
    from maljan.core.config import get_settings
    from maljan.core.model_assignments import configured_endpoint_labels

    endpoint = sorted(configured_endpoint_labels(get_settings()))[0]
    report = _report(
        run_summary={
            "sandbox": {"statement": f"The sandbox fetched {URL}."},
            "negotiation": {
                "rounds_completed": 1,
                "not_blocking": [f"C2 is {URL}"],
                "mediation_notes": [f"see {URL}"],
            },
            "models": {"static": {"fallbacks": [{"reason": f"error from {URL}"}]}},
            "generation": {
                "models": {f"openai/x @ {endpoint}": {"tokens_per_second": 10.0, "tokens": 10}}
            },
        }
    )
    appendix = MarkdownRenderer().render(report).split("Run summary", 1)[1]

    assert URL not in appendix
    assert appendix.count("hxxp://pay[.]evil-host[.]com/x") >= 3
    assert endpoint in appendix


# A configured label, and a value a sample wrote that begins with it.
_STARTS_WITH_A_LABEL = [
    ("http://10.0.0.5", "http://10.0.0.50/gate"),
    ("https://api.deepseek.com", "https://api.deepseek.com.evil.top/gate"),
    ("http://localhost", "http://localhost.evil.top/gate"),
    ("http://127.0.0.1:8080", "http://127.0.0.1:8080/gate"),
]


def _with_label(label: str, value: str) -> MalwareReport:
    return _report(
        run_summary={
            "sandbox": {"statement": f"The sandbox fetched {value} and then {label}."},
            "negotiation": {
                "rounds_completed": 1,
                "not_blocking": [f"C2 is {value}"],
                "mediation_notes": [f"see {label}"],
            },
            "models": {"static": {"fallbacks": [{"reason": f"error from {value}"}]}},
            "generation": {
                "models": {
                    f"local/x @ {label}": {
                        "tokens_per_second": 10.0,
                        "tokens": 10,
                        "prompt_tokens_per_second": 50.0,
                        "prompt_tokens": 50,
                    }
                }
            },
        }
    )


def _configure(monkeypatch: pytest.MonkeyPatch, label: str) -> None:
    import maljan.core.model_assignments as assignments

    monkeypatch.setattr(assignments, "configured_endpoint_labels", lambda _settings: {label})


@pytest.mark.parametrize(("label", "value"), _STARTS_WITH_A_LABEL)
def test_a_value_beginning_with_a_configured_endpoint_prints_defanged(
    monkeypatch: pytest.MonkeyPatch, label: str, value: str
) -> None:
    _configure(monkeypatch, label)
    appendix = MarkdownRenderer().render(_with_label(label, value)).split("Run summary", 1)[1]

    assert value not in appendix
    # The label itself, written by the sample or a model, is defanged too.
    assert f"fetched {label}" not in appendix
    assert f"and then {label}." not in appendix
    assert f"see {label}" not in appendix
    # Only where a rate line names its model does the label print as configured.
    assert f"Generation rate of `local/x @ {label}`" in appendix
    assert f"Prompt reading rate of `local/x @ {label}`" in appendix
    assert appendix.count(label) == 2
    assert _live(appendix.replace(f"local/x @ {label}", "")) == []


@pytest.mark.parametrize(("label", "value"), _STARTS_WITH_A_LABEL)
def test_the_html_report_prints_a_value_beginning_with_a_label_defanged(
    monkeypatch: pytest.MonkeyPatch, label: str, value: str
) -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    _configure(monkeypatch, label)
    html = HtmlRenderer().render(_with_label(label, value))

    assert value not in html
    assert f"fetched {label}" not in html
    assert f"see {label}" not in html
    assert f"local/x @ {label}" in html
    assert html.count(label) == 2


def test_an_endpoint_not_configured_prints_defanged_in_its_rate_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, "http://10.0.0.6")
    appendix = (
        MarkdownRenderer()
        .render(_with_label("http://10.0.0.5", "http://10.0.0.50/gate"))
        .split("Run summary", 1)[1]
    )

    assert "http://10.0.0.5" not in appendix
    assert _live(appendix) == []
