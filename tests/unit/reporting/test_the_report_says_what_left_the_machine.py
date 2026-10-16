"""The report prints the run's disclosure block in Appendix B, and only where it was recorded.

A run summary that carries the record prints its sentences, in the markdown
and in the HTML made from it; one stored without it prints no block, so a
stored report renders as it did. A host the settings address prints as
configured; any other host the record holds prints defanged.
"""

from __future__ import annotations

import pytest

from maljan.analysis import disclosure
from maljan.analysis.disclosure import INTRO_SENTENCE, disclosure_record, upload_record
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(run_summary: dict) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=run_summary,
    )


def _record() -> dict:
    return disclosure_record(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": "https://llm.example.org/v1",
            "sandbox.triage.base_url": "https://sandbox.example.net/api",
        },
        tokens={
            "llm_calls": 3,
            "per_agent": {
                "static": {"llm_calls": 3, "models": {"openai/x @ https://llm.example.org": 3}}
            },
        },
        agents=["static"],
        uploads=[upload_record("triage", submitted=True)],
    )


def _appendix(markdown: str) -> str:
    return markdown.split("Run summary", 1)[1].split("\n## Appendix C", 1)[0]


def test_a_recorded_disclosure_prints_in_the_run_summary_appendix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        disclosure, "configured_hosts", lambda _s: {"llm.example.org", "sandbox.example.net"}
    )
    markdown = MarkdownRenderer().render(
        _report({"final_decision": "Malware", "disclosure": _record()})
    )
    appendix = _appendix(markdown)

    assert INTRO_SENTENCE in appendix
    assert (
        "- Model prompts: `llm.example.org` (outside this machine) received 3 calls (static 3)."
        in appendix
    )
    assert (
        "- Sample upload: the sample was submitted once to the `triage` sandbox at "
        "`sandbox.example.net` (outside this machine)."
    ) in appendix


def test_a_host_the_settings_do_not_address_prints_defanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(disclosure, "configured_hosts", lambda _s: {"llm.example.org"})
    appendix = _appendix(
        MarkdownRenderer().render(_report({"final_decision": "Malware", "disclosure": _record()}))
    )

    assert "`llm.example.org`" in appendix
    assert "sandbox.example.net" not in appendix
    assert "`sandbox[.]example[.]net`" in appendix


def test_the_html_report_carries_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    monkeypatch.setattr(disclosure, "configured_hosts", lambda _s: {"llm.example.org"})
    html = HtmlRenderer().render(
        _report({"final_decision": "Malware", "disclosure": _record()}), nonce="fixed"
    )

    assert "<strong>Disclosure:</strong>" in html
    assert "<code>llm.example.org</code> (outside this machine) received 3 calls" in html


def test_a_summary_stored_without_the_record_prints_no_block() -> None:
    summary = {"final_decision": "Malware", "elapsed_seconds": 12.0}
    without = MarkdownRenderer().render(_report(summary))

    assert "Disclosure" not in without
    # The record is the only thing the block adds to the appendix.
    with_record = MarkdownRenderer().render(_report({**summary, "disclosure": _record()}))
    head = _appendix(with_record).split(INTRO_SENTENCE, 1)[0].rstrip("\n")
    assert head == _appendix(without).rstrip("\n")


def test_a_run_that_stayed_local_says_so_in_the_report() -> None:
    record = disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"},
        tokens={
            "llm_calls": 1,
            "per_agent": {
                "judge": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}
            },
        },
        agents=["judge"],
    )
    appendix = _appendix(
        MarkdownRenderer().render(_report({"final_decision": "Benign", "disclosure": record}))
    )

    assert f"- {disclosure.NOTHING_LEFT_SENTENCE}" in appendix
