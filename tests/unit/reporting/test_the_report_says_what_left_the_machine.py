"""The report prints the run's disclosure block in Appendix B, and only where it was recorded.

A run summary that carries the record prints its sentences, in the markdown
and in the HTML made from it, with the footnote that says what "this machine"
covers; one stored without it, or with a record that was not built, prints no
block, so a stored report renders as it did. A host the run's own settings
addressed (as the record keeps them) prints as configured; any other host the
record holds prints defanged, whatever the process's settings say now. The
enrichment that follows a report is named in it, then what it asked.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from maljan.analysis.disclosure import (
    FOOTNOTE_SENTENCE,
    INTRO_SENTENCE,
    NOT_BUILT_REPORTING_OFF,
    disclosure_record,
    enrichment_source_row,
    not_built,
    rdap_row,
    upload_record,
    with_enrichment,
    with_enrichment_asked,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer

SNAPSHOT = {
    "llm.provider": "openai",
    "llm.openai.base_url": "https://llm.example.org/v1",
    "sandbox.triage.base_url": "https://sandbox.example.net/api",
    "memory.backend": "memory",
}
GENERATED_AT = datetime(2026, 9, 1, tzinfo=UTC)
TOKENS = {
    "llm_calls": 3,
    "per_agent": {"static": {"llm_calls": 3, "models": {"openai/x @ https://llm.example.org": 3}}},
}


def _report(run_summary: dict) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=run_summary,
        generated_at=GENERATED_AT,
    )


def _record(snapshot: dict | None = None) -> dict:
    return disclosure_record(
        SNAPSHOT if snapshot is None else snapshot,
        tokens=TOKENS,
        agents=["static"],
        uploads=[upload_record("triage", submitted=True, host="sandbox.example.net")],
    )


def _appendix(markdown: str) -> str:
    return markdown.split("Run summary", 1)[1].split("\n## Appendix C", 1)[0]


def _rendered(record: dict) -> str:
    return _appendix(
        MarkdownRenderer().render(_report({"final_decision": "Malware", "disclosure": record}))
    )


def test_a_recorded_disclosure_prints_in_the_run_summary_appendix() -> None:
    appendix = _rendered(_record())

    assert INTRO_SENTENCE in appendix
    assert (
        "- Model prompts: `llm.example.org` (outside this machine) received 3 calls (static 3)."
        in appendix
    )
    assert (
        "- Sample upload: the sample was submitted once to the `triage` sandbox at "
        "`sandbox.example.net` (outside this machine)."
    ) in appendix
    assert appendix.count(FOOTNOTE_SENTENCE) == 1
    assert appendix.rstrip().endswith(FOOTNOTE_SENTENCE)


def test_a_host_the_runs_settings_did_not_address_prints_defanged() -> None:
    record = _record({k: v for k, v in SNAPSHOT.items() if not k.startswith("sandbox.")})

    appendix = _rendered(record)

    assert record["addressed"] == ["llm.example.org"]
    assert "`llm.example.org`" in appendix
    assert "sandbox.example.net" not in appendix
    assert "`sandbox[.]example[.]net`" in appendix


def test_what_prints_as_configured_is_read_from_the_record_never_the_process_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later render of a stored run prints the hosts its own run addressed, and only those."""
    from maljan.core import config

    record = _record()
    before = _rendered(record)

    def _refused() -> None:
        raise AssertionError("the renderer read the process's settings")

    monkeypatch.setattr(config, "get_settings", _refused)
    assert _rendered(record) == before
    assert "`sandbox.example.net`" in before


def test_the_html_report_carries_the_block() -> None:
    from maljan.reporting.renderers.html import HtmlRenderer

    html = HtmlRenderer().render(
        _report({"final_decision": "Malware", "disclosure": _record()}), nonce="fixed"
    )

    assert "<strong>Disclosure:</strong>" in html
    assert "<code>llm.example.org</code> (outside this machine) received 3 calls" in html


@pytest.mark.parametrize("held", [None, not_built(NOT_BUILT_REPORTING_OFF)])
def test_a_summary_without_a_built_record_prints_no_block(held: dict | None) -> None:
    summary = {"final_decision": "Malware", "elapsed_seconds": 12.0}
    without = MarkdownRenderer().render(_report(summary))
    marked = MarkdownRenderer().render(
        _report(summary if held is None else {**summary, "disclosure": held})
    )

    assert "Disclosure" not in without
    assert marked == without
    # The record is the only thing the block adds to the appendix.
    with_record = MarkdownRenderer().render(_report({**summary, "disclosure": _record()}))
    head = _appendix(with_record).split(INTRO_SENTENCE, 1)[0].rstrip("\n")
    assert head == _appendix(without).rstrip("\n")


def test_a_run_that_stayed_local_says_so_and_what_that_rests_on() -> None:
    record = disclosure_record(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": "http://127.0.0.1:8080/v1",
            "memory.backend": "memory",
        },
        tokens={
            "llm_calls": 1,
            "per_agent": {
                "judge": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}
            },
        },
        agents=["judge"],
        runtimes={"http://127.0.0.1:8080": "llama.cpp /props"},
    )

    appendix = _rendered(record)

    assert (
        "- Nothing left this machine. This rests on: every model endpoint in this run's "
        "settings is a local address that answered as a model runtime: `127.0.0.1` "
        "(llama.cpp /props) (a local address that answered as a model runtime is taken as "
        "running here, and a tunnel or proxy to a remote runtime cannot be told apart); the "
        "case-memory store is kept in the process or not configured; "
        "no lookup was asked, and tracing is off."
    ) in appendix


def test_the_enrichment_queued_after_the_report_is_named_then_what_it_asked() -> None:
    local = disclosure_record(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": "http://127.0.0.1:8080/v1",
            "memory.backend": "memory",
        },
        tokens={
            "llm_calls": 1,
            "per_agent": {
                "judge": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}
            },
        },
        agents=["judge"],
        runtimes={"http://127.0.0.1:8080": "llama.cpp /props"},
    )
    assert local["nothing_left"] is True
    source = enrichment_source_row("intel", kinds=["domain", "ip"], hosts=["api.intel.example"])
    queued = with_enrichment(local, [rdap_row(), source])

    appendix = _rendered(queued)

    assert queued["nothing_left"] is False
    assert "Nothing left this machine" not in appendix
    assert (
        "- Enrichment: a follow-up job queued after this report may send the report's public "
        "domains and addresses to RDAP (ip) at `rdap.arin.net` and the registry it refers "
        "an address to, with no key; source `intel` (domain, ip) at `api.intel.example`. "
        "What it sends is added here once it has run."
    ) in appendix

    asked = with_enrichment_asked(
        queued,
        [
            {"source": "rdap", "host": "rdap.arin.net", "kinds": {"ip": 2}, "why": ""},
            {"source": "intel", "host": "api.intel.example", "kinds": {"domain": 1}, "why": ""},
        ],
    )
    assert asked["nothing_left"] is False
    assert (
        "- Enrichment: the follow-up job asked `api.intel.example` (outside this machine) "
        "about domain 1 (source `intel`); `rdap.arin.net` (outside this machine) about ip 2 "
        "(RDAP)."
    ) in _rendered(asked)


# ``(markdown, html with the nonce "fixed")`` as dev 0517a43e renders the stored runs,
# none of which carries the record.
STORED_RENDERS = {
    "run7": ("5a98e8f996754f33", "80c0f1e1efc22387"),
    "run5": ("6c8ad459731fe4f2", "f3cb9aca3dcebfc9"),
    "run4": ("4932dab8f2f2c210", "cb4460ea310cdaa4"),
    "local8": ("5a1913468ca02123", "fccb9cb35eba3fb4"),
    "haiku4": ("323fd6816b055763", "2cd3dbc93fd5eb4d"),
}


@pytest.mark.parametrize("run", sorted(STORED_RENDERS))
def test_a_stored_run_renders_as_it_did_before_the_block(run: str) -> None:
    from maljan.reporting.renderers import HtmlRenderer
    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
        _benchmark,
    )

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    data = json.loads((root / run / "report.json").read_text())
    assert "disclosure" not in (data.get("run_summary") or {})
    report = MalwareReport.model_validate(data)

    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")

    digests = tuple(hashlib.sha256(text.encode()).hexdigest()[:16] for text in (markdown, html))
    assert digests == STORED_RENDERS[run]
    assert INTRO_SENTENCE not in markdown
