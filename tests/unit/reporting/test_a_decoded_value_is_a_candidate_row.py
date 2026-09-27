"""A network value the platform decoded is a candidate row, whether or not a model named it.

The record of what FLOSS and ``decode_string_blobs`` recovered gave a value
standing under the publish rule, but created no row: a URL both tools
recovered and no model named had no row in the IOC table, ``/iocs``, STIX or
Suricata, not even a ``no:`` one, and Appendix A printed it live. Each value
the record holds is now a network row of the string sweep's source, so the
rule's existing emulation gate decides it (a Benign or unstated verdict and a
well-known host are refused), the table states which tool recovered it and
where, and every printed copy of it is defanged.

Every value here is synthetic: example names.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import emulation_kwargs, publish_answer
from maljan.schemas.evidence import LedgerEntry

C2 = "relay7.example.net"
C2_URL = f"https://{C2}/Gate/Poll.php"


def _floss(*strings: str) -> LedgerEntry:
    rows = [
        {
            "kind": "decoded",
            "string": text,
            "encoding": "ASCII",
            "function_rva": "0x1a00",
            "called_at_rva": "0x1b10",
        }
        for text in strings
    ]
    return LedgerEntry(
        id="ev_0012",
        agent="pipeline",
        tool="floss",
        structured={"total": len(rows), "strings": rows, "truncated": False},
    )


def _decoder(text: str) -> LedgerEntry:
    row = {
        "offset": "0xfd30",
        "scheme": "xor8",
        "text": text,
        "references": [{"at": "0x1a2b", "function": "0x1a00"}],
    }
    return LedgerEntry(
        id="ev_0020",
        agent="pipeline",
        tool="decode_string_blobs",
        structured={"results": [row], "total": 1, "page_offset": 0, "next_offset": None},
    )


def _strings() -> LedgerEntry:
    return LedgerEntry(
        id="ev_0005",
        agent="pipeline",
        tool="strings",
        structured={
            "total": 1,
            "strings": [{"enc": "ascii", "text": "kernel32.dll", "offset": 0}],
            "truncated": False,
        },
    )


def _build(ledger: list[LedgerEntry], verdict: str = "Malware") -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return row


class TestADecodedURLNoModelNamed:
    def test_it_has_a_row_with_its_provenance(self) -> None:
        report = _build([_strings(), _floss(C2_URL), _decoder(C2_URL)])

        assert report.network is not None
        (url,) = report.network.urls
        assert (url.url, url.source) == (C2_URL, "strings")
        row = _row(report, C2_URL)
        assert row.published == "yes"
        assert "floss, ev_0012" in row.recovered_by
        assert "decode_string_blobs, ev_0020" in row.recovered_by
        assert _row(report, C2).published == "yes"

    def test_it_is_answered_exactly_as_a_floss_value_with_the_same_facts(self) -> None:
        report = _build([_strings(), _floss(C2_URL)])

        facts = emulation_kwargs(report, "url", C2_URL)
        expected = publish_answer("url", C2_URL, "strings", **facts)
        assert facts["recovered"].startswith("recovered by emulation (decoded strings), ev_0012")
        assert _row(report, C2_URL).published == expected == "yes"

    def test_under_a_benign_verdict_it_is_refused_with_the_reason(self) -> None:
        report = _build([_strings(), _floss(C2_URL)], verdict="Benign")

        answer = _row(report, C2_URL).published
        assert answer.startswith("no: recovered by emulation (decoded strings), ev_0012")
        assert "the verdict is Benign" in answer

    def test_a_well_known_host_is_refused(self) -> None:
        report = _build([_strings(), _floss("www.microsoft.com")])

        assert _row(report, "www.microsoft.com").published.startswith("no: ")

    def test_appendix_a_prints_it_defanged(self) -> None:
        markdown = MarkdownRenderer().render(_build([_strings(), _floss(C2_URL), _decoder(C2_URL)]))

        appendix = markdown[markdown.index("## Appendix A") :]
        assert C2 not in appendix
        assert "relay7[.]example[.]net" in appendix
