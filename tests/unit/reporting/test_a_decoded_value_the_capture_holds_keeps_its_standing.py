"""A value the sample hid and the capture holds keeps the standing its recovery gives it.

FLOSS decoding an address and a name made them publishable; the capture
holding a conversation to that address and the name in its TLS list made them
unattributed sandbox rows, which wait for the judge — so the stronger case (the
sample hid the value and the guest reached it) got the weaker answer. The
recovery now admits such a row before the unattributed hold, under every
refusal it already has (a Benign or unstated verdict, a well-known host, a
public resolver, a value also in the plain strings), and the reason states both
facts.

The address and the name are synthetic: a routable address the reference run
never reached, and an example name.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.renderers.stix_renderer import (
    emulation_kwargs,
    indicator_publish_reason,
    publishes,
)
from maljan.schemas.evidence import LedgerEntry

ADDRESS = "185.199.110.88"
NAME = "relay-alpha-7f3c.top"
RESOLVER = "9.9.9.9"


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


def _capture(*addresses: str, sni: tuple[str, ...] = ()) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0017",
        agent="pipeline",
        tool="pcap_summary",
        structured={
            "conversations": [{"dst": a, "dport": 443, "proto": "tcp"} for a in addresses],
            "sni": {name: 1 for name in sni},
            "empty": False,
        },
    )


def _build(ledger: list[LedgerEntry], verdict: str = "Malware") -> Any:
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


def _published(report: Any, value: str) -> str:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return str(row.published)


class TestADecodedAddressTheCaptureReached:
    def test_it_publishes_and_the_reason_states_both_facts(self) -> None:
        report = _build([_strings(), _floss(ADDRESS), _capture(ADDRESS)])

        assert report.network is not None
        (ip,) = report.network.ips
        assert ip.source == "sandbox"
        assert publishes(_published(report, ADDRESS))
        reason = indicator_publish_reason(
            "ip", ADDRESS, "sandbox", None, **emulation_kwargs(report, "ip", ADDRESS)
        )
        assert reason is not None
        assert "recovered by emulation (decoded strings), ev_0012" in reason
        assert "the sandbox report does not say which process made the flows to it" in reason

    def test_under_a_benign_verdict_it_is_refused(self) -> None:
        report = _build([_strings(), _floss(ADDRESS), _capture(ADDRESS)], verdict="Benign")

        answer = _published(report, ADDRESS)
        assert answer.startswith(
            "no: the sandbox report does not say which process made the flows to it; "
            "recovered by emulation (decoded strings), ev_0012"
        )
        assert "but the verdict is Benign" in answer


class TestADecodedNameInTheCapturesTLSList:
    def test_it_publishes(self) -> None:
        report = _build([_strings(), _floss(NAME), _capture(sni=(NAME,))])

        assert report.network is not None
        (domain,) = report.network.domains
        assert (domain.source, domain.capture_only) == ("sandbox", True)
        assert publishes(_published(report, NAME))


class TestADecodedPublicResolver:
    def test_it_is_refused(self) -> None:
        report = _build([_strings(), _floss(RESOLVER), _capture(RESOLVER)])

        assert _published(report, RESOLVER).startswith("no: ")
