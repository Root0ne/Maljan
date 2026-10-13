"""A url, domain or ip the report states names the answered entries that hold it.

The communications, command-and-control and configuration sections were shown
``urls: [...]`` with no entry behind it: a section could cite the value only
when some analyst claim happened to cite the entry that held it. Each value
now comes with the entries holding it, read from a captured output (its call
number) or a report section built from one entry or naming each row's entry.
A value no entry is known to hold is left out, never given a guessed entry.
"""

from __future__ import annotations

import json
import time
from typing import Any

from maljan.reporting.evidence_bundles import bundle_for, value_entries
from maljan.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
)

URL = "http://beacon.example.test/gate"
HOST = "beacon.example.test"


def _row(entry_id: str, tool: str, ok: bool = True) -> EvidenceIndexRow:
    return EvidenceIndexRow(id=entry_id, agent="static", tool=tool, ok=ok)


def _output(tool: str, seq: int, text: str) -> dict[str, Any]:
    return {"agent_id": "static", "tool_name": tool, "args": {}, "output": text, "seq": seq}


def _report(**over: Any) -> MalwareReport:
    fields: dict[str, Any] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        "network": NetworkIOCs(
            urls=[NetworkURL(url=URL)],
            domains=[NetworkDomain(fqdn=HOST)],
            ips=[NetworkIP(address="192.0.2.7", port=443)],
        ),
        **over,
    }
    return MalwareReport(**fields)


def test_each_value_names_the_entries_whose_answers_hold_it() -> None:
    report = _report(
        evidence_index=[_row("ev_0006", "iocs"), _row("ev_0030", "strings")],
        sections=[
            EvidenceSection(
                key="iocs",
                title="IOCs",
                kind="table",
                columns=["Kind", "Value"],
                rows=[["url", URL], ["ip", "192.0.2.7:443"]],
                evidence_ids=["ev_0006"],
            )
        ],
        technical_evidence={"static": [_output("strings", 29, json.dumps({"text": URL}))]},
    )
    for section in ("communications", "command_and_control", "configuration"):
        facts = bundle_for(section, report)["facts"]
        assert facts["entries_holding"] == [
            f"{URL}: ev_0006, ev_0030",
            f"{HOST}: ev_0006, ev_0030",
            "192.0.2.7:443: ev_0006",
        ], section
        assert facts["urls"] == [URL]


def test_a_failed_or_mismatched_entry_holds_nothing() -> None:
    report = _report(
        evidence_index=[_row("ev_0006", "iocs", ok=False), _row("ev_0030", "strings")],
        sections=[EvidenceSection(key="iocs", title="IOCs", items=[URL], evidence_ids=["ev_0006"])],
        # The call number names ev_0030, but the index files another tool there.
        technical_evidence={"static": [_output("floss", 29, URL)]},
    )
    assert value_entries(report, [URL, HOST]) == []


def test_a_section_of_several_entries_is_read_only_by_the_entry_a_row_names() -> None:
    rows = [_row("ev_0005", "strings"), _row("ev_0006", "iocs")]
    unnamed = EvidenceSection(
        key="mixed", title="M", kind="table", rows=[[URL]], evidence_ids=["ev_0005", "ev_0006"]
    )
    assert value_entries(_report(evidence_index=rows, sections=[unnamed]), [URL]) == []
    named = EvidenceSection(
        key="mixed",
        title="M",
        kind="table",
        columns=["Value", "Evidence"],
        rows=[[URL, "ev_0006"], ["other", "ev_0005"]],
        evidence_ids=["ev_0005", "ev_0006"],
    )
    assert value_entries(_report(evidence_index=rows, sections=[named]), [URL]) == [
        f"{URL}: ev_0006"
    ]


def test_a_url_s_scheme_is_never_read_as_an_address() -> None:
    report = _report(
        evidence_index=[_row("ev_0001", "notes")],
        sections=[EvidenceSection(key="n", title="N", text="http only", evidence_ids=["ev_0001"])],
    )
    assert value_entries(report, ["http://elsewhere.test/x"]) == []


def test_no_network_block_holds_nothing() -> None:
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
    assert bundle_for("communications", report)["facts"]["entries_holding"] == []


def test_reading_the_holders_stays_linear() -> None:
    def took(size: int) -> float:
        texts = [_output("strings", n, f"{URL} filler{n} " * 20) for n in range(size)]
        report = _report(
            evidence_index=[_row(f"ev_{n + 1:04d}", "strings") for n in range(size)],
            technical_evidence={"static": texts},
        )
        start = time.perf_counter()
        value_entries(report, [URL, HOST, *(f"h{n}.test" for n in range(size))])
        return time.perf_counter() - start

    small, large = took(200), took(2_000)
    assert large < small * 30, (small, large)


def _big_answer(distinct: int) -> MalwareReport:
    """One answered entry whose text holds ``distinct`` unrelated tokens and three wanted values."""
    filler = " ".join(f"token-of-filler-{n:x}" for n in range(distinct))
    text = f"{URL} {filler} 192.0.2.7:443 {filler[: len(filler) // 2]}"
    return _report(
        evidence_index=[_row("ev_0001", "strings")],
        technical_evidence={"static": [_output("strings", 0, text)]},
    )


def test_a_huge_answer_keeps_only_the_wanted_values_in_memory() -> None:
    import tracemalloc

    def peak(distinct: int) -> int:
        report = _big_answer(distinct)
        tracemalloc.start()
        try:
            held = value_entries(report, [URL, HOST, "192.0.2.7:443"])
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
            assert held == [f"{URL}: ev_0001", f"{HOST}: ev_0001", "192.0.2.7:443: ev_0001"]

    # About 7 MB and a quarter of a million distinct tokens, against a
    # thousandth of it: the peak is the same.
    small, large = peak(250), peak(250_000)
    assert large < 256 * 1024, large
    assert large < small + 64 * 1024, (small, large)


def test_the_sections_of_one_report_read_its_answers_once() -> None:
    from unittest import mock

    from maljan.reporting import evidence_bundles

    report = _big_answer(10)
    wraps = evidence_bundles._value_holders
    with mock.patch.object(evidence_bundles, "_value_holders", wraps=wraps) as read:
        for section in ("communications", "command_and_control", "configuration"):
            bundle_for(section, report)
    assert read.call_count == 1
    # A report given another entry since is read again.
    report.evidence_index.append(_row("ev_0002", "iocs"))
    with mock.patch.object(evidence_bundles, "_value_holders", wraps=wraps) as read:
        bundle_for("communications", report)
    assert read.call_count == 1


def test_a_change_in_place_is_read_again_never_answered_from_the_cache() -> None:
    report = _report(
        evidence_index=[_row("ev_0030", "strings")],
        technical_evidence={"static": [_output("strings", 29, json.dumps({"text": URL}))]},
    )
    assert value_entries(report, [URL]) == [f"{URL}: ev_0030"]
    # The entry's outcome flipped in place: it no longer holds the value.
    report.evidence_index[0].ok = False
    assert value_entries(report, [URL]) == []
    report.evidence_index[0].ok = True
    assert value_entries(report, [URL]) == [f"{URL}: ev_0030"]
    # The answer's text replaced in place with one of the same length.
    output = report.technical_evidence["static"][0]
    output["output"] = output["output"].replace("beacon", "nobody")
    assert value_entries(report, [URL]) == []
