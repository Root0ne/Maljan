"""A negative finding carries its coverage, and the run says what it could not establish.

``analysis.coverage`` reads, from the ledger and the analysts' final answers,
which tool looked, over which input and how much of it, whenever a claim says
something was not found, and lists what the run could not do or see from the
facts it already recorded. Coverage never overstates: where the record cannot
tell, the value is ``partial`` or ``unknown``, with the reason.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from maljan.analysis.coverage import (
    FAILED,
    FULL,
    INPUT_UNKNOWN,
    NOTHING_MISSING,
    PARTIAL,
    UNKNOWN,
    coverage_lines,
    coverage_record,
    negative_clauses,
    states_a_negative,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

SAMPLE = "/jobs/j1/sample.exe"
LAYER = "/staging/j1/carved/abc/sample.unpacked.exe"
FILE_ROLES = {"path": "path", "carved": "carved_path"}


def _entry(seq: int, tool: str, args: dict[str, Any], **kw: Any) -> LedgerEntry:
    kind = kw.pop("kind", None)
    facts = kw.pop("facts", None)
    if facts is None and kind is not None:
        facts = {"v": 1, "kind": kind, "arguments": FILE_ROLES}
    return LedgerEntry(
        id=f"ev_{seq:04d}",
        seq=seq,
        agent=kw.pop("agent", "static"),
        tool=tool,
        server=kw.pop("server", "analysis"),
        source=kw.pop("source", "mcp:analysis"),
        args=args,
        facts=facts,
        output=kw.pop("output", "{}"),
        **kw,
    )


def _claim(text: str, ref: str = "") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref or text, confidence=0.6)


def _record(entries: list[Any], *claims: ClaimEvidence, **kw: Any) -> dict[str, Any]:
    kw.setdefault("fills_staged_sample", lambda entry: False)
    record = coverage_record(
        entries=entries,
        isr_reports={"static": AgentISR(agent_id="static", domain="static", claims=list(claims))},
        sample_path=SAMPLE,
        **kw,
    )
    assert record is not None
    return record


def _only_negative(record: dict[str, Any]) -> dict[str, Any]:
    (row,) = record["negatives"]
    return row


# -- the wording reader -------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "No network indicators were found in the strings.",
        "The decoded strings show no C2 address.",
        "The rule scan matched nothing",
        "The import table does not import any networking API.",
        "Persistence is absent from the sample.",
        "It lacks a packer signature.",
        "No evidence of keylogging.",
        "The sample is not packed.",
        "No network activity.",
        "Persistence not yet observed.",
        "No C2 infrastructure.",
        "Not signed.",
        "No mutex created",
        "Did not beacon during the 120 s run",
        "It does not delete itself",
        "The 'found' list is empty: zero 'matches'.",
    ],
)
def test_a_statement_that_something_was_not_found_reads_as_a_negative(text: str) -> None:
    assert states_a_negative(text)


@pytest.mark.parametrize(
    "text",
    [
        "The sample injects code into explorer.exe.",
        "There is no doubt the sample imports WinHTTP.",
        "It does not only read the registry, it found the run key.",
        "The malware cannot be detected by most AV engines.",
        "Without admin rights it injects into explorer.exe and is not detected.",
        "It does not require administrator rights to persist.",
        "",
    ],
)
def test_a_positive_or_evasion_statement_is_not_read_as_a_negative(text: str) -> None:
    assert not states_a_negative(text)


@pytest.mark.parametrize(
    ("text", "negative"),
    [
        (
            "The sample does not import any networking API, but it calls VirtualAllocEx.",
            ["The sample does not import any networking API"],
        ),
        (
            "It injects into explorer.exe; no persistence was observed.",
            ["no persistence was observed"],
        ),
        (
            "No mutex was found. The sample beacons to its C2 however no DNS query was seen.",
            ["No mutex was found", "no DNS query was seen"],
        ),
        ("No URLs were found. [ev_0001]", ["No URLs were found [ev_0001]"]),
        ("It injects into explorer.exe, which holds the payload.", []),
    ],
)
def test_a_mixed_claim_counts_only_for_its_negative_clauses(text: str, negative: list[str]) -> None:
    assert negative_clauses(text) == negative


# -- full, and what keeps a call from it --------------------------------------


def _whole(seq: int, tool: str = "hashes", args: dict[str, Any] | None = None, **kw: Any) -> Any:
    """A call of a tool declared to read its whole input (kind ``identity``)."""
    kw.setdefault("structured", {"sha256": "ab"})
    return _entry(seq, tool, {"path": SAMPLE} if args is None else args, kind="identity", **kw)


def test_full_is_given_only_to_a_tool_declared_to_read_its_whole_input() -> None:
    entries = [_whole(1), _entry(2, "strings", {"path": SAMPLE}, kind="strings", structured={})]
    record = _record(
        entries,
        _claim("No packer signature was found [ev_0001]."),
        _claim("No URLs were found [ev_0002]."),
    )

    whole, strings = record["negatives"]
    assert whole["coverage"] == FULL
    (call,) = whole["looked"]
    assert (call["tool"], call["server"], call["kind"]) == ("hashes", "analysis", "identity")
    assert call["over"] == [{"input": "sample"}]
    assert call["read"] == "whole"
    assert whole["read_by"] == "wording"
    assert strings["coverage"] == PARTIAL
    assert strings["gaps"] == [{"gap": "not_declared_whole", "entry": "ev_0002"}]

    negatives = coverage_lines(record)[2]
    assert "coverage full" in negatives[0]
    assert "(entry `ev_0001`) looked over the sample." in negatives[0]
    assert "is of a tool no declaration says reads its whole input" in negatives[1]


@pytest.mark.parametrize(
    ("args", "named"),
    [
        ({"path": SAMPLE, "start": 4096, "end": 4352}, ["start", "end"]),
        ({"path": SAMPLE, "limit": 5}, ["limit"]),
        ({"path": SAMPLE, "encodings": ["ascii"], "min_len": 40}, ["encodings", "min_len"]),
        ({"path": SAMPLE, "rules": "rule a { condition: true }"}, ["rules"]),
        ({"path": SAMPLE, "section": ".rsrc"}, ["section"]),
    ],
)
def test_any_argument_no_declaration_marks_as_not_narrowing_makes_it_partial(
    args: dict[str, Any], named: list[str]
) -> None:
    record = _record([_whole(1, args=args)], _claim("No URL strings were found [ev_0001]."))

    row = _only_negative(record)
    assert row["coverage"] == PARTIAL
    assert row["gaps"] == [{"gap": "narrowed", "entry": "ev_0001", "by": named}]
    assert "arguments no declaration marks as not narrowing" in coverage_lines(record)[2][0]
    # The value is never printed: the entry holds it.
    assert "rsrc" not in coverage_lines(record)[2][0]


@pytest.mark.parametrize(
    "structured",
    [
        {"strings": [], "truncated": True},
        {"strings": [], "next_offset": 50},
        {"processes": [], "processes_next_offset": 20},
        {"strings": [], "shortened": [{"path": "strings", "dropped": 3}]},
        {"permissions": [], "totals": {"permissions": 900}},
        {"result": {"truncated": True}},
        {"total": 900, "returned": 0, "more": True},
        {"rows": [{"inner": {"has_more": True}}]},
    ],
)
def test_an_answer_that_says_it_holds_part_of_its_rows_is_partial(
    structured: dict[str, Any],
) -> None:
    record = _record([_whole(1, structured=structured)], _claim("No URLs were found [ev_0001]."))

    row = _only_negative(record)
    assert row["coverage"] == PARTIAL
    assert row["gaps"] == [{"gap": "capped", "entry": "ev_0001"}]


def test_an_answer_of_no_readable_shape_is_unknown() -> None:
    entries = [_whole(1, structured=None, output="sha256 ab, nothing more to say")]
    record = _record(entries, _claim("No packer signature was found [ev_0001]."))

    row = _only_negative(record)
    assert row["coverage"] == UNKNOWN
    assert row["why"] == {"answer_shape": ["ev_0001"]}
    assert "has no shape the record can read" in coverage_lines(record)[2][0]


def test_a_cut_answer_is_partial() -> None:
    entries = [_whole(1, truncated=True, chars_dropped=9)]
    record = _record(entries, _claim("No URLs were found [ev_0001]."))

    assert _only_negative(record)["gaps"] == [{"gap": "cited", "entry": "ev_0001", "state": "cut"}]


def test_a_negative_whose_tool_failed_says_its_coverage_failed() -> None:
    entries = [
        _entry(
            1,
            "floss",
            {"path": SAMPLE},
            kind="emulated_strings",
            ok=False,
            error="the tool server did not answer",
        )
    ]
    record = _record(entries, _claim("The decoded strings show no C2 [ev_0001]."))

    assert _only_negative(record)["coverage"] == FAILED
    negatives = coverage_lines(record)[2]
    assert "coverage failed" in negatives[0]
    assert "and failed (`the tool server did not answer`)" in negatives[0]


def test_a_negative_that_cites_nothing_says_its_coverage_is_unknown() -> None:
    entries = [_whole(1)]
    record = _record(
        entries,
        _claim("No persistence was observed.", "none"),
        _claim("No mutex was found [ev_0042]."),
    )

    first, second = record["negatives"]
    assert first["coverage"] == UNKNOWN
    assert second["coverage"] == UNKNOWN
    assert second["not_in_ledger"] == ["ev_0042"]
    negatives = coverage_lines(record)[2]
    assert negatives[0].endswith(
        "coverage unknown: the negative clause cites no entry the ledger holds."
    )
    assert "(it names entry `ev_0042`)" in negatives[1]


def test_coverage_uses_only_the_citations_in_the_negative_clause() -> None:
    entries = [
        _whole(1),
        _entry(
            2,
            "pcap_summary",
            {"pcap_path": "/c.pcap"},
            facts={"v": 1, "kind": "packet_summary", "arguments": {"path": "pcap_path"}},
            ok=False,
            error="no capture",
        ),
    ]
    record = _record(
        entries,
        _claim(
            "Imports VirtualAlloc [ev_0001], but no network activity was observed.", "[ev_0001]"
        ),
        _claim("Imports VirtualAlloc [ev_0001], but no DNS query was seen [ev_0002]."),
    )

    unrelated, own = record["negatives"]
    assert unrelated["negative"] == "no network activity was observed"
    assert unrelated["coverage"] == UNKNOWN
    assert own["coverage"] == FAILED
    assert [call["entry"] for call in own["looked"]] == ["ev_0002"]


def test_a_wholly_negative_claim_counts_its_evidence_field() -> None:
    record = _record([_whole(1)], _claim("No packer signature was found.", "hashes [ev_0001]"))

    assert _only_negative(record)["coverage"] == FULL


# -- related and unrelated failures -------------------------------------------


def test_a_failure_of_the_same_kind_over_the_same_input_makes_it_partial() -> None:
    entries = [
        _whole(1),
        _whole(2, server="other", source="mcp:other", ok=False, error="down", structured=None),
    ]
    record = _record(entries, _claim("No packer signature was found [ev_0001]."))

    row = _only_negative(record)
    assert row["coverage"] == PARTIAL
    assert row["gaps"] == [{"gap": "same_kind_no_answer", "entries": ["ev_0002"]}]
    missing, _looked, negatives = coverage_lines(record)
    assert "1 call of the same kind over the same input did not answer" in negatives[0]
    assert "`other`" not in negatives[0]
    assert sum("`other`" in line for line in missing) == 1


def test_an_unrelated_failure_is_listed_only_under_could_not_establish() -> None:
    entries = [
        _whole(1),
        _entry(2, "capa", {"path": SAMPLE}, kind="capability_rules", ok=False, error="timeout"),
        _entry(
            3,
            "unpack_upx",
            {"path": SAMPLE},
            kind="unpack",
            ok=False,
            error="not run: the run names no job staging directory",
        ),
    ]
    record = _record(entries, _claim("No packer signature was found [ev_0001]."))

    assert _only_negative(record)["coverage"] == FULL
    missing = coverage_lines(record)[0]
    assert any("`capa`" in line and "failed" in line for line in missing)
    assert any("`unpack_upx`" in line and "was not run" in line for line in missing)


# -- layers --------------------------------------------------------------------


def test_a_produced_layer_no_call_examined_is_a_gap_of_every_negative_over_the_sample() -> None:
    entries = [
        _whole(1),
        _entry(
            2,
            "unpack_upx",
            {"path": SAMPLE},
            kind="unpack",
            structured={"child": {"carved_path": LAYER, "sha256": "ab"}},
        ),
    ]
    record = _record(entries, _claim("No packer signature was found in the sample [ev_0001]."))

    row = _only_negative(record)
    assert row["coverage"] == PARTIAL
    assert row["gaps"] == [{"gap": "layer_never_examined", "path": LAYER, "from": "ev_0002"}]
    missing, _looked, negatives = coverage_lines(record)
    assert "was never examined" in negatives[0]
    assert any(
        line.startswith(f"The layer `{LAYER}` produced by entry `ev_0002`") for line in missing
    )


def test_a_layer_read_by_another_call_is_named_and_a_read_of_it_alone_is_a_mismatch() -> None:
    entries = [
        _entry(1, "unpack_upx", {"path": SAMPLE}, kind="unpack", structured={"carved_path": LAYER}),
        _whole(2),
        _whole(3, args={"carved_path": LAYER}),
    ]
    record = _record(
        entries,
        _claim("No packer signature was found in the sample [ev_0002]."),
        _claim("No packer signature was found in the sample [ev_0003]."),
    )

    over_sample, over_layer = record["negatives"]
    assert over_sample["gaps"] == [{"gap": "layer_not_read", "path": LAYER, "from": "ev_0001"}]
    layer = {"input": "layer", "path": LAYER, "from": "ev_0001", "from_tool": "unpack_upx"}
    assert over_layer["looked"][0]["over"] == [layer]
    assert over_layer["coverage"] == PARTIAL
    assert over_layer["gaps"] == [{"gap": "input_mismatch", "over": [layer]}]
    negatives = coverage_lines(record)[2]
    assert "was read by no call the clause cites" in negatives[0]
    assert "produced by entry `ev_0001` (`unpack_upx`)" in negatives[1]
    assert "not the sample" in negatives[1]


def test_a_read_of_another_file_does_not_stand_for_the_sample() -> None:
    record = _record(
        [_whole(1, args={"path": "/tmp/other.bin"})],
        _claim("No packer signature was found in the sample [ev_0001]."),
    )

    row = _only_negative(record)
    assert row["coverage"] == PARTIAL
    assert row["gaps"] == [
        {"gap": "input_mismatch", "over": [{"input": "file", "path": "/tmp/other.bin"}]}
    ]


def test_a_value_an_earlier_answer_held_is_never_a_layer() -> None:
    entries = [
        _entry(
            1,
            "strings",
            {"path": SAMPLE},
            kind="strings",
            structured={"strings": ["evil.example.com", "sub_1"]},
        ),
        _entry(
            2,
            "check_domain_reputation",
            {"domain": "evil.example.com"},
            facts={"v": 1, "kind": "indicator_reputation", "arguments": {"domain": "domain"}},
        ),
        _entry(3, "decompile", {"function": "sub_1"}, facts={"v": 1}),
    ]
    record = _record(
        entries,
        _claim("No URL strings were found [ev_0001]."),
        _claim("The domain shows no detections [ev_0002]."),
        _claim("No anti-debug found in sub_1 [ev_0003]."),
    )

    strings, domain, decompile = record["negatives"]
    assert not any(gap["gap"].startswith("layer") for gap in strings["gaps"])
    assert domain["looked"][0]["over"][0]["input"] == "role"
    assert decompile["coverage"] == PARTIAL
    assert {"gap": "narrowed", "entry": "ev_0003", "by": ["function"]} in decompile["gaps"]
    assert "evil.example.com" not in "\n".join(coverage_lines(record)[2])


def test_a_call_that_names_its_own_input_made_no_layer_of_it() -> None:
    other = "/staging/j1/dropped/x.bin"
    entries = [
        _entry(
            1, "strings", {"carved_path": other}, kind="strings", structured={"carved_path": other}
        )
    ]
    record = _record(entries, _claim("No URLs were found [ev_0001]."))

    assert _only_negative(record)["looked"][0]["over"] == [{"input": "file", "path": other}]
    assert record["not_established"][0]["what"] == "input"


# -- undeclared tools and declarations -----------------------------------------


def test_a_new_undeclared_mcp_tool_gets_coverage_but_never_full() -> None:
    entries = [
        _entry(
            1,
            "deep_scan",
            {"target_file": SAMPLE},
            server="newscan",
            source="mcp:newscan",
            facts={"v": 1},
        ),
        _entry(
            2,
            "lookup",
            {"indicator": "evil"},
            server="newscan",
            source="mcp:newscan",
            facts={"v": 1},
        ),
    ]
    record = _record(
        entries,
        _claim("deep_scan matched nothing [ev_0001]."),
        _claim("The lookup returned no results [ev_0002]."),
    )

    by_value, undeclared = record["negatives"]
    assert by_value["coverage"] == INPUT_UNKNOWN
    assert by_value["looked"][0]["over"] == [{"input": "sample"}]
    assert undeclared["coverage"] == PARTIAL
    assert undeclared["looked"][0]["over"] == [{"input": "undeclared"}]
    tools = {row["tool"]: row for row in record["tools"]}
    assert tools["deep_scan"]["server"] == "newscan"
    negatives = coverage_lines(record)[2]
    assert "coverage of the input unknown" in negatives[0]
    assert "how much of it the record cannot tell (the tool declares nothing)" in negatives[0]


def test_a_declared_sample_argument_the_platform_fills_in_is_the_sample() -> None:
    entries = [
        _entry(
            1,
            "hashes",
            {"carved_path": ""},
            facts={"v": 1, "kind": "identity", "arguments": FILE_ROLES},
            structured={"sha256": "ab"},
        )
    ]
    record = _record(
        entries,
        _claim("No packer signature was found [ev_0001]."),
        fills_staged_sample=lambda entry: True,
    )

    row = _only_negative(record)
    assert row["coverage"] == FULL
    assert row["looked"][0]["over"] == [{"input": "sample", "filled": True}]


def _sandbox_call(seq: int, args: dict[str, Any] | None = None) -> Any:
    return _entry(
        seq,
        "sandbox_network",
        args or {},
        server=None,
        source="sandbox",
        facts={"v": 1, "kind": "sandbox_network"},
        structured={"connections": []},
    )


@pytest.mark.parametrize("report", [{"status": "timeout", "x": 1}, None])
def test_a_negative_over_a_sandbox_report_not_observed_fails(report: Any) -> None:
    from maljan.pipeline.sandbox_status import SYNTHETIC_KEY

    held = {**report, SYNTHETIC_KEY: True} if report else None
    record = _record(
        [_sandbox_call(1)],
        _claim("No network activity was observed [ev_0001]."),
        sandbox_report=held,
    )

    row = _only_negative(record)
    assert row["looked"][0]["over"] == [{"input": "sandbox_report"}]
    assert row["coverage"] == FAILED
    assert row["why"]["input"] == "sandbox_report"
    assert "The sandbox report's own record is incomplete" in coverage_lines(record)[2][0]


def test_a_negative_over_an_observed_report_with_no_capture_is_partial() -> None:
    record = _record(
        [_sandbox_call(1), _sandbox_call(2, {"limit": 0, "offset": 0})],
        _claim("No mutex created [ev_0001]."),
        _claim("No mutex created [ev_0002]."),
        sandbox_report={"processes": []},
    )

    plain, paged = record["negatives"]
    assert plain["coverage"] == PARTIAL
    assert {"gap": "no_capture"} in plain["gaps"]
    assert {"gap": "not_declared_whole", "entry": "ev_0001"} in plain["gaps"]
    assert paged["coverage"] == PARTIAL
    assert {"gap": "narrowed", "entry": "ev_0002", "by": ["limit", "offset"]} in paged["gaps"]


def test_a_non_path_argument_is_kept_as_its_role_and_a_digest_never_the_value() -> None:
    text = "x" * 5000
    entries = [
        _entry(
            1,
            "iocs_from_text",
            {"text": text},
            facts={"v": 1, "kind": "text_iocs", "arguments": {"text": "text"}},
        )
    ]
    record = _record(entries, _claim("No indicators were found in the text [ev_0001]."))

    (label,) = _only_negative(record)["looked"][0]["over"]
    assert label["input"] == "role" and label["role"] == "text"
    assert text not in str(record)
    assert all(len(line) < 400 for block in coverage_lines(record) for line in block)


# -- what could not be established ----------------------------------------------


def test_the_could_not_establish_block_is_built_from_the_recorded_facts() -> None:
    entries = [
        _entry(1, "floss", {"path": SAMPLE}, kind="emulated_strings", ok=False, error="boom"),
        _entry(
            2,
            "strings",
            {"path": SAMPLE},
            kind="strings",
            truncated=True,
            chars_dropped=1200,
            output="cut",
        ),
        {"id": None, "seq": "not a number"},
    ]
    record = _record(
        entries,
        server_reasons=["tool server 'intel' could not be attached"],
        server_rests=2,
        unreadable=1,
        shortened=["the static analyst's input was shortened to fit its prompt"],
    )

    whats = [row["what"] for row in record["not_established"]]
    assert whats == [
        "call",
        "call",
        "input",
        "input",
        "server",
        "server_rests",
        "unreadable_rows",
        "shortened",
    ]
    missing = coverage_lines(
        record, analysts=(["network"], {"dynamic": "no sandbox data"}, ["intel"])
    )[0]
    text = "\n".join(missing)
    assert "failed over the sample (entry `ev_0001`): `boom`." in text
    assert "1,200 characters cut." in text
    assert "No sandbox report: " in text
    assert "No packet capture: no sandbox report, so no packet capture." in text
    assert "Tool server not attached: `tool server 'intel' could not be attached`." in text
    assert "2 tool server rests, listed with the run summary lines above." in text
    assert "2 ledger rows could not be read" in text
    assert "Analyst `network` failed" in text
    assert "Analyst `dynamic` was skipped (`no sandbox data`)." in text
    assert "Analyst `intel` ran and made no claims." in text
    assert "Input shortened: " in text


def test_a_guard_answer_is_counted_apart_from_the_calls() -> None:
    entries = [
        _entry(1, "strings", {"path": SAMPLE}, kind="strings"),
        _entry(
            2, "strings", {"path": SAMPLE}, kind="strings", repeated_of="ev_0002", output="refused"
        ),
    ]
    record = _record(entries)

    (tool,) = record["tools"]
    assert (tool["calls"], tool["guard_answers"]) == (1, 1)
    looked = coverage_lines(record)[1][0]
    assert "1 more answered by a guard with no tool run (counted apart" in looked


def test_a_run_that_saw_everything_says_so_and_names_the_capture() -> None:
    capture = "/jobs/j1/captures/run.pcap"
    entries = [
        _entry(
            1,
            "pcap_summary",
            {"pcap_path": capture},
            server="network",
            source="mcp:network",
            facts={"v": 1, "kind": "packet_summary", "arguments": {"path": "pcap_path"}},
        ),
    ]
    record = _record(
        entries,
        _claim("No DNS queries were observed [ev_0001]."),
        sandbox_report={"network": {"pcap_local_path": capture}},
    )

    assert record["not_established"] == []
    missing, looked, _negatives = coverage_lines(record, analysts=([], {}, []))
    assert missing == [NOTHING_MISSING]
    assert "over the packet capture" in looked[0]
    # A capture summary is not declared to read its whole input.
    assert _only_negative(record)["coverage"] == PARTIAL


def test_a_repeat_is_read_as_the_entry_that_holds_its_answer() -> None:
    entries = [
        _whole(1),
        _whole(2, repeated_of="ev_0001", output="answered from [ev_0001]", structured=None),
    ]
    record = _record(entries, _claim("No packer signature was found [ev_0002]."))

    row = _only_negative(record)
    assert row["coverage"] == FULL
    assert [call["entry"] for call in row["looked"]] == ["ev_0001"]


def test_an_entry_id_prints_through_the_code_span_guard() -> None:
    hostile = "ev_0001](http://x)\n# pwn"
    entries = [_entry(1, "strings", {"path": SAMPLE}, kind="strings", ok=False, error="x")]
    entries[0].id = hostile
    missing = coverage_lines(_record(entries))[0]
    assert "](http://x)" not in "".join(
        line.replace(f"`{hostile.replace(chr(10), ' ')}`", "") for line in missing
    )


def test_an_input_path_prints_through_the_code_span_guard() -> None:
    hostile = "/staging/j1/a`b [x](https://example.org)"
    entries = [_entry(1, "strings", {"path": hostile}, kind="strings")]
    record = _record(entries, _claim("No URLs were found [ev_0001]."))

    (line,) = coverage_lines(record)[2]
    assert f"`` {hostile} ``" in line


def test_a_stopped_run_says_its_record_may_be_incomplete() -> None:
    record = _record([], partial_reason="the run was stopped part-way")
    missing = coverage_lines(record)[0]
    assert missing[0].startswith("This record may be incomplete: the run was stopped part-way")


def test_no_record_prints_nothing() -> None:
    assert coverage_lines(None) == ([], [], [])
    assert coverage_lines({"tools": []}) == ([], [], [])


def test_the_reading_and_grouping_are_linear() -> None:
    """Many calls of one tool over distinct inputs and many negatives, each read once."""
    from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

    def build(n: int) -> Callable[[], Any]:
        entries = [
            _entry(
                i + 1,
                "file_report",
                {"hash": f"{i:064x}"},
                server="intel",
                source="mcp:intel",
                ok=bool(i % 2),
                error=None if i % 2 else "down",
                facts={"v": 1, "kind": "file_reputation", "arguments": {"hash": "hash"}},
            )
            for i in range(n)
        ]
        claims = [_claim(f"No detections were found [ev_{i + 1:04d}].") for i in range(n)]
        return lambda: _record(entries, *claims)

    build(50)()  # one-time costs (caches, lazy imports) are not the reading's
    small, large = build(400), build(1600)
    # CPU time, not wall-clock: four times the input must take under eight times
    # as long, and a quadratic reading takes sixteen times. The calls made are
    # held to the same ratio too, which a load cannot move.
    assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
    assert calls(large) <= calls(small) * 4 * 1.2 + 100


def test_the_report_node_reads_the_record_from_the_state_and_the_container() -> None:
    from types import SimpleNamespace

    from maljan.pipeline.nodes import run_coverage

    container = SimpleNamespace(
        server_degradation_reasons=lambda: ["tool server 'intel' could not be attached"],
        get_truncation_ledger=lambda: SimpleNamespace(input_shortened=[]),
    )
    state = {
        "sample_path": SAMPLE,
        "evidence_ledger": [
            _entry(1, "strings", {"path": SAMPLE}, kind="strings").model_dump(mode="json")
        ],
        "isr_reports": {
            "static": AgentISR(
                agent_id="static", domain="static", claims=[_claim("No URLs were found [ev_0001].")]
            )
        },
        "sandbox_report": None,
    }
    record = run_coverage(state, container, {"server_rests": [{"server": "a"}]}, unreadable=2)

    assert record is not None
    assert record["negatives"][0]["looked"][0]["over"][0]["input"] == "sample"
    whats = {row["what"]: row for row in record["not_established"]}
    assert whats["server_rests"]["count"] == 1
    assert whats["unreadable_rows"]["count"] == 2


def test_a_stopped_run_records_its_coverage_as_of_the_stop() -> None:
    from types import SimpleNamespace

    from maljan.analysis.disclosure import STOPPED_PART_WAY
    from maljan.pipeline.stopped_run import stopped_coverage

    container = SimpleNamespace(
        server_degradation_reasons=lambda: [],
        get_truncation_ledger=lambda: SimpleNamespace(input_shortened=[]),
    )
    state = {"sample_path": SAMPLE, "evidence_ledger": [], "isr_reports": {}}
    record = stopped_coverage(state, container, {})

    assert record is not None
    assert record["partial_reason"] == STOPPED_PART_WAY
