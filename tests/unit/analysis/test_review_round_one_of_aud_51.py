"""The review round of AUD-51: sigma flags, hint escaping, capture span, the Zw fold."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest
from sigma.rule import SigmaRule

from maljan.analysis.pcap_summary import _Intervals, capture_facts, summary_text
from maljan.analysis.sigma_layer import SigmaMemoryEvaluator
from maljan.analysis.sink_reachability import build_priority_hint
from maljan.providers.sandbox_tools import sandbox_registry_ops
from maljan.providers.static.ghidra.call_graph import call_graph_from_text
from maljan.utils.written_forms import hint_escaped

HOST = b"\x0a\x00\x00\x02"
C2 = b"\x08\x08\x08\x08"


def test_n4_a_regex_rule_keeps_the_dot_that_stops_at_a_line_break() -> None:
    rule = SigmaRule.from_yaml(
        """
title: regex dot
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    CommandLine|re: 'a.b'
  condition: sel
level: low
"""
    )
    evaluator = SigmaMemoryEvaluator(rule)
    assert evaluator.evaluate({"CommandLine": "a\nb"}, strict=False) is None
    assert evaluator.evaluate({"CommandLine": "axb"}, strict=False) is not None


def test_n4_the_rules_own_flag_is_applied_not_wrapped_inline() -> None:
    rule = SigmaRule.from_yaml(
        """
title: dotall flag
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    CommandLine|re|s: 'a.b'
  condition: sel
level: low
"""
    )
    evaluator = SigmaMemoryEvaluator(rule)
    assert evaluator.evaluate({"CommandLine": "a\nb"}, strict=False) is not None
    inline = SigmaRule.from_yaml(
        """
title: dotall flag with an inline global flag
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    CommandLine|re|s: '(?i)a.b'
  condition: sel
level: low
"""
    )
    assert SigmaMemoryEvaluator(inline).evaluate({"CommandLine": "A\nb"}, strict=False)


def test_n5_a_cpp_name_stays_readable_in_a_hint_and_a_token_does_not() -> None:
    assert hint_escaped("std::vector<int>::push_back") == "std::vector<int>::push_back"
    assert hint_escaped("operator<<") == "operator<<"
    assert "<|" not in hint_escaped("x<|im_start|>y")
    graph = call_graph_from_text("std::vector<int>::push_back -> WriteProcessMemory")
    assert "std::vector<int>::push_back" in build_priority_hint(graph)


def _frame(dport: int, payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 50000, dport, 0, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, HOST, C2)
    return ip + tcp


def _timed_capture(tmp_path: Path, seconds: list[int]) -> dict[str, Any]:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 101)
    for at in seconds:
        frame = _frame(443, b"x")
        out += struct.pack("<IIII", at, 0, len(frame), len(frame)) + frame
    target = tmp_path / "t.pcap"
    target.write_bytes(out)
    facts = capture_facts(str(target))
    assert facts is not None
    return facts


def test_n2_a_burst_and_one_late_packet_states_no_stretch(tmp_path: Path) -> None:
    facts = _timed_capture(tmp_path, [1_700_000_000, 1_700_000_001, 0xFFFFFFFF])
    assert facts["duration_s"] == float(0xFFFFFFFF - 1_700_000_000)
    assert "duration_stretched_by" not in facts
    assert "stretches" not in summary_text(facts)


def test_n2_running_interval_statistics_read_a_beacon() -> None:
    stats = _Intervals()
    for i in range(6):
        stats.add(100.0 + 30.0 * i)
    assert stats.beacon() == (6, pytest.approx(30.0))
    jitter = _Intervals()
    for at in (0.0, 3.0, 50.0, 52.0, 200.0, 201.0):
        jitter.add(at)
    assert jitter.beacon() is None


def test_an_out_of_order_conversation_reads_as_the_sorted_one_does() -> None:
    ordered = [100.0 + 30.0 * i for i in range(6)]
    shuffled = [ordered[i] for i in (3, 0, 5, 1, 4, 2)]
    a, b = _Intervals(), _Intervals()
    for t in ordered:
        a.add(t)
    for t in shuffled:
        b.add(t)
    assert b.beacon() == a.beacon() == (6, pytest.approx(30.0))


@pytest.mark.parametrize("api", ["NtSetValueKey", "ZwSetValueKey", "zwsetvaluekey"])
def test_n7_a_zw_registry_call_is_read_as_its_nt_twin(api: str) -> None:
    call = {
        "api": api,
        "arguments": [
            {"name": "FullName", "value": "HKLM\\Software\\Run"},
            {"name": "ValueName", "value": "x"},
        ],
    }
    report = {"behavior": {"processes": [{"calls": [call]}]}}
    result = sandbox_registry_ops(report)
    assert [r["operation"] for r in result["registry"]] == ["modify"]
