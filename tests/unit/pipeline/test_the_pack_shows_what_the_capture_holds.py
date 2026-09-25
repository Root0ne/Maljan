"""The pack shows the capture's counts and conversations, and a claim it holds nothing is asked.

The pack used to print the capture summary's heading alone. A report model
then wrote that the capture entry "holds only a header line with no parsed
flows" about an entry listing its packet count, its protocols and fifteen
conversations. The line now carries the facts within the pack's room, and a
statement that an entry holds nothing, or one line, is checked against it.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.pipeline import triage_pack
from maljan.pipeline.validation import (
    ENTRY_CONTENTS_MISSTATED_CODE,
    KEPT_WITH_A_FINDING,
    EntryTexts,
    misstated_entry_contents,
)
from maljan.schemas.evidence import build_entry


def _facts(conversations: int = 3) -> dict[str, Any]:
    return {
        "summary": "#### Packet Capture Analysis (deterministic, whole capture):\n...",
        "empty": False,
        "packets_read": 1200,
        "packets_in_capture": 1200,
        "packet_limit": None,
        "bytes": 90_000,
        "duration_s": 60.0,
        "protocols": {"other": 2, "tcp": 1100, "udp": 98},
        "conversations": [
            {
                "dst": f"198.51.100.{i}",
                "dport": 443,
                "proto": "tcp",
                "packets": 100 - i,
                "bytes": 9000 - i,
            }
            for i in range(conversations)
        ],
        "sni": {},
        "beacons": [],
    }


def _entry(tool: str, payload: Any, number: int = 17) -> Any:
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="pipeline",
        tool=tool,
        args={},
        server="pipeline",
        output=json.dumps(payload),
        stage="triage_pack",
    )


class TestThePackLine:
    def test_the_line_carries_the_counts_the_protocols_and_the_conversations(self) -> None:
        line = triage_pack._pack_line(_entry("pcap_summary", _facts()))

        assert "1,200 of 1,200 packets in the capture read" in line
        assert "tcp 1,100" in line and "udp 98" in line
        assert "all 3 external conversations by volume" in line
        assert "198.51.100.0:443/tcp — 100 pkts, 9000 bytes" in line
        assert "contacts at a regular interval: none detected" in line

    def test_a_short_room_keeps_the_heaviest_conversations_and_says_so(self) -> None:
        entry = _entry("pcap_summary", _facts(conversations=40))

        line = triage_pack._within_room(entry, 600)

        assert line is not None and len(line) <= 600
        assert "of 40 external conversations by volume (the rest are in the entry)" in line
        assert "198.51.100.0:443/tcp" in line

    def test_an_entry_recorded_before_the_facts_keeps_its_whole_text(self) -> None:
        entry = _entry("pcap_summary", {"summary": "line one\nline two", "empty": False})

        assert "line one line two" in triage_pack._pack_line(entry)


class TestAStatementThatAnEntryHoldsNothing:
    @staticmethod
    def _entries() -> EntryTexts:
        return EntryTexts.from_ledger(
            [
                _entry("pcap_summary", _facts(), 17),
                _entry("sandbox_registry_ops", {"registry": [], "total": 0}, 21),
                _entry("yara_scan", {"matches": [], "rule_count": 31}, 7),
            ]
        )

    def test_one_line_said_of_an_entry_holding_more_is_asked(self) -> None:
        payload = {
            "key_findings": [
                "No YARA rule matched and the packet-capture entry holds only a header line "
                "with no parsed flows [ev_0007, ev_0017]."
            ]
        }

        [violation] = misstated_entry_contents(payload, self._entries())

        assert violation.code == ENTRY_CONTENTS_MISSTATED_CODE
        assert "ev_0017 (pcap_summary)" in violation.message
        assert ENTRY_CONTENTS_MISSTATED_CODE in KEPT_WITH_A_FINDING

    def test_nothing_said_of_an_entry_that_records_an_absence_stands(self) -> None:
        payload = {"body": "The registry view records no entries [ev_0021]."}

        assert misstated_entry_contents(payload, self._entries()) == []

    def test_an_entry_the_sentence_does_not_name_is_not_judged(self) -> None:
        payload = {"body": "The registry view is empty [ev_0021, ev_0017]."}

        assert misstated_entry_contents(payload, self._entries()) == []

    def test_a_partial_entry_is_never_said_to_hold_more(self) -> None:
        entries = self._entries()
        partial = EntryTexts(
            texts=entries.texts, tools=entries.tools, partial=frozenset({"ev_0017"})
        )
        payload = {"body": "The capture entry holds only a header line [ev_0017]."}

        assert misstated_entry_contents(payload, partial) == []
