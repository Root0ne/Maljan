"""What a capture contains, as one summary an agent can read in a turn.

A thin tool-shaped view over ``analysis/pcap_summary``: that module already
owns the conversation roll-up, the SNI extraction and the beacon-interval
statistic, and a second implementation would be a second place for the packet
walk to be wrong. Exposed by the existing ``network`` sidecar next to its three
packet-level tools, so an agent can ask for the whole picture before it starts
reading individual packets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def pcap_summary(path: str, packet_limit: Any = None) -> dict[str, Any]:
    """The capture's summary: the text, and the facts it is written from.

    The whole capture unless ``packet_limit`` asks for fewer packets, and the
    answer says how many packets were read and how many the capture holds —
    a head of a capture read as the whole of it is how a beacon disappears.
    The facts (``protocols``, ``conversations``, ``sni``, ``beacons``) are
    what the triage pack renders its line from.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "pcap_summary"}
    try:
        from maljan.analysis.pcap_summary import capture_facts, summary_text
    except ImportError as exc:
        return {"error": f"scapy is not installed: {exc}", "tool": "pcap_summary"}
    try:
        facts = capture_facts(str(target), packet_limit)
    except Exception as exc:  # noqa: BLE001 — a malformed capture is an answer
        return {
            "error": f"pcap read failed: {type(exc).__name__}: {exc}",
            "tool": "pcap_summary",
        }
    if not facts or not facts.get("packets_read"):
        from maljan.analysis.pcap_summary import asked_limit

        return {
            "summary": "",
            "empty": True,
            "packets_read": 0,
            "packets_in_capture": int((facts or {}).get("packets_in_capture") or 0),
            "packet_limit": asked_limit(packet_limit),
        }
    return {"summary": summary_text(facts), "empty": False, **facts}
