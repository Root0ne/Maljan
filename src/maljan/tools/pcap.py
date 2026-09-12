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


def pcap_summary(path: str, packet_limit: int = 5000) -> dict[str, Any]:
    """A text summary of the capture, plus how many packets backed it.

    ``packet_limit`` bounds the walk so a multi-gigabyte capture cannot hold a
    tool call open; the summary says when it was reached, because a truncated
    picture read as a complete one is how a beacon disappears.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "pcap_summary"}
    try:
        from maljan.analysis.pcap_summary import summarize_pcap
    except ImportError as exc:
        return {"error": f"scapy is not installed: {exc}", "tool": "pcap_summary"}
    try:
        summary = summarize_pcap(str(target))
    except Exception as exc:  # noqa: BLE001 — a malformed capture is an answer
        return {
            "error": f"pcap read failed: {type(exc).__name__}: {exc}",
            "tool": "pcap_summary",
        }
    if not summary:
        return {"summary": "", "empty": True, "packet_limit": int(packet_limit)}
    return {"summary": summary, "empty": False, "packet_limit": int(packet_limit)}
