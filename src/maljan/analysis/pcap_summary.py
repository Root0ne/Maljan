"""Deterministic whole-capture analysis for the network analyst.

The structured CAPE ``network`` block (dns/tcp/udp/hosts) lists *what* was
contacted, but not the packet-level dynamics — regular callback intervals
(C2 beaconing), byte volumes (exfiltration), or the encrypted destination
names inside TLS ClientHello (SNI). Those live only in the raw PCAP.

The capture is read once, as a stream: one packet in memory at a time, and
every packet in the file unless a caller asked for fewer. A count that stops
early is not a picture of the capture — one live capture held 14,887 packets
and the network server read the first 5,000 of them — so every answer carries
how many packets were read and how many the capture holds.

``capture_facts(path)`` is the structured view (counts, protocols, every
external conversation, SNI names, beacons); ``summarize_pcap(path)`` is the
same facts as a text block. Both are best-effort and side-effect free: a file
that cannot be read as a capture returns ``None``. The capture is read by
``analysis.capture_reader``.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.capture_reader import Capture, Packet, ReadNotes
from maljan.core.logger import logger
from maljan.utils.written_forms import pack_escaped

# Beaconing: a destination contacted at least this many times with a stable
# inter-arrival interval (coefficient of variation below the threshold) is a
# regular callback — the classic C2 heartbeat the structured block can't show.
_BEACON_MIN_HITS = 4
_BEACON_MAX_CV = 0.35
_BEACON_MIN_INTERVAL_S = 1.0


@dataclass
class CaptureRead:
    """How much of one capture a reader read: the fact every answer states.

    ``limit`` is the caller's own, and ``None`` when it gave none — a read with
    no limit reads the whole capture. The rest is what the reader had to skip
    or where it stopped (``capture_reader.ReadNotes``): pcapng blocks it could
    not read and why, the byte cap a gzip capture reached, and records whose
    headers could not be walked to the end. Each appears in the fields only
    when it happened.
    """

    packets_read: int = 0
    packets_in_capture: int = 0
    limit: int | None = None
    blocks_unreadable: int = 0
    unreadable_reasons: list[str] = field(default_factory=list)
    byte_cap: int | None = None
    packets_undecoded: int = 0

    def note(self, notes: ReadNotes) -> None:
        self.blocks_unreadable = notes.blocks_unreadable
        self.unreadable_reasons = list(notes.unreadable_reasons)
        self.byte_cap = notes.byte_cap
        self.packets_undecoded = notes.packets_undecoded

    @property
    def whole(self) -> bool:
        return (
            self.packets_read >= self.packets_in_capture
            and not self.blocks_unreadable
            and self.byte_cap is None
        )

    def statement(self) -> str:
        """``"14887 of 14887 packets in the capture read"``, and why fewer when fewer.

        When blocks were skipped or a byte cap stopped the read, the capture's
        own count is not known, and the statement says what was read and why
        instead: ``"6 packets read, 1 blocks unreadable: <reason>"``.
        """
        partial = self.blocks_unreadable or self.byte_cap is not None
        if partial:
            said = f"{self.packets_read} packets read"
        else:
            said = f"{self.packets_read} of {self.packets_in_capture} packets in the capture read"
        if self.packets_read < self.packets_in_capture and self.limit is not None:
            said += f" (the caller asked for {self.limit})"
        if self.blocks_unreadable:
            said += f", {self.blocks_unreadable} blocks unreadable: " + "; ".join(
                self.unreadable_reasons
            )
        if self.byte_cap is not None:
            said += (
                f", reading stopped at the {self.byte_cap} decompressed bytes the platform "
                "allows a capture"
            )
        if self.packets_undecoded:
            said += (
                f", {self.packets_undecoded} of them read only to the headers before "
                "one that could not be decoded"
            )
        return said

    def as_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "packets_read": self.packets_read,
            "packets_in_capture": self.packets_in_capture,
            "packet_limit": self.limit,
        }
        if self.blocks_unreadable:
            fields["blocks_unreadable"] = self.blocks_unreadable
            fields["unreadable_reasons"] = list(self.unreadable_reasons)
        if self.byte_cap is not None:
            fields["byte_cap"] = self.byte_cap
        if self.packets_undecoded:
            fields["packets_undecoded"] = self.packets_undecoded
        return fields

    @classmethod
    def from_fields(cls, facts: dict[str, Any]) -> CaptureRead:
        return cls(
            packets_read=int(facts.get("packets_read") or 0),
            packets_in_capture=int(facts.get("packets_in_capture") or 0),
            limit=facts.get("packet_limit"),
            blocks_unreadable=int(facts.get("blocks_unreadable") or 0),
            unreadable_reasons=list(facts.get("unreadable_reasons") or []),
            byte_cap=facts.get("byte_cap"),
            packets_undecoded=int(facts.get("packets_undecoded") or 0),
        )


def asked_limit(packet_limit: Any) -> int | None:
    """A caller's packet limit as a positive count, or ``None`` for the whole capture.

    Nothing, zero, a negative number and a value that is not a number all mean
    no limit: a limit applies only when the caller passed one.
    """
    if packet_limit is None or isinstance(packet_limit, bool):
        return None
    try:
        wanted = int(packet_limit)
    except (TypeError, ValueError):
        return None
    return wanted if wanted > 0 else None


def each_packet(
    path: str, visit: Callable[[Packet], None], packet_limit: Any = None
) -> CaptureRead:
    """Call ``visit`` on each packet of the capture at ``path``, in file order.

    A stream: one packet in memory at a time, which is what lets a reader take
    the whole capture instead of a head of it. With a limit the walk stops
    there and the rest are counted without being decoded, so the answer still
    says how many the capture holds. Raises ``CaptureFormatError`` for a file
    that is not a capture.
    """
    limit = asked_limit(packet_limit)
    read = CaptureRead(limit=limit)
    with Capture(path) as capture:
        stream = capture.records()
        rest = 0
        for record in stream:
            if limit is not None and read.packets_read >= limit:
                rest = 1 + sum(1 for _record in stream)
                break
            read.packets_read += 1
            visit(capture.decode(record))
        read.packets_in_capture = read.packets_read + rest
        read.note(capture.notes)
    return read


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _cv(xs: list[float]) -> float:
    """Coefficient of variation (std/mean) — low = regular/periodic."""
    if len(xs) < 2:
        return 1.0
    m = _mean(xs)
    if m <= 0:
        return 1.0
    var = sum((x - m) ** 2 for x in xs) / len(xs)
    return float((var**0.5) / m)


def _extract_sni(pkt: Packet) -> str | None:
    """Best-effort TLS SNI from a ClientHello, parsed from the raw TCP payload.

    Walks the TLS record -> handshake -> extensions to the server_name.
    Returns None on any shape mismatch — SNI is a bonus signal, never a hard
    dependency.
    """
    try:
        if pkt.tcp is None or not pkt.tcp.data:
            return None
        data: bytes = pkt.tcp.data
        # TLS record: content_type(22=handshake) ver(2) len(2); handshake:
        # type(1=client_hello) len(3) ver(2) random(32) ...
        if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
            return None
        idx = 43  # after record(5) + hs header(4) + ver(2) + random(32)
        sid_len = data[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2 + cs_len
        comp_len = data[idx]
        idx += 1 + comp_len
        ext_total = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2
        end = min(idx + ext_total, len(data))
        while idx + 4 <= end:
            etype = int.from_bytes(data[idx : idx + 2], "big")
            elen = int.from_bytes(data[idx + 2 : idx + 4], "big")
            idx += 4
            if etype == 0x0000:  # server_name
                # server_name_list(2) + entry: type(1) + name_len(2) + name
                name_len = int.from_bytes(data[idx + 3 : idx + 5], "big")
                name = data[idx + 5 : idx + 5 + name_len]
                # A host name is ASCII (RFC 6066, an A-label for an IDN); a
                # byte outside it is written as an escape, not dropped. The
                # name is the sender's text, written as the triage pack
                # writes a sample's strings: control characters escaped.
                if not name:
                    return None
                return pack_escaped(name.decode("ascii", "backslashreplace"))
            idx += elen
    except Exception:
        return None
    return None


def capture_facts(pcap_path: str, packet_limit: Any = None) -> dict[str, Any] | None:
    """The capture's facts as data, or ``None`` when it could not be read.

    Keys: ``packets_read``, ``packets_in_capture``, ``packet_limit`` (the
    caller's, or ``None``), ``bytes``, ``duration_s``, ``protocols`` (count per
    ``tcp``/``udp``/``other`` of the IP packets read), ``conversations`` (every
    external destination as ``{dst, dport, proto, packets, bytes}``, the
    heaviest first), ``sni`` (``{name: ClientHello count}``) and ``beacons``
    (``{dst, dport, proto, callbacks, interval_s}``).
    """
    times: list[float] = []
    proto_counts: dict[str, int] = defaultdict(int)
    # (dst, dport, proto) -> {pkts, bytes, times}
    convs: dict[tuple[str, int, str], dict[str, Any]] = {}
    snis: dict[str, int] = defaultdict(int)
    total_bytes = 0

    def _visit(pkt: Packet) -> None:
        nonlocal total_bytes
        try:
            plen = pkt.length
            total_bytes += plen
            t = pkt.time
            if t:
                times.append(t)
            if pkt.ip_dst is None:
                return
            dst = pkt.ip_dst
            if pkt.tcp is not None:
                proto = "tcp"
                dport = pkt.tcp.dport
                if dport == 443:
                    sni = _extract_sni(pkt)
                    if sni:
                        snis[sni] += 1
            elif pkt.udp is not None:
                proto = "udp"
                dport = pkt.udp.dport
            else:
                proto = "other"
                dport = 0
            proto_counts[proto] += 1
            if not _is_external(dst):
                return  # the summary is about the external (C2) surface
            c = convs.setdefault((dst, dport, proto), {"pkts": 0, "bytes": 0, "times": []})
            c["pkts"] += 1
            c["bytes"] += plen
            if t:
                c["times"].append(t)
        except Exception:  # noqa: BLE001 — one malformed packet is not a lost capture
            return

    try:
        read = each_packet(pcap_path, _visit, packet_limit)
    except Exception as exc:
        logger.warning("pcap_summary: the capture could not be read (%s).", type(exc).__name__)
        return None

    logger.info("pcap_summary: %s", read.statement())

    beacons: list[dict[str, Any]] = []
    for (dst, dport, proto), c in convs.items():
        ts = sorted(c["times"])
        if len(ts) < _BEACON_MIN_HITS:
            continue
        deltas = [b - a for a, b in zip(ts, ts[1:], strict=False) if (b - a) > 0]
        if len(deltas) < _BEACON_MIN_HITS - 1:
            continue
        interval = _mean(deltas)
        if interval >= _BEACON_MIN_INTERVAL_S and _cv(deltas) <= _BEACON_MAX_CV:
            beacons.append(
                {
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "callbacks": len(ts),
                    "interval_s": round(interval, 1),
                }
            )

    ranked = sorted(convs.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
    return {
        **read.as_fields(),
        "bytes": total_bytes,
        "duration_s": round(max(times) - min(times), 1) if len(times) >= 2 else 0.0,
        "protocols": dict(sorted(proto_counts.items())),
        "conversations": [
            {"dst": dst, "dport": dport, "proto": proto, "packets": c["pkts"], "bytes": c["bytes"]}
            for (dst, dport, proto), c in ranked
        ],
        "sni": dict(sorted(snis.items())),
        "beacons": beacons,
    }


def conversation_line(row: dict[str, Any]) -> str:
    """``"<dst>:<port>/<proto> — N pkts, M bytes"``: one conversation as every surface writes it."""
    return (
        f"{row.get('dst')}:{row.get('dport')}/{row.get('proto')} — "
        f"{row.get('packets')} pkts, {row.get('bytes')} bytes"
    )


def summary_text(facts: dict[str, Any]) -> str:
    """The facts as the markdown block the network analyst and the report read."""
    read = CaptureRead.from_fields(facts)
    heading = "#### Packet Capture Analysis (deterministic, whole capture):"
    if not read.whole:
        heading = "#### Packet Capture Analysis (deterministic, part of the capture):"
    protocols = facts.get("protocols") or {}
    overview = (
        f"{read.statement()}: {facts.get('bytes', 0)} bytes over "
        f"{float(facts.get('duration_s') or 0.0):.1f}s. Protocols: "
        + (", ".join(f"{k}={v}" for k, v in protocols.items()) or "no IP packets")
    )
    conversations = facts.get("conversations") or []
    if not conversations:
        return (
            f"{heading}\n{overview}\nNo external (public) endpoints contacted — traffic "
            "stayed internal to the sandbox."
        )
    out = [
        heading,
        overview,
        "",
        f"External conversations (all {len(conversations)}, by volume):",
        *[f"- {conversation_line(row)}" for row in conversations],
    ]
    sni = facts.get("sni") or {}
    if sni:
        out += [
            "",
            "TLS SNI (encrypted destinations):",
            *[f"- {name} ({n} ClientHello)" for name, n in sni.items()],
        ]
    beacons = facts.get("beacons") or []
    if beacons:
        out += [
            "",
            "Beaconing detected (periodic callbacks — strong C2 signal):",
            *[
                f"- {b['dst']}:{b['dport']}/{b['proto']} — {b['callbacks']} callbacks, "
                f"~{b['interval_s']:.1f}s interval (regular; likely C2 beacon)"
                for b in beacons
            ],
        ]
    else:
        out += ["", "No regular beaconing interval detected in the packets read."]
    return "\n".join(out)


def summarize_pcap(pcap_path: str, packet_limit: Any = None) -> str | None:
    """The whole capture as a markdown block, or ``None`` when it holds no packet."""
    facts = capture_facts(pcap_path, packet_limit)
    if not facts or not facts.get("packets_read"):
        return None
    return summary_text(facts)
