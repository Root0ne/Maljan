"""Deterministic full-PCAP analysis for the network analyst.

The structured CAPE ``network`` block (dns/tcp/udp/hosts) lists *what* was
contacted, but not the packet-level dynamics — regular callback intervals
(C2 beaconing), byte volumes (exfiltration), or the encrypted destination
names inside TLS ClientHello (SNI). Those live only in the raw PCAP.

Rather than hope the LLM iteratively calls PCAP MCP tools (it skips them to
stay inside its time budget — live task 9, 2026-07-11: tool_calls=0), this
module reads the **entire** capture once with scapy and folds the packet-level
intelligence into a compact text block the analyst reasons on directly.

``summarize_pcap(path)`` is best-effort and side-effect free: any parse error
(missing scapy, truncated capture, unreadable file) returns ``None`` and the
analyst simply works from the structured flows.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from maljan.core.logger import logger

# Bound memory/CPU on pathological captures — a detonation PCAP is normally a
# few thousand packets; 200k is a generous ceiling that still parses quickly.
_MAX_PACKETS = 200_000
# Beaconing: a destination contacted at least this many times with a stable
# inter-arrival interval (coefficient of variation below the threshold) is a
# regular callback — the classic C2 heartbeat the structured block can't show.
_BEACON_MIN_HITS = 4
_BEACON_MAX_CV = 0.35
_BEACON_MIN_INTERVAL_S = 1.0


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


def _extract_sni(pkt: Any) -> str | None:
    """Best-effort TLS SNI from a ClientHello, parsed from the raw TCP payload.

    Avoids scapy's optional TLS layer (not loaded by default); walks the TLS
    record -> handshake -> extensions to the server_name. Returns None on any
    shape mismatch — SNI is a bonus signal, never a hard dependency.
    """
    try:
        from scapy.all import TCP, Raw  # type: ignore[attr-defined]

        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        data: bytes = bytes(pkt[Raw].load)
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
                return name.decode("idna", "replace") if name else None
            idx += elen
    except Exception:
        return None
    return None


def summarize_pcap(pcap_path: str) -> str | None:
    """Return a compact markdown summary of the full capture, or None.

    Sections: capture overview, external conversations (bytes/packets), TLS SNI
    destinations, and detected C2 beaconing (periodic callbacks).
    """
    try:
        # ``scapy.all`` (not ``scapy.utils``) populates conf.l2types so the
        # capture's link-layer type (DLT 1 = Ethernet, from KVM/CAPE) decodes to
        # Ether/IP instead of Raw — otherwise every packet is opaque and no IP
        # endpoints are seen.
        from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore[attr-defined]
    except Exception as exc:  # scapy missing / import failure
        logger.info("pcap_summary: scapy unavailable (%s); skipping.", exc)
        return None

    try:
        packets = rdpcap(pcap_path, count=_MAX_PACKETS)
    except Exception as exc:
        logger.warning("pcap_summary: rdpcap failed for %s: %s", pcap_path, exc)
        return None

    if len(packets) == 0:
        return None

    # Audit trail: proves the FULL capture was read and folded into the
    # network analyst's evidence on this run (the analyst rephrases the
    # summary, so its ISR may not quote this text verbatim — this line is the
    # authoritative per-run record that every packet was examined).
    logger.info("pcap_summary: analyzed %d packets from %s", len(packets), pcap_path)

    times: list[float] = []
    proto_counts: dict[str, int] = defaultdict(int)
    # (dst, dport, proto) -> {pkts, bytes, times}
    convs: dict[tuple[str, int, str], dict[str, Any]] = {}
    snis: dict[str, int] = defaultdict(int)
    total_bytes = 0

    for pkt in packets:
        try:
            plen = len(pkt)
            total_bytes += plen
            t = float(getattr(pkt, "time", 0.0))
            if t:
                times.append(t)
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            dst = ip.dst
            if pkt.haslayer(TCP):
                proto = "tcp"
                dport = int(pkt[TCP].dport)
                if dport == 443:
                    sni = _extract_sni(pkt)
                    if sni:
                        snis[sni] += 1
            elif pkt.haslayer(UDP):
                proto = "udp"
                dport = int(pkt[UDP].dport)
            else:
                proto = "other"
                dport = 0
            proto_counts[proto] += 1
            if not _is_external(dst):
                continue  # focus the summary on the external (C2) surface
            key = (dst, dport, proto)
            c = convs.get(key)
            if c is None:
                c = {"pkts": 0, "bytes": 0, "times": []}
                convs[key] = c
            c["pkts"] += 1
            c["bytes"] += plen
            if t:
                c["times"].append(t)
        except Exception:
            continue

    if not convs:
        # No external traffic at all — say so explicitly (still useful signal).
        dur = (max(times) - min(times)) if len(times) >= 2 else 0.0
        return (
            "#### Packet Capture Analysis (deterministic, full capture):\n"
            f"{len(packets)} packets over {dur:.1f}s, no external (public) "
            "endpoints contacted — traffic stayed internal to the sandbox."
        )

    duration = (max(times) - min(times)) if len(times) >= 2 else 0.0

    # External conversations, ranked by bytes (exfil / heavy C2 first).
    conv_rows = sorted(convs.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
    conv_lines = []
    for (dst, dport, proto), c in conv_rows[:15]:
        conv_lines.append(f"- {dst}:{dport}/{proto} — {c['pkts']} pkts, {c['bytes']} bytes")

    # Beaconing: stable inter-arrival interval to an external destination.
    beacon_lines = []
    for (dst, dport, proto), c in convs.items():
        ts = sorted(c["times"])
        if len(ts) < _BEACON_MIN_HITS:
            continue
        deltas = [b - a for a, b in zip(ts, ts[1:], strict=False) if (b - a) > 0]
        if len(deltas) < _BEACON_MIN_HITS - 1:
            continue
        interval = _mean(deltas)
        if interval >= _BEACON_MIN_INTERVAL_S and _cv(deltas) <= _BEACON_MAX_CV:
            beacon_lines.append(
                f"- {dst}:{dport}/{proto} — {len(ts)} callbacks, "
                f"~{interval:.1f}s interval (regular; likely C2 beacon)"
            )

    out = [
        "#### Packet Capture Analysis (deterministic, full capture):",
        f"{len(packets)} packets, {total_bytes} bytes over {duration:.1f}s. "
        f"Protocols: " + ", ".join(f"{k}={v}" for k, v in sorted(proto_counts.items())),
        "",
        "External conversations (by volume):",
        *conv_lines,
    ]
    if snis:
        out += [
            "",
            "TLS SNI (encrypted destinations):",
            *[f"- {name} ({n} ClientHello)" for name, n in sorted(snis.items())],
        ]
    if beacon_lines:
        out += ["", "Beaconing detected (periodic callbacks — strong C2 signal):", *beacon_lines]
    else:
        out += ["", "No regular beaconing interval detected in the capture window."]
    return "\n".join(out)
