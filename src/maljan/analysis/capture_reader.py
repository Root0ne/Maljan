"""Read a packet capture: pcap or pcapng, plain or gzip, one packet at a time.

Written for what the network tools and the capture summary read, and nothing
more: every record's timestamp and length, the first IPv4 header, the first
TCP and UDP headers, and the first DNS question name. No third-party library:
the format work is small, and owning it keeps the decoder's rules in one place
where ``tests/unit/analysis/test_pcap_reader_parity.py`` pins them.

Framing. A pcap file in either byte order and at micro- or nanosecond
resolution; a pcapng file with any number of sections and interfaces, each
interface with its own link type and timestamp resolution; either one
compressed with gzip. A record cut short at the end of the file is read as far
as it goes. A cut inside a record header or a pcapng block ends the capture
there, and every packet before it is still read. A file that is not a capture
raises ``CaptureFormatError``.

Decoding walks the headers from the link layer in:

- link types: BSD loopback (``DLT_NULL``, ``DLT_LOOP``), Ethernet, raw IP
  (``DLT_RAW`` in both numberings, ``LINKTYPE_IPV4``, ``LINKTYPE_IPV6``), Linux
  cooked capture v1 and v2; any other link type carries no IP header here;
- below Ethernet: 802.1Q and 802.1ad tags and PPPoE sessions;
- IPv4 and IPv6 (hop-by-hop, routing, destination-options and fragment
  extension headers), and inside them IPv4, IPv6 and GRE tunnels, and VXLAN on
  its UDP ports;
- TCP and UDP; DNS on port 53 over UDP and TCP, mDNS on 5353, LLMNR on 5355;
- ICMP and ICMPv6 errors: the datagram an error quotes is read for a DNS
  question only, never as a packet of its own.

A non-first IP fragment is not read past its IP header, and a header cut short
ends the walk at the last header that was whole.
"""

from __future__ import annotations

import gzip
import ipaddress
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from typing import BinaryIO

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 6),
    b"\xd4\xc3\xb2\xa1": ("<", 6),
    b"\xa1\xb2\x3c\x4d": (">", 9),
    b"\x4d\x3c\xb2\xa1": ("<", 9),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_GZIP_MAGIC = b"\x1f\x8b"
_NOT_A_CAPTURE = "Not a supported capture file"

# A record's bytes are read in pieces no larger than this, so a length field
# claiming more than the file holds costs what the file holds, not the claim.
_READ_PIECE = 1 << 20

# Link types (tcpdump.org/linktypes.html).
_DLT_NULL = 0
_DLT_ETHERNET = (1, 23, 772)
_DLT_RAW = (12, 101)
_DLT_LOOP = 108
_DLT_LINUX_SLL = 113
_DLT_IPV4 = 228
_DLT_IPV6 = (31, 229)
_DLT_LINUX_SLL2 = 276

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_8021Q = 0x8100
_ETH_8021AD = 0x88A8
_ETH_PPPOE_SESSION = 0x8864
_ETH_BRIDGED = 0x6558  # transparent Ethernet bridging, inside GRE
_ETH_LENGTH_MAX = 1500  # an EtherType at or below this is an 802.3 length

# What a UDP payload is read as, decided by its ports: the first entry naming
# either port of the datagram decides. Ports that are neither DNS nor a tunnel
# are listed because they decide first for a datagram that names one of them.
_DNS = "dns"
_GRE = "gre"
_VXLAN = "vxlan"
_OTHER = "other"


def _either(kind: str, *ports: int) -> list[tuple[str, int, str]]:
    return [(side, port, kind) for port in ports for side in ("dport", "sport")]


_UDP_PORTS: tuple[tuple[str, int, str], ...] = (
    ("dport", 4754, _GRE),
    *_either(_DNS, 5353, 53),
    *_either(_OTHER, 137, 138, 88, 464),
    ("dport", 547, _OTHER),
    ("dport", 546, _OTHER),
    *_either(_OTHER, 1985, 2029, 4500, 500, 1701, 389),
    *_either(_DNS, 5355),
    *_either(_OTHER, 2727, 434, 2055, 2056, 9995, 9996, 6343, 123, 1812, 1813, 3799, 520),
    *_either(_OTHER, 161, 162),
    ("dport", 69, _OTHER),
    *_either(_VXLAN, 4789, 4790, 6633, 8472),
    ("dport", 48879, _VXLAN),
)
_DHCP_PORT_PAIRS = {(68, 67), (67, 68), (67, 67)}

_ICMP_ERRORS = (3, 4, 5, 11, 12)
_ICMP6_ERRORS = (1, 2, 3, 4)
_IPV6_OPTION_HEADERS = (0, 43, 60)  # hop-by-hop, routing, destination options
_IPV6_FRAGMENT_HEADER = 44

_DNS_MAX_JUMPS = 20  # compression pointers one name may follow


class CaptureFormatError(Exception):
    """The file is not a packet capture this reader can read."""


@dataclass(frozen=True, slots=True)
class Segment:
    """A TCP header's ports and what follows it.

    ``data`` is the segment's payload inside the IP datagram. ``rest`` is every
    byte of the record after the TCP header, trailing link-layer padding
    included.
    """

    sport: int
    dport: int
    data: bytes
    rest: bytes


@dataclass(frozen=True, slots=True)
class Datagram:
    sport: int
    dport: int


@dataclass(slots=True)
class Packet:
    """One record, as far as its headers could be read.

    ``time`` is the record's timestamp in seconds (``0.0`` when it carries
    none) and ``length`` its captured bytes. ``ip_src``/``ip_dst`` are the
    first IPv4 header's, ``tcp`` and ``udp`` the first of each, ``dns_qname``
    the first DNS question's name (``b"example.com."``). Each is ``None`` when
    the record holds none.
    """

    time: float = 0.0
    length: int = 0
    ip_src: str | None = None
    ip_dst: str | None = None
    tcp: Segment | None = None
    udp: Datagram | None = None
    dns_qname: bytes | None = None


@dataclass(frozen=True, slots=True)
class Record:
    time: float
    data: bytes
    linktype: int


# ---------------------------------------------------------------- framing


class _CaptureEnds(Exception):
    """The file ends here, whole or cut."""


def _read_up_to(stream: BinaryIO, size: int) -> bytes:
    """``size`` bytes, or fewer when the file ends first."""
    pieces: list[bytes] = []
    remaining = size
    while remaining > 0:
        piece = stream.read(min(remaining, _READ_PIECE))
        if not piece:
            break
        pieces.append(piece)
        remaining -= len(piece)
    return b"".join(pieces)


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = _read_up_to(stream, size)
    if len(data) != size:
        raise _CaptureEnds
    return data


def _pcap_records(stream: BinaryIO, magic: bytes) -> Iterator[Record]:
    endian, digits = _PCAP_MAGICS[magic]
    header = stream.read(20)
    if len(header) < 20:
        raise CaptureFormatError(_NOT_A_CAPTURE)
    linktype = struct.unpack(endian + "IIIII", header)[4]
    scale = Decimal(10) ** -digits

    def walk() -> Iterator[Record]:
        while True:
            head = stream.read(16)
            if len(head) < 16:
                return
            seconds, fraction, caplen, _wirelen = struct.unpack(endian + "IIII", head)
            yield Record(float(seconds + scale * fraction), _read_up_to(stream, caplen), linktype)

    return walk()


def _pcapng_options(body: bytes, endian: str) -> dict[int, bytes]:
    """A pcapng options list; an option given twice keeps its last value."""
    options: dict[int, bytes] = {}
    while len(body) >= 4:
        code, length = struct.unpack(endian + "HH", body[:4])
        if code == 0:
            break
        if 4 + length <= len(body):
            options[code] = body[4 : 4 + length]
        body = body[4 + length + (-length % 4) :]
    return options


@dataclass
class _Interface:
    linktype: int
    snaplen: int
    resolution: int  # timestamp units per second


@dataclass
class _PcapNg:
    """A pcapng stream: its sections, interfaces and packet blocks."""

    stream: BinaryIO
    endian: str = "<"
    interfaces: list[_Interface] = field(default_factory=list)

    def open(self) -> _PcapNg:
        try:
            self._section()
        except (_CaptureEnds, struct.error) as exc:
            raise CaptureFormatError(_NOT_A_CAPTURE) from exc
        return self

    def _section(self) -> None:
        """A Section Header Block, read from just after its block type."""
        raw_length = _read_exact(self.stream, 4)
        order = _read_exact(self.stream, 4)
        if order == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif order == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            raise _CaptureEnds
        length = struct.unpack(self.endian + "I", raw_length)[0]
        if length < 28:
            raise _CaptureEnds
        if struct.unpack(self.endian + "H", _read_exact(self.stream, 2))[0] != 1:
            raise _CaptureEnds  # a major version this reader does not know
        _read_exact(self.stream, 10)  # minor version, section length
        _read_exact(self.stream, length - 28)  # options
        self._tail(length)
        self.interfaces = []  # interface numbers start again in every section

    def _tail(self, length: int) -> None:
        if length % 4:
            self.stream.read(-length % 4)
        if struct.unpack(self.endian + "I", _read_exact(self.stream, 4))[0] != length:
            raise _CaptureEnds

    def _interface(self, body: bytes) -> None:
        linktype, snaplen = struct.unpack(self.endian + "HxxI", body[:8])
        resolution = 1_000_000
        exponent = _pcapng_options(body[8:], self.endian).get(9)  # if_tsresol
        if exponent is not None and len(exponent) == 1:
            resolution = (2 if exponent[0] & 0x80 else 10) ** (exponent[0] & 0x7F)
        self.interfaces.append(_Interface(linktype, snaplen, resolution))

    def _on(self, number: int) -> _Interface:
        if number >= len(self.interfaces):
            raise _CaptureEnds
        return self.interfaces[number]

    @staticmethod
    def _stamp(interface: _Interface, high: int, low: int) -> float:
        return float(Decimal((high << 32) + low) / interface.resolution)

    def records(self) -> Iterator[Record]:
        while True:
            try:
                block_type = struct.unpack(self.endian + "I", _read_exact(self.stream, 4))[0]
                if block_type == 0x0A0D0D0A:
                    self._section()
                    continue
                length = struct.unpack(self.endian + "I", _read_exact(self.stream, 4))[0]
                if length < 12:
                    return
                body = _read_exact(self.stream, length - 12)
                self._tail(length)
                record = self._block(block_type, body)
            except (_CaptureEnds, struct.error):
                return
            if record is not None:
                yield record

    def _block(self, block_type: int, body: bytes) -> Record | None:
        endian = self.endian
        if block_type == 1:  # Interface Description Block
            self._interface(body)
        elif block_type == 6:  # Enhanced Packet Block
            number, high, low, caplen, _wirelen = struct.unpack(endian + "5I", body[:20])
            interface = self._on(number)
            data = body[20 : 20 + caplen]
            return Record(self._stamp(interface, high, low), data, interface.linktype)
        elif block_type == 3:  # Simple Packet Block, which carries no timestamp
            interface = self._on(0)
            wirelen = struct.unpack(endian + "I", body[:4])[0]
            data = body[4 : 4 + min(wirelen, interface.snaplen)]
            return Record(0.0, data, interface.linktype)
        elif block_type == 2:  # Packet Block, obsolete
            number, _drops, high, low, caplen, _wirelen = struct.unpack(endian + "HH4I", body[:20])
            interface = self._on(number)
            data = body[20 : 20 + caplen]
            return Record(self._stamp(interface, high, low), data, interface.linktype)
        return None


def records(path: str) -> Iterator[Record]:
    """Every record of the capture at ``path``, in file order.

    Raises ``CaptureFormatError`` for a file that is not a capture, and what
    ``open`` raises for a file that cannot be opened.
    """
    with open(path, "rb") as raw:
        stream: BinaryIO = raw
        try:
            head = stream.read(2)
            if head == _GZIP_MAGIC:
                raw.seek(0)
                stream = gzip.GzipFile(fileobj=raw)  # type: ignore[assignment]
                head = stream.read(2)
            magic = head + stream.read(2)
        except (EOFError, gzip.BadGzipFile, zlib.error) as exc:
            raise CaptureFormatError(_NOT_A_CAPTURE) from exc
        if not magic:
            raise CaptureFormatError("No data could be read!")
        if magic in _PCAP_MAGICS:
            walk = _pcap_records(stream, magic)
        elif magic == _PCAPNG_MAGIC:
            walk = _PcapNg(stream).open().records()
        else:
            raise CaptureFormatError(_NOT_A_CAPTURE)
        try:
            yield from walk
        except (EOFError, gzip.BadGzipFile, zlib.error):
            return  # a gzip stream cut short or corrupt ends the capture there


def count_records(path: str) -> int:
    """How many records the capture at ``path`` holds, none of them decoded."""
    return sum(1 for _record in records(path))


# ---------------------------------------------------------------- decoding


def _dns_name(message: bytes, start: int) -> tuple[bytes, int]:
    """The name at ``start`` in a DNS message, and the offset just past it.

    Compression pointers are followed inside the message. A pointer that
    leaves it, a pointer seen before, or a jump past ``_DNS_MAX_JUMPS`` ends
    the name where it got to, and the offset past a name that jumped is the
    one after its first pointer. A name with no label reads as ``b"."``.
    """
    labels: list[bytes] = []
    position = start
    after_first_jump: int | None = None
    targets: list[int] = []
    while position < len(message):
        length = message[position]
        position += 1
        if length & 0xC0:  # a pointer: the two top bits set, or either of them
            if after_first_jump is None:
                after_first_jump = position + 1
            if position >= len(message):
                break
            target = ((length & 0x3F) << 8) | message[position]
            if target in targets or len(targets) >= _DNS_MAX_JUMPS:
                break
            targets.append(target)
            position = target
        elif length:
            labels.append(message[position : position + length])
            position += length
        else:
            break
    end = after_first_jump if after_first_jump is not None else position
    return b"".join(label + b"." for label in labels) or b".", end


def _dns_question(message: bytes) -> bytes | None:
    """The first question's name in a DNS or LLMNR message, or ``None``.

    The twelve-byte header must be whole, and the question its name, type and
    class. Compression pointers count from the start of ``message``.
    """
    if len(message) <= 12 or struct.unpack("!H", message[4:6])[0] == 0:
        return None
    name, end = _dns_name(message, 12)
    if len(message) - end < 4:
        return None
    return name


def _dns_over_tcp(data: bytes) -> bytes | None:
    """The first question of a DNS message over TCP, after its two-byte length."""
    if len(data) < 2:
        return None
    length = struct.unpack("!H", data[:2])[0]
    if length < 14 or len(data) < length:
        return None
    return _dns_question(data[2:])


def _udp_payload_kind(sport: int, dport: int) -> str:
    if (sport, dport) in _DHCP_PORT_PAIRS:
        return _OTHER
    for side, port, kind in _UDP_PORTS:
        if (dport if side == "dport" else sport) == port:
            return kind
    return _OTHER


@dataclass
class _Walk:
    """One record's header walk. Every reader takes ``start``, the offset of
    its header in the frame, and ``end``, where the bytes it may read end."""

    frame: bytes
    packet: Packet

    def link(self, linktype: int) -> None:
        frame, end = self.frame, len(self.frame)
        if linktype in _DLT_ETHERNET:
            self.ethernet(0, end)
        elif linktype in _DLT_RAW:
            if frame and frame[0] >> 4 == 6:
                self.ipv6(0, end)
            else:
                self.ipv4(0, end)
        elif linktype == _DLT_IPV4:
            self.ipv4(0, end)
        elif linktype in _DLT_IPV6:
            self.ipv6(0, end)
        elif linktype == _DLT_NULL and end >= 4:
            # The family is written in the capturing host's byte order and
            # its first byte read: a big-endian family reads as 0.
            self.address_family(frame[0], 4, end)
        elif linktype == _DLT_LOOP and end >= 4:
            self.address_family(struct.unpack("!I", frame[:4])[0], 4, end)
        elif linktype == _DLT_LINUX_SLL and end >= 16:
            self.cooked(struct.unpack("!H", frame[14:16])[0], 16, end)
        elif linktype == _DLT_LINUX_SLL2 and end >= 20:
            self.cooked(struct.unpack("!H", frame[0:2])[0], 20, end)

    def address_family(self, family: int, start: int, end: int) -> None:
        if family in (0, 2):
            self.ipv4(start, end)
        elif family == 10:
            self.ipv6(start, end)

    def cooked(self, protocol: int, start: int, end: int) -> None:
        if protocol == _ETH_IPV4:
            self.ipv4(start, end)
        elif protocol == _ETH_IPV6:
            self.ipv6(start, end)
        elif protocol == _ETH_8021Q:
            self.vlan(start, end)
        elif protocol == _ETH_PPPOE_SESSION:
            self.pppoe(start, end)
        elif protocol == 1:  # an Ethernet frame after the cooked header
            self.ethernet(start, end)

    def ethernet(self, start: int, end: int) -> None:
        if end - start < 14:
            return
        self.ethertype(struct.unpack("!H", self.frame[start + 12 : start + 14])[0], start + 14, end)

    def ethertype(self, kind: int, start: int, end: int) -> None:
        if kind <= _ETH_LENGTH_MAX:  # 802.3: LLC follows, not an IP header
            return
        if kind == _ETH_IPV4:
            self.ipv4(start, end)
        elif kind == _ETH_IPV6:
            self.ipv6(start, end)
        elif kind in (_ETH_8021Q, _ETH_8021AD):
            self.vlan(start, end)
        elif kind == _ETH_PPPOE_SESSION:
            self.pppoe(start, end)

    def vlan(self, start: int, end: int) -> None:
        if end - start < 4:
            return
        self.ethertype(struct.unpack("!H", self.frame[start + 2 : start + 4])[0], start + 4, end)

    def pppoe(self, start: int, end: int) -> None:
        frame = self.frame
        if end - start < 7 or frame[start + 1] != 0:  # code 0: session data
            return
        first = frame[start + 6]
        if first == 0xFF:  # HDLC-framed PPP is not read
            return
        if first & 1:  # a compressed, one-byte protocol field
            protocol, body = first, start + 7
        elif end - start >= 8:
            protocol, body = struct.unpack("!H", frame[start + 6 : start + 8])[0], start + 8
        else:
            return
        if protocol == 0x21:
            self.ipv4(body, end)
        elif protocol == 0x57:
            self.ipv6(body, end)

    def ipv4(self, start: int, end: int, quoted: bool = False) -> None:
        frame = self.frame
        if end - start < 20:
            return
        header_length = (frame[start] & 0x0F) * 4
        total_length = struct.unpack("!H", frame[start + 2 : start + 4])[0]
        fragment_offset = struct.unpack("!H", frame[start + 6 : start + 8])[0] & 0x1FFF
        protocol = frame[start + 9]
        if not quoted and self.packet.ip_dst is None:
            self.packet.ip_src = str(ipaddress.IPv4Address(frame[start + 12 : start + 16]))
            self.packet.ip_dst = str(ipaddress.IPv4Address(frame[start + 16 : start + 20]))
        if header_length < 20:  # below the minimum: nothing past it is read
            return
        body = min(start + header_length, end)
        if total_length >= header_length:  # a smaller total (TSO writes 0) is ignored
            end = min(end, start + total_length)
        if quoted:
            if fragment_offset == 0:
                self.transport(protocol, body, end, quoted=True)
        elif protocol == 41:
            self.ipv6(body, end)
        elif fragment_offset == 0:
            if protocol == 4:
                self.ipv4(body, end)
            elif protocol == 47:
                self.gre(body, end)
            elif protocol == 1:
                if end - body >= 8 and frame[body] in _ICMP_ERRORS:
                    self.ipv4(body + 8, end, quoted=True)
            else:
                self.transport(protocol, body, end)

    def ipv6(self, start: int, end: int, quoted: bool = False) -> None:
        frame = self.frame
        if end - start < 40:
            return
        payload_length = struct.unpack("!H", frame[start + 4 : start + 6])[0]
        following = frame[start + 6]
        position = start + 40
        end = min(end, position + payload_length)
        if quoted:
            self.transport(following, position, end, quoted=True)
            return
        while following in _IPV6_OPTION_HEADERS or following == _IPV6_FRAGMENT_HEADER:
            if end - position < 8:
                return
            if following == _IPV6_FRAGMENT_HEADER:
                if struct.unpack("!H", frame[position + 2 : position + 4])[0] >> 3:
                    return  # a non-first fragment
                following, position = frame[position], position + 8
            else:
                following, position = frame[position], position + (frame[position + 1] + 1) * 8
        if position > end:
            return
        if following == 41:
            self.ipv6(position, end)
        elif following == 4:
            self.ipv4(position, end)
        elif following == 47:
            self.gre(position, end)
        elif following == 58:
            if end - position >= 8 and frame[position] in _ICMP6_ERRORS:
                self.ipv6(position + 8, end, quoted=True)
        else:
            self.transport(following, position, end)

    def gre(self, start: int, end: int) -> None:
        frame = self.frame
        if end - start < 4:
            return
        flags = frame[start]
        protocol = struct.unpack("!H", frame[start + 2 : start + 4])[0]
        if protocol == 0x880B:  # PPTP's enhanced GRE is not read
            return
        header_length = 4
        header_length += 4 if flags & 0xC0 else 0  # checksum or routing present
        header_length += 4 if flags & 0x20 else 0  # key present
        header_length += 4 if flags & 0x10 else 0  # sequence number present
        if end - start < header_length:
            return
        body = start + header_length
        if protocol == _ETH_8021Q:
            self.vlan(body, end)
        elif protocol == _ETH_BRIDGED:
            self.ethernet(body, end)
        elif flags & 0x40:  # routing entries follow, and are not read
            return
        elif protocol == _ETH_IPV4:
            self.ipv4(body, end)
        elif protocol == _ETH_IPV6:
            self.ipv6(body, end)

    def transport(self, protocol: int, start: int, end: int, quoted: bool = False) -> None:
        if protocol == 6:
            self.tcp(start, end, quoted)
        elif protocol == 17:
            self.udp(start, end, quoted)

    def tcp(self, start: int, end: int, quoted: bool) -> None:
        frame = self.frame
        if end - start < 20:
            return
        sport, dport = struct.unpack("!HH", frame[start : start + 4])
        data_start = min(start + max(20, (frame[start + 12] >> 4) * 4), end)
        data = frame[data_start:end]
        if not quoted and self.packet.tcp is None:
            self.packet.tcp = Segment(sport, dport, data, frame[data_start:])
        if sport == 53 or dport == 53:
            self.question(_dns_over_tcp(data))

    def udp(self, start: int, end: int, quoted: bool) -> None:
        frame = self.frame
        if end - start < 8:
            return
        sport, dport, length = struct.unpack("!HHH", frame[start : start + 6])
        body = start + 8
        # The UDP length bounds the payload; one below the header's own eight
        # bytes counts back from the end of what the datagram holds.
        if length >= 8:
            body_end = min(end, body + length - 8)
        else:
            body_end = max(body, end + length - 8)
        if not quoted and self.packet.udp is None:
            self.packet.udp = Datagram(sport, dport)
        kind = _udp_payload_kind(sport, dport)
        if kind == _DNS:
            self.question(_dns_question(frame[body:body_end]))
        elif quoted:
            return
        elif kind == _VXLAN:
            self.vxlan(body, body_end)
        elif kind == _GRE:
            self.gre(body, body_end)

    def vxlan(self, start: int, end: int) -> None:
        if end - start < 8:
            return
        inner = start + 8
        if self.frame[start] & 0x04:  # a next-protocol field (VXLAN-GPE)
            following = self.frame[start + 3]
            if following == 1:
                self.ipv4(inner, end)
            elif following == 2:
                self.ipv6(inner, end)
            elif following in (0, 3):
                self.ethernet(inner, end)
        else:
            self.ethernet(inner, end)

    def question(self, name: bytes | None) -> None:
        if name is not None and self.packet.dns_qname is None:
            self.packet.dns_qname = name


def decode(record: Record) -> Packet:
    """One record's headers, as far as they go."""
    packet = Packet(time=record.time, length=len(record.data))
    _Walk(record.data, packet).link(record.linktype)
    return packet


def packets(path: str) -> Iterator[Packet]:
    """Every packet of the capture at ``path``, decoded, in file order."""
    for record in records(path):
        yield decode(record)
