"""Read a packet capture: pcap or pcapng, plain or gzip, one packet at a time.

Written for what the network tools and the capture summary read, and nothing
more: every record's timestamp and length, the first IPv4 header, the first
TCP and UDP headers, and the first DNS question name. No third-party library:
the format work is small, and owning it keeps the decoder's rules in one place
where ``tests/unit/analysis/test_pcap_reader_parity.py`` pins them.

Framing. A pcap file in either byte order and at micro- or nanosecond
resolution; a pcapng file with any number of sections and interfaces, each
interface with its own link type, snapshot length and timestamp resolution;
either one compressed with gzip, decompressed as a stream. A record's bytes are
read up to the snapshot length the capture declares (0 declares none) and the
rest of the record is skipped. A plain file is read whole: the channel that
delivered it already capped its size. A gzip capture is decompressed no
further than the larger of the two delivery caps (``_capture_byte_cap``: the
sample upload's and the sandbox download's), and ``ReadNotes`` says when it
stopped there.

A record cut short at the end of the file is read as far as it goes. A cut
inside a record header or a pcapng block, or a pcapng block whose trailing
length disagrees with its leading one, ends the capture there, and every
packet before it is still read. A pcapng block that is correctly framed but
cannot be read (a packet naming an interface no description declared, a fixed
part shorter than its type requires) is skipped by its length and counted in
``ReadNotes``. A file that is not a capture raises ``CaptureFormatError``.

Decoding walks the headers from the link layer in, as a loop: each header
names the next one and where it lies, so a frame of any nesting depth costs
time linear in its length.

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
ends the walk at the last header that was whole. A record the walk fails on is
kept with the headers read before the failure, marked ``undecoded``, and the
next record is read.
"""

from __future__ import annotations

import gzip
import ipaddress
import os
import struct
import zlib
from array import array
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from types import TracebackType
from typing import BinaryIO

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 6),
    b"\xd4\xc3\xb2\xa1": ("<", 6),
    b"\xa1\xb2\x3c\x4d": (">", 9),
    b"\x4d\x3c\xb2\xa1": ("<", 9),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_SECTION_HEADER = 0x0A0D0D0A
_GZIP_MAGIC = b"\x1f\x8b"
_NOT_A_CAPTURE = "Not a supported capture file"
_GZIP_ERRORS = (EOFError, gzip.BadGzipFile, zlib.error)

# Bytes skipped are read and dropped in pieces of this size, so skipping costs
# no memory however long the skipped part claims to be.
_SKIP_PIECE = 1 << 20

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

_IPV4_MAX_TOTAL_LENGTH = 0xFFFF  # the most an IPv4 total length field can state
_ICMP_ERRORS = (3, 4, 5, 11, 12)
_ICMP6_ERRORS = (1, 2, 3, 4)
_IPV6_OPTION_HEADERS = (0, 43, 60)  # hop-by-hop, routing, destination options
_IPV6_FRAGMENT_HEADER = 44

_DNS_MAX_JUMPS = 20  # compression pointers one name may follow
_DNS_MAX_NAME_OCTETS = 255  # RFC 1035 2.3.4: a name, uncompressed, root included


class CaptureFormatError(Exception):
    """The file is not a packet capture this reader can read."""


@dataclass(frozen=True, slots=True)
class Segment:
    """A TCP header's ports, and where its payload lies in the record.

    ``data`` is the segment's payload as its IP header bounds it, sliced from
    the record when asked for; bytes past the datagram are trailer or padding.
    """

    sport: int
    dport: int
    frame: bytes
    data_start: int
    data_end: int

    @property
    def data(self) -> bytes:
        return self.frame[self.data_start : self.data_end]


@dataclass(frozen=True, slots=True)
class Datagram:
    sport: int
    dport: int


@dataclass(slots=True)
class Packet:
    """One record, as far as its headers could be read.

    ``time`` is the record's timestamp in seconds (``0.0`` when it carries
    none) and ``length`` its captured bytes as read. ``ip_src``/``ip_dst`` are
    the first IPv4 header's, ``tcp`` and ``udp`` the first of each, and
    ``dns_qname`` the first DNS question's name (``b"example.com."``). Each is
    ``None`` when the record holds none. When the first question's name is
    longer than DNS allows, ``dns_name_octets_malformed`` is its length and
    ``dns_qname`` stays ``None``. ``undecoded`` is set when the walk
    failed part of the way in; the fields hold what it read before that.
    """

    time: float = 0.0
    length: int = 0
    ip_src: str | None = None
    ip_dst: str | None = None
    tcp: Segment | None = None
    udp: Datagram | None = None
    dns_qname: bytes | None = None
    dns_name_octets_malformed: int | None = None
    undecoded: bool = False


@dataclass(frozen=True, slots=True)
class Record:
    time: float
    data: bytes
    linktype: int


@dataclass
class ReadNotes:
    """What a read had to skip, or where it had to stop, and why.

    ``blocks_unreadable`` counts correctly framed pcapng blocks that could not
    be read. ``unreadable_reasons`` holds one entry per kind of reason, from a
    fixed vocabulary: how many blocks it covered and where the first one was,
    so its size is bounded by the kinds, never by the blocks. ``byte_cap`` is
    the cap in bytes when a gzip capture's decompressed bytes reached it and
    the read stopped there; ``stream_error`` says where a gzip stream could not
    be decompressed further. ``packets_undecoded`` counts the records the
    header walk failed on.
    """

    blocks_unreadable: int = 0
    unreadable_reasons: dict[str, dict[str, int | str]] = field(default_factory=dict)
    byte_cap: int | None = None
    stream_error: str | None = None
    packets_undecoded: int = 0

    def unreadable(self, reason: str, first: str) -> None:
        self.blocks_unreadable += 1
        entry = self.unreadable_reasons.setdefault(reason, {"count": 0, "first": first})
        entry["count"] = int(entry["count"]) + 1


# ---------------------------------------------------------------- framing


class _CaptureEnds(Exception):
    """The file ends here, whole or cut."""


class _Unreadable(Exception):
    """A correctly framed block that cannot be read.

    ``reason`` is one of a fixed vocabulary; ``detail`` is this block's own
    particular (the interface it named), kept only for the first of its kind.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _capture_byte_cap() -> int:
    """The cap on a gzip capture's decompressed bytes, read at call time.

    A capture reaches the reader by one of two channels, each with its own cap
    on the bytes it delivers: a sandbox download (``MAX_RESPONSE_BYTES``) or a
    sample upload (``SAMPLE_UPLOAD_MAX_BYTES``), both declared in
    ``core/delivery_limits.py``. The reader cannot tell which delivered a
    file, so it holds the decompressed bytes to the larger, and a capture is
    never cut below what either channel delivers. A plain file is never cut:
    its channel already capped its size.
    """
    from maljan.core import delivery_limits

    return max(
        int(delivery_limits.MAX_RESPONSE_BYTES), int(delivery_limits.SAMPLE_UPLOAD_MAX_BYTES)
    )


class _Source:
    """The capture's bytes, read no further than they can exist.

    For a plain file a read is clamped to what the file still holds; for a gzip
    stream, to what is left under the byte cap, and ``capped`` is set when the
    decompressed stream holds more than that.
    """

    def __init__(self, raw: BinaryIO) -> None:
        self.raw = raw
        self.stream: BinaryIO = raw
        self.size = os.fstat(raw.fileno()).st_size
        self.cap: int | None = None
        self.taken = 0
        self.capped = False

    def decompress(self) -> None:
        self.raw.seek(0)
        self.stream = gzip.GzipFile(fileobj=self.raw)  # type: ignore[assignment]
        self.cap = _capture_byte_cap()
        self.taken = 0

    def _room(self) -> int:
        limit = self.size if self.cap is None else self.cap
        return max(0, limit - self.taken)

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes; fewer when the file, or the cap, ends first."""
        wanted = min(size, self._room())
        data = self.stream.read(wanted)
        if len(data) < wanted:  # a gzip stream may answer in pieces
            buffer = bytearray(data)
            while len(buffer) < wanted:
                piece = self.stream.read(wanted - len(buffer))
                if not piece:
                    break
                buffer += piece
            data = bytes(buffer)
        self.taken += len(data)
        if self.cap is not None and len(data) < size and self._room() == 0:
            if self.stream.read(1):
                self.capped = True
        return data

    def skip(self, size: int) -> int:
        """Skip up to ``size`` bytes; how many were skipped."""
        if self.cap is None:
            skipped = min(size, self._room())
            self.raw.seek(skipped, os.SEEK_CUR)
            self.taken += skipped
            return skipped
        skipped = 0
        while skipped < size:
            piece = self.read(min(_SKIP_PIECE, size - skipped))
            if not piece:
                break
            skipped += len(piece)
        return skipped

    def exact(self, size: int) -> bytes:
        data = self.read(size)
        if len(data) != size:
            raise _CaptureEnds
        return data

    def skip_exact(self, size: int) -> None:
        if self.skip(size) != size:
            raise _CaptureEnds


def _within(caplen: int, snaplen: int) -> int:
    """How many of a record's ``caplen`` bytes are read: up to the snapshot length."""
    return min(caplen, snaplen) if snaplen else caplen


def _pcap_records(source: _Source, endian: str, digits: int) -> Iterator[Record]:
    header = source.read(20)
    if len(header) < 20:
        raise CaptureFormatError(_NOT_A_CAPTURE)
    snaplen, linktype = struct.unpack(endian + "IIIII", header)[3:]
    scale = Decimal(10) ** -digits

    def walk() -> Iterator[Record]:
        while True:
            head = source.read(16)
            if len(head) < 16:
                return
            seconds, fraction, caplen, _wirelen = struct.unpack(endian + "IIII", head)
            kept = _within(caplen, snaplen)
            data = source.read(kept)
            if len(data) == kept and kept < caplen:
                source.skip(caplen - kept)
            if source.capped and len(data) < kept:
                return  # the cap fell inside the bytes this record keeps
            yield Record(float(seconds + scale * fraction), data, linktype)
            if source.capped:
                return

    return walk()


def _pcapng_options(body: bytes, endian: str) -> dict[int, bytes]:
    """A pcapng options list; an option given twice keeps its last value."""
    options: dict[int, bytes] = {}
    view = memoryview(body)
    position = 0
    while len(body) - position >= 4:
        code, length = struct.unpack_from(endian + "HH", view, position)
        if code == 0:
            break
        if position + 4 + length <= len(body):
            options[code] = bytes(view[position + 4 : position + 4 + length])
        position += 4 + length + (-length % 4)
    return options


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    snaplen: int
    resolution: int  # timestamp units per second


_DEFAULT_RESOLUTION = 6  # if_tsresol's default: 10**6 units per second


@dataclass
class _Interfaces:
    """One section's interface descriptions, as three typed arrays.

    A row costs 7 bytes, so a section that declares millions of interfaces
    costs memory linear in them and small.
    """

    linktypes: array = field(default_factory=lambda: array("H"))
    snaplens: array = field(default_factory=lambda: array("I"))
    resolutions: array = field(default_factory=lambda: array("B"))

    def __len__(self) -> int:
        return len(self.linktypes)

    def add(self, linktype: int, snaplen: int, resolution: int) -> None:
        self.linktypes.append(linktype)
        self.snaplens.append(snaplen)
        self.resolutions.append(resolution)

    def __getitem__(self, number: int) -> _Interface:
        code = self.resolutions[number]
        units = (2 if code & 0x80 else 10) ** (code & 0x7F)
        return _Interface(self.linktypes[number], self.snaplens[number], units)


@dataclass
class _PcapNg:
    """A pcapng stream: its sections, interfaces and packet blocks."""

    source: _Source
    notes: ReadNotes
    endian: str = "<"
    interfaces: _Interfaces = field(default_factory=_Interfaces)

    def open(self) -> _PcapNg:
        try:
            self._section()
        except (_CaptureEnds, struct.error) as exc:
            raise CaptureFormatError(_NOT_A_CAPTURE) from exc
        return self

    def _u32(self, data: bytes) -> int:
        return int(struct.unpack(self.endian + "I", data)[0])

    def _section(self) -> None:
        """A Section Header Block, read from just after its block type."""
        raw_length = self.source.exact(4)
        order = self.source.exact(4)
        if order == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        elif order == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        else:
            raise _CaptureEnds
        length = self._u32(raw_length)
        if length < 28:
            raise _CaptureEnds
        if struct.unpack(self.endian + "H", self.source.exact(2))[0] != 1:
            raise _CaptureEnds  # a major version this reader does not know
        self.source.skip_exact(10)  # minor version, section length
        self.source.skip_exact(length - 28)  # options
        self._tail(length)
        self.interfaces = _Interfaces()  # interface numbers start again in every section

    def _tail(self, length: int) -> None:
        if length % 4:
            self.source.skip(-length % 4)
        if self._u32(self.source.exact(4)) != length:
            raise _CaptureEnds

    def _on(self, number: int, block: str) -> _Interface:
        if number >= len(self.interfaces):
            raise _Unreadable(
                f"{block} names an interface no interface description declared",
                f"interface {number}",
            )
        return self.interfaces[number]

    @staticmethod
    def _stamp(interface: _Interface, high: int, low: int) -> float:
        return float(Decimal((high << 32) + low) / interface.resolution)

    def records(self) -> Iterator[Record]:
        while True:
            try:
                block_type = self._u32(self.source.exact(4))
                if block_type == _SECTION_HEADER:
                    self._section()
                    continue
                length = self._u32(self.source.exact(4))
                if length < 12:
                    return
                at = self.source.taken - 8
                record, unreadable = self._block(block_type, length - 12)
                self._tail(length)
            except _CaptureEnds:
                return
            if self.source.capped:
                return
            if unreadable is not None:
                reason, detail = unreadable
                where = f"at byte {at}" + (f", {detail}" if detail else "")
                self.notes.unreadable(reason, where)
            elif record is not None:
                yield record

    def _fixed(self, body_length: int, size: int, name: str) -> bytes:
        """A block's fixed part; ``_Unreadable`` when the block is shorter."""
        if body_length < size:
            raise _Unreadable(f"{name} is shorter than its fixed part")
        return self.source.exact(size)

    def _block(
        self, block_type: int, body_length: int
    ) -> tuple[Record | None, tuple[str, str] | None]:
        """One block's body, consumed whole: its record, or why it is unreadable."""
        consumed = 0
        try:
            if block_type == 1:  # Interface Description Block
                body = self.source.exact(body_length)
                consumed = body_length
                if body_length < 8:
                    raise _Unreadable("an interface description is shorter than its fixed part")
                self._interface(body)
                return None, None
            if block_type == 6:  # Enhanced Packet Block
                fixed = self._fixed(body_length, 20, "an enhanced packet block")
                consumed = 20
                number, high, low, caplen, _wirelen = struct.unpack(self.endian + "5I", fixed)
                interface = self._on(number, "an enhanced packet block")
                kept = min(_within(caplen, interface.snaplen), body_length - 20)
                data = self.source.exact(kept)
                consumed += kept
                return Record(self._stamp(interface, high, low), data, interface.linktype), None
            if block_type == 3:  # Simple Packet Block, which carries no timestamp
                fixed = self._fixed(body_length, 4, "a simple packet block")
                consumed = 4
                interface = self._on(0, "a simple packet block")
                wirelen = self._u32(fixed)
                kept = min(_within(wirelen, interface.snaplen), body_length - 4)
                data = self.source.exact(kept)
                consumed += kept
                return Record(0.0, data, interface.linktype), None
            if block_type == 2:  # Packet Block, obsolete
                fixed = self._fixed(body_length, 20, "a packet block")
                consumed = 20
                number, _drops, high, low, caplen, _wirelen = struct.unpack(
                    self.endian + "HH4I", fixed
                )
                interface = self._on(number, "a packet block")
                kept = min(_within(caplen, interface.snaplen), body_length - 20)
                data = self.source.exact(kept)
                consumed += kept
                return Record(self._stamp(interface, high, low), data, interface.linktype), None
            return None, None
        except _Unreadable as exc:
            return None, (exc.reason, exc.detail)
        finally:
            self.source.skip_exact(body_length - consumed)

    def _interface(self, body: bytes) -> None:
        linktype, snaplen = struct.unpack(self.endian + "HxxI", body[:8])
        resolution = _DEFAULT_RESOLUTION
        exponent = _pcapng_options(body[8:], self.endian).get(9)  # if_tsresol
        if exponent is not None and len(exponent) == 1:
            resolution = exponent[0]
        self.interfaces.add(linktype, snaplen, resolution)


class Capture:
    """One capture file, open for reading; use as a context manager.

    Opening raises ``CaptureFormatError`` for a file that is not a capture,
    and what ``open`` raises for a file that cannot be opened. ``notes`` fills
    in as the records are read.
    """

    def __init__(self, path: str) -> None:
        self.notes = ReadNotes()
        raw = open(path, "rb")  # noqa: SIM115 - closed by close()
        self._source = _Source(raw)
        try:
            self._walk = self._open()
        except Exception:
            raw.close()
            raise

    def _open(self) -> Iterator[Record]:
        source = self._source
        try:
            head = source.read(2)
            if head == _GZIP_MAGIC:
                source.decompress()
                head = source.read(2)
            magic = head + source.read(2)
            if not magic:
                raise CaptureFormatError("No data could be read!")
            if magic in _PCAP_MAGICS:
                return _pcap_records(source, *_PCAP_MAGICS[magic])
            if magic == _PCAPNG_MAGIC:
                return _PcapNg(source, self.notes).open().records()
        except _GZIP_ERRORS as exc:
            raise CaptureFormatError(_NOT_A_CAPTURE) from exc
        raise CaptureFormatError(_NOT_A_CAPTURE)

    def records(self) -> Iterator[Record]:
        """Every record, in file order."""
        try:
            yield from self._walk
        except _GZIP_ERRORS as exc:
            # A gzip stream cut short, corrupt, or followed by bytes that are
            # not a gzip member ends the capture there, and the answer says so.
            self.notes.stream_error = (
                f"the gzip stream could not be decompressed past byte "
                f"{self._source.taken} ({type(exc).__name__})"
            )
        finally:
            if self._source.capped:
                self.notes.byte_cap = self._source.cap

    def decode(self, record: Record) -> Packet:
        """One record's headers; a record the walk fails on is counted and kept."""
        packet = decode(record)
        if packet.undecoded:
            self.notes.packets_undecoded += 1
        return packet

    def packets(self) -> Iterator[Packet]:
        for record in self.records():
            yield self.decode(record)

    def close(self) -> None:
        self._source.stream.close()
        self._source.raw.close()

    def __enter__(self) -> Capture:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def records(path: str) -> Iterator[Record]:
    """Every record of the capture at ``path``, in file order."""
    with Capture(path) as capture:
        yield from capture.records()


def count_records(path: str) -> int:
    """How many records the capture at ``path`` holds, none of them decoded."""
    return sum(1 for _record in records(path))


# ---------------------------------------------------------------- decoding


def _dns_name(message: bytes, start: int) -> tuple[bytes | None, int, int]:
    """The name at ``start`` in a DNS message, the offset just past it, and its octets.

    Compression pointers are followed inside the message. A pointer that
    leaves it, a pointer seen before, or a jump past ``_DNS_MAX_JUMPS`` ends
    the name where it got to, and the offset past a name that jumped is the
    one after its first pointer. A name with no label reads as ``b"."``.
    The octets are the name's length uncompressed, root included; a name
    longer than ``_DNS_MAX_NAME_OCTETS`` is not a DNS name and comes back as
    ``None`` with its length.
    """
    labels: list[bytes] = []
    octets = 1  # the root
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
        elif length:  # a label: 63 octets at most, by the two top bits
            octets += length + 1
            if octets <= _DNS_MAX_NAME_OCTETS:
                labels.append(message[position : position + length])
            position += length
        else:
            break
    end = after_first_jump if after_first_jump is not None else position
    if octets > _DNS_MAX_NAME_OCTETS:
        return None, end, octets
    return b"".join(label + b"." for label in labels) or b".", end, octets


@dataclass(frozen=True, slots=True)
class _Question:
    name: bytes | None
    octets: int


def _dns_question(message: bytes) -> _Question | None:
    """The first question of a DNS or LLMNR message, or ``None``.

    The twelve-byte header must be whole, and the question its name, type and
    class. Compression pointers count from the start of ``message``. A name
    longer than DNS allows comes back with ``name`` ``None`` and its length.
    """
    if len(message) <= 12 or struct.unpack("!H", message[4:6])[0] == 0:
        return None
    name, end, octets = _dns_name(message, 12)
    if len(message) - end < 4:
        return None
    return _Question(name, octets)


def _dns_over_tcp(data: bytes) -> _Question | None:
    """The first question of a DNS message over TCP, after its two-byte length."""
    if len(data) < 2:
        return None
    length = struct.unpack("!H", data[:2])[0]
    if length < 14 or len(data) < length:
        return None
    return _dns_question(data[2:])


def _jumbo_length(frame: bytes, position: int, end: int, following: int) -> int:
    """An IPv6 jumbogram's payload length from its hop-by-hop option, else 0."""
    if following != 0 or end - position < 8:
        return 0
    header_end = min(end, position + (frame[position + 1] + 1) * 8)
    option = position + 2
    while option < header_end:
        kind = frame[option]
        if kind == 0:  # Pad1
            option += 1
            continue
        if option + 2 > header_end:
            break
        size = frame[option + 1]
        if kind == 0xC2 and size == 4 and option + 6 <= header_end:
            return int(struct.unpack("!I", frame[option + 2 : option + 6])[0])
        option += 2 + size
    return 0


def _udp_payload_kind(sport: int, dport: int) -> str:
    if (sport, dport) in _DHCP_PORT_PAIRS:
        return _OTHER
    for side, port, kind in _UDP_PORTS:
        if (dport if side == "dport" else sport) == port:
            return kind
    return _OTHER


# One step of the walk: the header to read next, where it starts, where the
# bytes it may read end, and whether it lies inside an ICMP error's quote.
_Step = tuple[Callable[[int, int, bool], "_Step | None"], int, int, bool]


@dataclass
class _Walk:
    """One record's header walk. Each reader takes ``start``, the offset of
    its header in the frame, and ``end``, where the bytes it may read end; it
    fills ``packet`` with what it finds and returns the next step, or
    ``None`` where the walk ends."""

    frame: bytes
    packet: Packet

    def run(self, linktype: int) -> None:
        step = self.link(linktype)
        while step is not None:
            read, start, end, quoted = step
            step = read(start, end, quoted)

    def link(self, linktype: int) -> _Step | None:
        frame, end = self.frame, len(self.frame)
        if linktype in _DLT_ETHERNET:
            return (self.ethernet, 0, end, False)
        if linktype in _DLT_RAW:
            if frame and frame[0] >> 4 == 6:
                return (self.ipv6, 0, end, False)
            return (self.ipv4, 0, end, False)
        if linktype == _DLT_IPV4:
            return (self.ipv4, 0, end, False)
        if linktype in _DLT_IPV6:
            return (self.ipv6, 0, end, False)
        if linktype == _DLT_NULL and end >= 4:
            # The family is written in the capturing host's byte order and
            # its first byte read: a big-endian family reads as 0.
            return self.address_family(frame[0], 4, end)
        if linktype == _DLT_LOOP and end >= 4:
            return self.address_family(struct.unpack("!I", frame[:4])[0], 4, end)
        if linktype == _DLT_LINUX_SLL and end >= 16:
            return self.cooked(struct.unpack("!H", frame[14:16])[0], 16, end)
        if linktype == _DLT_LINUX_SLL2 and end >= 20:
            return self.cooked(struct.unpack("!H", frame[0:2])[0], 20, end)
        return None

    def address_family(self, family: int, start: int, end: int) -> _Step | None:
        if family in (0, 2):
            return (self.ipv4, start, end, False)
        if family == 10:
            return (self.ipv6, start, end, False)
        return None

    def cooked(self, protocol: int, start: int, end: int) -> _Step | None:
        if protocol == _ETH_IPV4:
            return (self.ipv4, start, end, False)
        if protocol == _ETH_IPV6:
            return (self.ipv6, start, end, False)
        if protocol == _ETH_8021Q:
            return (self.vlan, start, end, False)
        if protocol == _ETH_PPPOE_SESSION:
            return (self.pppoe, start, end, False)
        if protocol == 1:  # an Ethernet frame after the cooked header
            return (self.ethernet, start, end, False)
        return None

    def ethertype(self, kind: int, start: int, end: int) -> _Step | None:
        if kind <= _ETH_LENGTH_MAX:  # 802.3: LLC follows, not an IP header
            return None
        if kind == _ETH_IPV4:
            return (self.ipv4, start, end, False)
        if kind == _ETH_IPV6:
            return (self.ipv6, start, end, False)
        if kind in (_ETH_8021Q, _ETH_8021AD):
            return (self.vlan, start, end, False)
        if kind == _ETH_PPPOE_SESSION:
            return (self.pppoe, start, end, False)
        return None

    def ethernet(self, start: int, end: int, _quoted: bool = False) -> _Step | None:
        if end - start < 14:
            return None
        kind = struct.unpack("!H", self.frame[start + 12 : start + 14])[0]
        return self.ethertype(kind, start + 14, end)

    def vlan(self, start: int, end: int, _quoted: bool = False) -> _Step | None:
        if end - start < 4:
            return None
        kind = struct.unpack("!H", self.frame[start + 2 : start + 4])[0]
        return self.ethertype(kind, start + 4, end)

    def pppoe(self, start: int, end: int, _quoted: bool = False) -> _Step | None:
        frame = self.frame
        if end - start < 7 or frame[start + 1] != 0:  # code 0: session data
            return None
        first = frame[start + 6]
        if first == 0xFF:  # HDLC-framed PPP is not read
            return None
        if first & 1:  # a compressed, one-byte protocol field
            protocol, body = first, start + 7
        elif end - start >= 8:
            protocol, body = struct.unpack("!H", frame[start + 6 : start + 8])[0], start + 8
        else:
            return None
        if protocol == 0x21:
            return (self.ipv4, body, end, False)
        if protocol == 0x57:
            return (self.ipv6, body, end, False)
        return None

    def ipv4(self, start: int, end: int, quoted: bool = False) -> _Step | None:
        frame = self.frame
        if end - start < 20:
            return None
        header_length = (frame[start] & 0x0F) * 4
        total_length = struct.unpack("!H", frame[start + 2 : start + 4])[0]
        fragment_offset = struct.unpack("!H", frame[start + 6 : start + 8])[0] & 0x1FFF
        protocol = frame[start + 9]
        if not quoted and self.packet.ip_dst is None:
            self.packet.ip_src = str(ipaddress.IPv4Address(frame[start + 12 : start + 16]))
            self.packet.ip_dst = str(ipaddress.IPv4Address(frame[start + 16 : start + 20]))
        if header_length < 20:  # below the minimum: nothing past it is read
            return None
        body = min(start + header_length, end)
        # The datagram ends where its own header says; bytes past the total are
        # trailer or padding. A total below the header length is what segmentation
        # offload writes (Windows LSOv2, Linux BIG TCP write 0): the payload is
        # the rest of the frame, up to the 65,535 octets an IPv4 header can state.
        if total_length >= header_length:
            end = min(end, start + total_length)
        else:
            end = min(end, start + _IPV4_MAX_TOTAL_LENGTH)
        if quoted:
            if fragment_offset == 0:
                return self.transport(protocol, body, end, quoted=True)
            return None
        if protocol == 41:
            return (self.ipv6, body, end, False)
        if fragment_offset != 0:
            return None
        if protocol == 4:
            return (self.ipv4, body, end, False)
        if protocol == 47:
            return (self.gre, body, end, False)
        if protocol == 1:
            if end - body >= 8 and frame[body] in _ICMP_ERRORS:
                return (self.ipv4, body + 8, end, True)
            return None
        return self.transport(protocol, body, end)

    def ipv6(self, start: int, end: int, quoted: bool = False) -> _Step | None:
        frame = self.frame
        if end - start < 40:
            return None
        payload_length = struct.unpack("!H", frame[start + 4 : start + 6])[0]
        following = frame[start + 6]
        position = start + 40
        if payload_length == 0 and not quoted:
            # A jumbogram states its length in a hop-by-hop option; with none,
            # a payload length of 0 declares no payload.
            payload_length = _jumbo_length(frame, position, end, following)
        end = min(end, position + payload_length)
        if quoted:
            return self.transport(following, position, end, quoted=True)
        while following in _IPV6_OPTION_HEADERS or following == _IPV6_FRAGMENT_HEADER:
            if end - position < 8:
                return None
            if following == _IPV6_FRAGMENT_HEADER:
                if struct.unpack("!H", frame[position + 2 : position + 4])[0] >> 3:
                    return None  # a non-first fragment
                following, position = frame[position], position + 8
            else:
                following, position = frame[position], position + (frame[position + 1] + 1) * 8
        if position > end:
            return None
        if following == 41:
            return (self.ipv6, position, end, False)
        if following == 4:
            return (self.ipv4, position, end, False)
        if following == 47:
            return (self.gre, position, end, False)
        if following == 58:
            if end - position >= 8 and frame[position] in _ICMP6_ERRORS:
                return (self.ipv6, position + 8, end, True)
            return None
        return self.transport(following, position, end)

    def gre(self, start: int, end: int, _quoted: bool = False) -> _Step | None:
        frame = self.frame
        if end - start < 4:
            return None
        flags = frame[start]
        protocol = struct.unpack("!H", frame[start + 2 : start + 4])[0]
        if protocol == 0x880B:  # PPTP's enhanced GRE is not read
            return None
        header_length = 4
        header_length += 4 if flags & 0xC0 else 0  # checksum or routing present
        header_length += 4 if flags & 0x20 else 0  # key present
        header_length += 4 if flags & 0x10 else 0  # sequence number present
        if end - start < header_length:
            return None
        body = start + header_length
        if protocol == _ETH_8021Q:
            return (self.vlan, body, end, False)
        if protocol == _ETH_BRIDGED:
            return (self.ethernet, body, end, False)
        if flags & 0x40:  # routing entries follow, and are not read
            return None
        if protocol == _ETH_IPV4:
            return (self.ipv4, body, end, False)
        if protocol == _ETH_IPV6:
            return (self.ipv6, body, end, False)
        return None

    def transport(self, protocol: int, start: int, end: int, quoted: bool = False) -> _Step | None:
        if protocol == 6:
            return (self.tcp, start, end, quoted)
        if protocol == 17:
            return (self.udp, start, end, quoted)
        return None

    def tcp(self, start: int, end: int, quoted: bool) -> _Step | None:
        frame = self.frame
        if end - start < 20:
            return None
        sport, dport = struct.unpack("!HH", frame[start : start + 4])
        data_start = min(start + max(20, (frame[start + 12] >> 4) * 4), end)
        if not quoted and self.packet.tcp is None:
            self.packet.tcp = Segment(sport, dport, frame, data_start, end)
        if sport == 53 or dport == 53:
            self.question(_dns_over_tcp(frame[data_start:end]))
        return None

    def udp(self, start: int, end: int, quoted: bool) -> _Step | None:
        frame = self.frame
        if end - start < 8:
            return None
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
            return None
        if quoted:
            return None
        if kind == _VXLAN:
            return (self.vxlan, body, body_end, False)
        if kind == _GRE:
            return (self.gre, body, body_end, False)
        return None

    def vxlan(self, start: int, end: int, _quoted: bool = False) -> _Step | None:
        if end - start < 8:
            return None
        inner = start + 8
        if self.frame[start] & 0x04:  # a next-protocol field (VXLAN-GPE)
            following = self.frame[start + 3]
            if following == 1:
                return (self.ipv4, inner, end, False)
            if following == 2:
                return (self.ipv6, inner, end, False)
            if following in (0, 3):
                return (self.ethernet, inner, end, False)
            return None
        return (self.ethernet, inner, end, False)

    def question(self, question: _Question | None) -> None:
        packet = self.packet
        if question is None or packet.dns_qname is not None:
            return
        if packet.dns_name_octets_malformed is not None:
            return
        if question.name is None:
            packet.dns_name_octets_malformed = question.octets
        else:
            packet.dns_qname = question.name


def decode(record: Record) -> Packet:
    """One record's headers, as far as they go; never raises.

    A record the walk fails on comes back with what was read before the
    failure and ``undecoded`` set.
    """
    packet = Packet(time=record.time, length=len(record.data))
    try:
        _Walk(record.data, packet).run(record.linktype)
    except Exception:  # noqa: BLE001 - one record never costs the capture
        packet.undecoded = True
    return packet


def packets(path: str) -> Iterator[Packet]:
    """Every packet of the capture at ``path``, decoded, in file order."""
    with Capture(path) as capture:
        yield from capture.packets()
