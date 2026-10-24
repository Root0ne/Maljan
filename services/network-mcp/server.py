"""Packet captures over MCP: the summary, DNS and HTTP of a sandbox's capture.

Started by the worker it serves over stdio; with ``--http``, over streamable
HTTP behind its own token, from a container of its own (``MCP_BIND_ADDRESS``,
``MCP_PORT``, ``MCP_AUTH_TOKEN``, the shared sidecar plumbing's), where
``run_reader`` runs the triage pack's own reading of the capture
(``maljan.tools.readers``), which the worker then does not run itself.
"""

import copy
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.core.stdio_safe import route_logging_to_stderr

# Only when run as the stdio server: a test or tool that imports this module
# in-process keeps its own logging.
if __name__ == "__main__":
    route_logging_to_stderr()

from maljan.analysis.capture_reader import Packet
from maljan.analysis.pcap_summary import each_packet
from maljan.tools import readers, staging
from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, manifest
from maljan.tools.errors import (
    CAPTURES_REMEDIATION,
    NO_CAPTURE_REMEDIATION,
    NO_SUCH_FILE,
    PATH_OUTSIDE_ROOTS,
    code_for_exception,
    normalise_error,
    tool_error,
)
from maljan.tools.roots import PathOutsideRoots, resolve_under_roots
from maljan.utils.written_forms import pack_escaped

# Every name, request line and header read out of a capture is the sender's
# text. It is written the way the triage pack writes a sample's own strings
# (``utils.written_forms.pack_escaped``): newlines, control and format
# characters (bidirectional overrides, zero-width marks) as escapes, every
# other character as it is, so a value stays one fact on its own line and
# cannot start a line of its own text. Renderers fence a block with a fence
# longer than any backtick run inside it.

mcp = FastMCP("NetworkMCP", stateless_http=True)

# Every tool here reads the whole capture, one packet at a time
# (``analysis.pcap_summary.each_packet``, over ``analysis.capture_reader``,
# which needs no optional library), and stops early only where the
# caller passed ``packet_limit``. Each answer says how many packets it read and
# how many the capture holds: a capture that held 14,887 packets was once read
# to its 5,000th, and "No DNS queries found" about the rest of it would have
# been the platform stating something nobody looked at.

TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds("read_pcap_summary"),
    ToolNeeds("extract_dns"),
    ToolNeeds("extract_http"),
    ToolNeeds("pcap_summary"),
    ToolNeeds(readers.RUN_READER),
]
CAPABILITIES = manifest("network", TOOL_NEEDS)

# The one argument every tool here takes a file in. Named once, because the
# refusal below names it and the platform's pinning hides it by this name.
CAPTURE_ARGUMENT = "pcap_path"


def _written(value: bytes, unwritten: list[BaseException]) -> str | None:
    """One value read out of a capture, as the sender's text; ``None`` when it could not be.

    Bytes that are not UTF-8 are written as escapes rather than dropped, so
    two different names never read as one. A value that cannot be written
    (``MemoryError`` included) is counted in ``unwritten`` and costs no other.
    """
    try:
        return pack_escaped(value.decode("utf-8", errors="backslashreplace"))
    except Exception as exc:  # noqa: BLE001 - one value, counted and stated
        unwritten.append(exc)
        return None


def _isolated(
    visit: Callable[[Packet], None], unwritten: list[BaseException]
) -> Callable[[Packet], None]:
    """``visit`` for one packet at a time: a failure on one is counted, not the answer."""

    def _one(pkt: Packet) -> None:
        try:
            visit(pkt)
        except Exception as exc:  # noqa: BLE001 - one packet, counted and stated
            unwritten.append(exc)

    return _one


def _text_error(code: str, message: str, tool: str, remediation: str | None = None) -> str:
    """The structured error, as the text the three text-answering tools return."""
    return json.dumps(tool_error(code, message, tool=tool, remediation=remediation))


def _staging_root() -> Path:
    """The delivery directory a capture may have been staged into.

    The same directory the analysis sidecar writes this job's uploads to: the
    base ``MALJAN_STAGING_DIR`` names plus the job leaf the spawn composed, so
    on a host where both sidecars run a capture delivered for this job is a
    capture this server may read — and one delivered for another job is not.
    Nothing here writes to it.
    """
    return staging.staging_root()


def capture_remediation() -> str:
    """What a caller that named no readable capture is told to do instead.

    Written from these tools' own signature: ``pcap_path`` is required here, so
    the general advice to leave a path argument out would send a caller after
    a call that cannot be made. The captures are listed by the names a caller
    can pass back, relative to the job's own directory, and never as a host
    path: the refusal travels to the model, the ledger and the event feed.
    """
    names = staging.job_captures(_staging_root())
    if not names:
        return NO_CAPTURE_REMEDIATION.format(argument=CAPTURE_ARGUMENT)
    return CAPTURES_REMEDIATION.format(argument=CAPTURE_ARGUMENT, names=", ".join(names))


def _capture(pcap_path: str) -> Path:
    """One ``pcap_path`` argument, resolved inside the directories this server may read.

    A capture is named by the model, and a model that has read a sample has
    read whatever its author wrote there. A relative name is read inside this
    job's own directory — the form a refusal lists the captures in — and a bare
    file name inside its captures. Raises ``PathOutsideRoots`` for anything
    that resolves elsewhere; see ``maljan.tools.roots``.
    """
    asked = str(pcap_path or "").strip().strip("'\"")
    candidate = Path(asked)
    if asked and not candidate.is_absolute():
        root = _staging_root()
        in_job = root / candidate
        in_captures = root / staging.CAPTURES_DIRECTORY / candidate
        candidate = in_captures if in_captures.is_file() and not in_job.is_file() else in_job
    inside = resolve_under_roots(candidate, extra_roots=(_staging_root(),))
    return staging.confined_to_this_job(inside)


def _opened(tool: str, pcap_path: str) -> Path | str:
    """The capture to read, or the refusal as the text the text tools return."""
    try:
        capture = _capture(pcap_path)
    except PathOutsideRoots as refusal:
        return _text_error(PATH_OUTSIDE_ROOTS, str(refusal), tool, capture_remediation())
    if not capture.is_file():
        return _text_error(
            NO_SUCH_FILE,
            f"no such capture: {Path(str(pcap_path)).name}",
            tool,
            capture_remediation(),
        )
    return capture


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, its optional dependency, and whether it is available.
    """
    # Deep, so "computed once when the server started" also means a
    # caller cannot reach in and change what it says.
    return copy.deepcopy(CAPABILITIES)


@mcp.tool()
def read_pcap_summary(pcap_path: str, packet_limit: int | None = None, offset: int = 0) -> str:
    """Summarise a PCAP file, or list its IP packets one line each.

    With no ``packet_limit`` the answer is the whole capture's facts: packet
    count, protocols, every external conversation, TLS names and periodic
    contacts. With one, it lists ``packet_limit`` packets from ``offset``, one
    line each, and names the offset of the next page.
    """
    capture = _opened("read_pcap_summary", pcap_path)
    if isinstance(capture, str):
        return capture
    try:
        from maljan.analysis.pcap_summary import asked_limit, capture_facts, summary_text

        page = asked_limit(packet_limit)
        if page is None:
            facts = capture_facts(str(capture))
            if not facts:
                return _text_error(
                    "tool_failed", "the capture could not be read", "read_pcap_summary"
                )
            return summary_text(facts)
        start = max(0, int(offset or 0))
        output: list[str] = []
        index = 0

        def _visit(pkt: Packet) -> None:
            nonlocal index
            if index >= start and pkt.ip_dst is not None:
                proto = "Unknown"
                if pkt.tcp is not None:
                    proto = f"TCP {pkt.tcp.sport}->{pkt.tcp.dport}"
                elif pkt.udp is not None:
                    proto = f"UDP {pkt.udp.sport}->{pkt.udp.dport}"
                output.append(f"Packet {index}: {pkt.ip_src} -> {pkt.ip_dst} ({proto})")
            index += 1

        read = each_packet(str(capture), _visit, start + page)
        end = read.packets_read
        head = (
            f"Packets {start} to {max(start, end - 1)} of the {read.packets_in_capture} "
            "in the capture"
        )
        if end < read.packets_in_capture:
            head += f"; the next page starts at offset {end}"
        if read.blocks_unreadable or read.byte_cap is not None or read.packets_undecoded:
            # The count above is of what could be read; the statement says what could not.
            head += f" ({read.statement()})"
        head += "."
        return "\n".join([head, *output]) if output else f"{head} No IP packets in them."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "read_pcap_summary")


@mcp.tool()
def extract_dns(pcap_path: str, packet_limit: int | None = None) -> str:
    """Extract every DNS query name in a PCAP file; ``packet_limit`` reads fewer packets."""
    capture = _opened("extract_dns", pcap_path)
    if isinstance(capture, str):
        return capture
    try:
        queries: dict[str, None] = {}
        malformed: list[int] = []
        unwritten: list[BaseException] = []

        def _visit(pkt: Packet) -> None:
            if pkt.dns_name_octets_malformed is not None:
                malformed.append(pkt.dns_name_octets_malformed)
            if pkt.dns_qname is not None:
                written = _written(pkt.dns_qname, unwritten)
                if written is not None:
                    queries.setdefault(written, None)

        read = each_packet(str(capture), _isolated(_visit, unwritten), packet_limit)
        for octets in malformed:
            read.malformed_dns_name(octets)
        for failure in unwritten:
            read.unwritable(failure)
        head = f"{read.statement()}."
        return "\n".join([head, *queries]) if queries else f"{head} No DNS queries in them."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_dns")


# A request line as HTTP/1.x writes it: a method token (any, not a fixed
# list), a target, the version.
# The target is whatever the sender wrote (it may hold a bare line feed).
_REQUEST_LINE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+ .* HTTP/1\.[01]$", re.DOTALL)


def http_request_of(data: bytes) -> tuple[bytes, bytes] | None:
    """The request line and Host header of an HTTP/1.x request at the start of ``data``.

    Any method counts (PATCH, OPTIONS, CONNECT and a made-up one as much as
    GET). The Host header is found by name, case-insensitively, with or
    without the space after the colon, and only among the headers, never in a
    body after the blank line. ``None`` when ``data`` does not start with a
    request line; the host is the header line as sent, or ``b""`` when there is none.
    """
    head = data.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    # The five methods always read are kept as read before, however the segment
    # ends; any other method needs its whole request line.
    if not (
        data.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD "))
        or _REQUEST_LINE.match(lines[0])
    ):
        return None
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon and name.strip().lower() == b"host":
            return lines[0], line
    return lines[0], b""


@mcp.tool()
def extract_http(pcap_path: str, packet_limit: int | None = None) -> str:
    """Extract every HTTP request line and Host header; ``packet_limit`` reads fewer packets."""
    capture = _opened("extract_http", pcap_path)
    if isinstance(capture, str):
        return capture
    try:
        # Each distinct request once, in order of first appearance, with how
        # many times it was sent; a repeat is counted, not written again.
        requests: dict[tuple[bytes, bytes], list[Any]] = {}

        unwritten: list[BaseException] = []

        def _visit(pkt: Packet) -> None:
            # The segment's payload as its IP header bounds it; trailing
            # link-layer bytes are not the sender's request.
            data = pkt.tcp.data if pkt.tcp is not None else b""
            # The request line, and the Host header when there is one.
            found = http_request_of(data)
            if found is None:
                return
            request, host = found
            seen = requests.get((request, host))
            if seen is not None:
                seen[1] += 1
                return
            line, written_host = _written(request, unwritten), _written(host, unwritten)
            if line is not None and written_host is not None:
                requests[(request, host)] = [f"{line} | {written_host}", 1]

        read = each_packet(str(capture), _isolated(_visit, unwritten), packet_limit)
        for failure in unwritten:
            read.unwritable(failure)
        head = f"{read.statement()}."
        if not requests:
            return f"{head} No HTTP requests in them."
        # A request line begins with its method, so a count before it cannot be
        # mistaken for the sender's text.
        written = [
            text if count == 1 else f"{count} times: {text}" for text, count in requests.values()
        ]
        return "\n".join([head, *written])
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_http")


@mcp.tool()
def pcap_summary(pcap_path: str, packet_limit: int | None = None) -> dict[str, Any]:
    """Summarise a capture: conversations, TLS SNI destinations and beaconing.

    The whole-capture view, next to the three packet-level tools above. An
    agent that reads this first knows which conversation to go and read
    individual packets from, instead of walking the capture to find out.
    """
    from maljan.tools.pcap import pcap_summary as summarize

    capture = _opened("pcap_summary", pcap_path)
    if isinstance(capture, str):
        return dict(json.loads(capture))
    try:
        return dict(normalise_error(dict(summarize(str(capture), packet_limit=packet_limit))))
    except Exception as exc:  # noqa: BLE001 - a tool server answers, it does not raise
        return tool_error(
            code_for_exception(exc), f"{type(exc).__name__}: {exc}", tool="pcap_summary"
        )


# The tools whose readings ``run_reader`` runs here: this server's own.
_OFFERED = frozenset(need.name for need in TOOL_NEEDS)


def _reader_path(value: str, job: str) -> str:
    """A reading's file argument held to the sample roots and this job's staging directory."""
    environ: dict[str, str] = dict(os.environ)
    if job:
        environ[staging.STAGING_JOB_ENV] = staging.job_directory_name(job)
    inside = resolve_under_roots(value, extra_roots=(staging.staging_root(environ),))
    return str(staging.confined_to_this_job(inside, environ))


@mcp.tool()
def run_reader(
    reader: str, arguments: dict[str, Any] | None = None, job: str = ""
) -> dict[str, Any]:
    """Run one of the platform's own readings of the job's capture here, for the worker.

    A delivery primitive, never offered to a model: the worker's triage pack
    calls it when this server runs in a container of its own, so the capture
    is parsed here and the worker reads only the answer
    (``maljan.tools.readers``). Only a reading standing in for a tool this
    server offers is run, its file arguments held to the sample roots and
    ``job``'s staging directory.
    """
    return readers.serve_reader(reader, arguments, job, offered=_OFFERED, confine=_reader_path)


def _http_serve() -> None:
    """Serve over streamable HTTP behind the token, with the shared sidecar plumbing."""
    try:  # An image that copies the shared module beside this file.
        import cli_sidecar as sidecar
    except ModuleNotFoundError:  # The repository keeps it in a directory of its own.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
        import cli_sidecar as sidecar
    sidecar.serve(mcp, [])


if __name__ == "__main__":
    # Before the server starts its threads: C code in this process folds case
    # as ASCII does (``core.ctype_locale``). The one line goes to standard
    # error: standard output is this server's protocol.
    from maljan.core.ctype_locale import pin_character_classification, say_on_stderr

    pin_character_classification(say=say_on_stderr)
    if "--http" in sys.argv[1:]:
        _http_serve()
    else:
        mcp.run(transport="stdio")
