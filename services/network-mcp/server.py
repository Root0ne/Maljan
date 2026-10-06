import copy
import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.analysis.capture_reader import Packet
from maljan.analysis.pcap_summary import each_packet
from maljan.tools import staging
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

mcp = FastMCP("NetworkMCP")

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
]
CAPABILITIES = manifest("network", TOOL_NEEDS)

# The one argument every tool here takes a file in. Named once, because the
# refusal below names it and the platform's pinning hides it by this name.
CAPTURE_ARGUMENT = "pcap_path"


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

        def _visit(pkt: Packet) -> None:
            if pkt.dns_qname is not None:
                queries.setdefault(pkt.dns_qname.decode("utf-8", errors="ignore"), None)

        read = each_packet(str(capture), _visit, packet_limit)
        head = f"{read.statement()}."
        return "\n".join([head, *queries]) if queries else f"{head} No DNS queries in them."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_dns")


@mcp.tool()
def extract_http(pcap_path: str, packet_limit: int | None = None) -> str:
    """Extract every HTTP request line and Host header; ``packet_limit`` reads fewer packets."""
    capture = _opened("extract_http", pcap_path)
    if isinstance(capture, str):
        return capture
    try:
        requests: list[str] = []

        def _visit(pkt: Packet) -> None:
            if pkt.tcp is not None and pkt.tcp.rest:
                payload = pkt.tcp.rest.decode("utf-8", errors="ignore")
                if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    # The request line, and the Host header when there is one.
                    lines = payload.split("\r\n")
                    host = next((x for x in lines[1:] if x.lower().startswith("host: ")), "")
                    requests.append(f"{lines[0]} | {host}")

        read = each_packet(str(capture), _visit, packet_limit)
        head = f"{read.statement()}."
        return "\n".join([head, *requests]) if requests else f"{head} No HTTP requests in them."
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


if __name__ == "__main__":
    mcp.run(transport="stdio")
