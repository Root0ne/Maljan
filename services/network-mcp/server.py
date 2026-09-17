import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, manifest, module
from maljan.tools.errors import (
    MISSING_DEPENDENCY,
    NO_SUCH_FILE,
    PATH_OUTSIDE_ROOTS,
    code_for_exception,
    normalise_error,
    tool_error,
)
from maljan.tools.roots import PathOutsideRoots, resolve_under_roots

# scapy is the one library every tool here reads a capture with. Imported
# guarded so a host without it still starts the server and answers the
# manifest, and every tool then answers the same error instead of the server
# never coming up.
try:
    from scapy.all import (  # type: ignore[attr-defined]
        DNSQR,
        IP,
        TCP,
        UDP,
        rdpcap,
    )

    _SCAPY_MISSING: str | None = None
except ModuleNotFoundError as exc:  # pragma: no cover - depends on the host
    DNSQR = IP = TCP = UDP = rdpcap = None  # type: ignore[assignment]
    _SCAPY_MISSING = f"scapy is not installed ({exc})"
except ImportError as exc:  # pragma: no cover - depends on the host
    # A broken install rather than an absent one. Its message names absolute
    # paths on this host, and this reason travels to a probe response, the
    # console and the judge's prompt, so only the type crosses.
    DNSQR = IP = TCP = UDP = rdpcap = None  # type: ignore[assignment]
    _SCAPY_MISSING = f"scapy is not installed ({type(exc).__name__})"

mcp = FastMCP("NetworkMCP")

# How many packets a tool reads when the caller does not say. Every tool here
# takes it: ``rdpcap`` with no count reads the whole capture into memory, and
# a capture is as large as the detonation made it. 5000 is what the
# whole-capture summary has always used.
DEFAULT_PACKET_LIMIT = 5000

TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds("read_pcap_summary", (module("scapy"),)),
    ToolNeeds("extract_dns", (module("scapy"),)),
    ToolNeeds("extract_http", (module("scapy"),)),
    ToolNeeds("pcap_summary", (module("scapy"),)),
]
CAPABILITIES = manifest("network", TOOL_NEEDS)


def _text_error(code: str, message: str, tool: str) -> str:
    """The structured error, as the text the three text-answering tools return."""
    return json.dumps(tool_error(code, message, tool=tool))


def _staging_base() -> Path:
    """The delivery directory a capture may have been staged into.

    The same ``MALJAN_STAGING_DIR`` the analysis sidecar writes uploads to: on
    a host where both sidecars run, a capture delivered there is a capture
    this server may read. Nothing here writes to it.
    """
    configured = os.environ.get("MALJAN_STAGING_DIR", "").strip()
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "maljan-analysis-mcp"


def _within(packet_limit: Any) -> int:
    """One tool's packet budget, held to what this server will read.

    A limit the caller did not give, gave as nothing, or gave as more than the
    ceiling is the ceiling: every read here is into memory, and a capture is
    as large as the detonation made it.
    """
    try:
        wanted = int(packet_limit)
    except (TypeError, ValueError):
        return DEFAULT_PACKET_LIMIT
    return max(1, min(wanted, DEFAULT_PACKET_LIMIT))


def _capture(pcap_path: str) -> Path:
    """One ``pcap_path`` argument, resolved inside the directories this server may read.

    A capture is named by the model, and a model that has read a sample has
    read whatever its author wrote there. Raises ``PathOutsideRoots`` for
    anything that resolves elsewhere; see ``maljan.tools.roots``.
    """
    return resolve_under_roots(pcap_path, extra_roots=(_staging_base(),))


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, its optional dependency, and whether it is available.
    """
    # Deep, so "computed once when the server started" also means a
    # caller cannot reach in and change what it says.
    return copy.deepcopy(CAPABILITIES)


@mcp.tool()
def read_pcap_summary(pcap_path: str, packet_limit: int = 100) -> str:
    """Read a summary of packets from a PCAP file."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "read_pcap_summary")
    try:
        capture = _capture(pcap_path)
    except PathOutsideRoots as refusal:
        return _text_error(PATH_OUTSIDE_ROOTS, str(refusal), "read_pcap_summary")
    if not capture.exists():
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "read_pcap_summary")
    try:
        packets = rdpcap(str(capture), count=_within(packet_limit))
        output = []
        for i, pkt in enumerate(packets):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "Unknown"
                if TCP in pkt:
                    proto = f"TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
                elif UDP in pkt:
                    proto = f"UDP {pkt[UDP].sport}->{pkt[UDP].dport}"
                output.append(f"Packet {i}: {src} -> {dst} ({proto})")
        return "\n".join(output) if output else "No IP packets found."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "read_pcap_summary")


@mcp.tool()
def extract_dns(pcap_path: str, packet_limit: int = DEFAULT_PACKET_LIMIT) -> str:
    """Extract all DNS queries from the first ``packet_limit`` packets of a PCAP file."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "extract_dns")
    try:
        capture = _capture(pcap_path)
    except PathOutsideRoots as refusal:
        return _text_error(PATH_OUTSIDE_ROOTS, str(refusal), "extract_dns")
    if not capture.exists():
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "extract_dns")
    try:
        # A bounded read, filtered for DNS
        packets = rdpcap(str(capture), count=_within(packet_limit))
        queries = set()
        for pkt in packets:
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                queries.add(qname)
        return "\n".join(queries) if queries else "No DNS queries found."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_dns")


@mcp.tool()
def extract_http(pcap_path: str, packet_limit: int = DEFAULT_PACKET_LIMIT) -> str:
    """Extract raw HTTP request headers from the first ``packet_limit`` packets."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "extract_http")
    try:
        capture = _capture(pcap_path)
    except PathOutsideRoots as refusal:
        return _text_error(PATH_OUTSIDE_ROOTS, str(refusal), "extract_http")
    if not capture.exists():
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "extract_http")
    try:
        packets = rdpcap(str(capture), count=_within(packet_limit))
        requests = []
        for pkt in packets:
            if TCP in pkt and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload).decode("utf-8", errors="ignore")
                if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    # Get just the first line (the request line) and Host header if present
                    lines = payload.split("\r\n")
                    req_line = lines[0]
                    host = ""
                    for line in lines[1:]:
                        if line.lower().startswith("host: "):
                            host = line
                            break
                    requests.append(f"{req_line} | {host}")
        return "\n".join(requests) if requests else "No HTTP requests found."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_http")


@mcp.tool()
def pcap_summary(pcap_path: str, packet_limit: int = DEFAULT_PACKET_LIMIT) -> dict[str, Any]:
    """Summarise a capture: conversations, TLS SNI destinations and beaconing.

    The whole-capture view, next to the three packet-level tools above. An
    agent that reads this first knows which conversation to go and read
    individual packets from, instead of walking the capture to find out.
    """
    from maljan.tools.pcap import pcap_summary as summarize

    try:
        capture = _capture(pcap_path)
    except PathOutsideRoots as refusal:
        return tool_error(PATH_OUTSIDE_ROOTS, str(refusal), tool="pcap_summary")
    try:
        return dict(
            normalise_error(dict(summarize(str(capture), packet_limit=_within(packet_limit))))
        )
    except Exception as exc:  # noqa: BLE001 - a tool server answers, it does not raise
        return tool_error(
            code_for_exception(exc), f"{type(exc).__name__}: {exc}", tool="pcap_summary"
        )


if __name__ == "__main__":
    mcp.run(transport="stdio")
