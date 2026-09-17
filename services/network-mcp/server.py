import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, manifest, module
from maljan.tools.errors import (
    MISSING_DEPENDENCY,
    NO_SUCH_FILE,
    code_for_exception,
    normalise_error,
    tool_error,
)

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
except ImportError as exc:  # pragma: no cover - depends on the host
    DNSQR = IP = TCP = UDP = rdpcap = None  # type: ignore[assignment]
    _SCAPY_MISSING = f"scapy is not installed ({exc})"

mcp = FastMCP("NetworkMCP")

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


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, its optional dependency, and whether it is available.
    """
    return dict(CAPABILITIES)


@mcp.tool()
def read_pcap_summary(pcap_path: str, packet_limit: int = 100) -> str:
    """Read a summary of packets from a PCAP file."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "read_pcap_summary")
    if not os.path.exists(pcap_path):
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "read_pcap_summary")
    try:
        packets = rdpcap(pcap_path, count=packet_limit)
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
def extract_dns(pcap_path: str) -> str:
    """Extract all DNS queries from a PCAP file."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "extract_dns")
    if not os.path.exists(pcap_path):
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "extract_dns")
    try:
        # Load all packets, filter for DNS
        packets = rdpcap(pcap_path)
        queries = set()
        for pkt in packets:
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                queries.add(qname)
        return "\n".join(queries) if queries else "No DNS queries found."
    except Exception as e:  # noqa: BLE001 - a tool server answers, it does not raise
        return _text_error(code_for_exception(e), f"{type(e).__name__}: {e}", "extract_dns")


@mcp.tool()
def extract_http(pcap_path: str) -> str:
    """Extract raw HTTP request headers from a PCAP file (basic extraction)."""
    if _SCAPY_MISSING:
        return _text_error(MISSING_DEPENDENCY, _SCAPY_MISSING, "extract_http")
    if not os.path.exists(pcap_path):
        return _text_error(NO_SUCH_FILE, f"no such file: {pcap_path}", "extract_http")
    try:
        packets = rdpcap(pcap_path)
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
def pcap_summary(pcap_path: str, packet_limit: int = 5000) -> dict[str, Any]:
    """Summarise a capture: conversations, TLS SNI destinations and beaconing.

    The whole-capture view, next to the three packet-level tools above. An
    agent that reads this first knows which conversation to go and read
    individual packets from, instead of walking the capture to find out.
    """
    from maljan.tools.pcap import pcap_summary as summarize

    try:
        return dict(normalise_error(dict(summarize(pcap_path, packet_limit=packet_limit))))
    except Exception as exc:  # noqa: BLE001 - a tool server answers, it does not raise
        return tool_error(
            code_for_exception(exc), f"{type(exc).__name__}: {exc}", tool="pcap_summary"
        )


if __name__ == "__main__":
    mcp.run(transport="stdio")
