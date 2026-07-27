import os

from mcp.server.fastmcp import FastMCP
from scapy.all import (  # type: ignore[attr-defined]
    DNSQR,
    IP,
    TCP,
    UDP,
    rdpcap,
)

mcp = FastMCP("NetworkMCP")


@mcp.tool()
def read_pcap_summary(pcap_path: str, packet_limit: int = 100) -> str:
    """Read a summary of packets from a PCAP file."""
    if not os.path.exists(pcap_path):
        return f"Error: File {pcap_path} not found."
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
    except Exception as e:
        return f"Error reading PCAP: {str(e)}"


@mcp.tool()
def extract_dns(pcap_path: str) -> str:
    """Extract all DNS queries from a PCAP file."""
    if not os.path.exists(pcap_path):
        return f"Error: File {pcap_path} not found."
    try:
        # Load all packets, filter for DNS
        packets = rdpcap(pcap_path)
        queries = set()
        for pkt in packets:
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                queries.add(qname)
        return "\n".join(queries) if queries else "No DNS queries found."
    except Exception as e:
        return f"Error extracting DNS: {str(e)}"


@mcp.tool()
def extract_http(pcap_path: str) -> str:
    """Extract raw HTTP request headers from a PCAP file (basic extraction)."""
    if not os.path.exists(pcap_path):
        return f"Error: File {pcap_path} not found."
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
    except Exception as e:
        return f"Error extracting HTTP: {str(e)}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
