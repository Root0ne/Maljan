from typing import Any

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.registry import register_parser


@register_parser("network")
class NetworkParser(BaseParser):
    """Zeek (Bro) & C2 Network Log Refinement Engine."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through network JSON logs for C2 and exfiltration indicators.

        Supports two shapes:
          * dict — CAPEv2 ``network`` block (dns/http/tcp/hosts/domains keys)
          * list — Zeek (Bro) connection log
        """
        if isinstance(raw_data, dict):
            return self._parse_sandbox_network(raw_data)
        if isinstance(raw_data, list):
            return self._parse_zeek_network(raw_data)
        return "Invalid network log format."

    def _parse_sandbox_network(self, raw_data: dict[str, Any]) -> str:
        """Parse a sandbox ``network`` dict (CAPEv2 shape)."""
        dns_rows: list[list[str]] = []
        http_rows: list[list[str]] = []
        tcp_rows: list[list[str]] = []
        host_rows: list[list[str]] = []

        # DNS
        for entry in raw_data.get("dns", []):
            query = entry.get("request", entry.get("query", "N/A"))
            ip = entry.get("answers", ["N/A"])[0] if entry.get("answers") else "N/A"
            is_dga = self._is_suspicious_dns(str(query))
            dns_rows.append([str(query), str(ip), "[Suspicious]" if is_dga else "Normal"])

        # HTTP
        for entry in raw_data.get("http", []):
            host = entry.get("host", "N/A")
            uri = entry.get("uri", entry.get("path", "/"))
            method = entry.get("method", "GET")
            http_rows.append([str(host), f"{method} {uri}", str(entry.get("status", "?"))])

        # TCP
        for entry in raw_data.get("tcp", []):
            dst = entry.get("dst", entry.get("dport", "N/A"))
            dport = entry.get("dport", "?")
            tcp_rows.append([str(dst), str(dport), str(entry.get("src", "?"))])

        # Hosts
        for host in raw_data.get("hosts", []):
            host_rows.append([str(host), "observed", "—"])

        # Domains
        for domain in raw_data.get("domains", []):
            is_dga = self._is_suspicious_dns(str(domain))
            host_rows.append([str(domain), "domain", "[Suspicious]" if is_dga else "Normal"])

        dns_table = self._format_as_table(
            headers=["Target Domain", "IP Address", "Evaluation"], rows=dns_rows
        )
        http_table = self._format_as_table(headers=["Host", "Request", "Status"], rows=http_rows)
        tcp_table = self._format_as_table(headers=["Destination", "Port", "Source"], rows=tcp_rows)
        host_table = self._format_as_table(
            headers=["Host/Domain", "Type", "Evaluation"], rows=host_rows
        )

        return (
            "### Network Traffic Intelligence (Sandbox)\n\n"
            "#### DNS Exfiltration & DGA Analysis:\n"
            f"{dns_table}\n\n"
            "#### HTTP Requests:\n"
            f"{http_table}\n\n"
            "#### TCP Connections:\n"
            f"{tcp_table}\n\n"
            "#### Observed Hosts & Domains:\n"
            f"{host_table}"
        )

    def _parse_zeek_network(self, raw_data: list[Any]) -> str:
        """Parse Zeek (Bro) network log format."""
        dns_rows: list[list[str]] = []
        conn_rows: list[list[str]] = []

        for entry in raw_data:
            service = entry.get("service", "N/A")
            ip = entry.get("id.resp_h", "N/A")
            port = entry.get("id.resp_p", "N/A")

            if service == "dns":
                query = entry.get("query", "N/A")
                is_dga = self._is_suspicious_dns(query)
                dns_rows.append([query, ip, "[Suspicious]" if is_dga else "Normal"])

            elif service in ["ssl", "http"]:
                conn_rows.append([f"{ip}:{port}", service, str(entry.get("resp_bytes", 0))])

        dns_table = self._format_as_table(
            headers=["Target Domain", "IP Address", "Evaluation"], rows=dns_rows
        )
        conn_table = self._format_as_table(
            headers=["Endpoint", "Protocol", "Bytes Recv"], rows=conn_rows
        )

        return (
            "### Network Traffic Intelligence (Zeek Summarized)\n\n"
            "#### DNS Exfiltration & DGA Analysis:\n"
            f"{dns_table}\n\n"
            "#### C2 Connectivity Beaconing:\n"
            f"{conn_table}"
        )

    def _is_suspicious_dns(self, query: str) -> bool:
        """Flag suspicious domains (DGA / homograph / C2-infra tokens).

        Delegates to the canonical scorer in ``network_extractor`` so the
        ``[Suspicious]`` markers in this LLM-facing text summary agree with the
        structured ``MalwareReport.network`` verdicts (single source of truth),
        instead of the old ``len > 25`` proof-of-concept heuristic.
        """
        from maljan.extractors.network_extractor import _assess_domain

        return _assess_domain(query).suspicious
