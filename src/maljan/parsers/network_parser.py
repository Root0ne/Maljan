from typing import Any

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.registry import register_parser


@register_parser("network")
class NetworkParser(BaseParser):
    """Zeek (Bro) & C2 Network Log Refinement Engine."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through network JSON logs for C2 and exfiltration indicators."""
        if not isinstance(raw_data, list):
            return "Invalid network log format."

        # 1. DNS/DGA Detection & SSL Anomalies
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
                # Connectivity Beacon Check
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
        """Heuristic check for long, random-looking domains (DGA)."""
        # Simplistic heuristic for PoC
        if len(query) > 25:
            return True
        if ".example" in query:  # Demo purposes
            return True
        return False
