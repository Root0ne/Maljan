from typing import Any

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.registry import register_parser
from maljan.schemas.sandbox_document import dns_row_name, place


@register_parser("dynamic")
class DynamicParser(BaseParser):
    """The neutral sandbox report's document, refined to its behaviour summary."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through the report's parts (``schemas.sandbox_document``) for threat indicators."""
        if not isinstance(raw_data, dict):
            return "Invalid sandbox data format."

        generic_events = place(raw_data, "generic_events", [])
        apistats = place(raw_data, "apistats", {})

        # A sandbox that reported success and traced nothing has said
        # something, and the table of zero rows does not say it. The parser
        # states the fact; what it means — evasion, a platform mismatch, an
        # empty file — is the analyst's reading, and naming a technique here
        # would be this formatter deciding it.
        _network_root = raw_data.get("network", {}) or {}
        _net_total = sum(
            len(_network_root.get(k, []) or [])
            for k in ("dns", "http", "tcp", "hosts", "domains", "udp")
        )
        _signatures = place(raw_data, "signatures") or []
        if not generic_events and not apistats and not _signatures and _net_total == 0:
            return (
                "### Sandbox Behavioral Summary\n\n"
                "**SANDBOX COMPLETED WITH ZERO OBSERVED EVENTS.**\n\n"
                "The sandbox report parsed successfully and every section "
                "(behavior.generic, behavior.apistats, network.*, signatures) "
                "is empty. That is an observation about the detonation, not "
                "missing input: the run completed and traced nothing.\n"
            )

        # 1. Behavioral Signatures (Injection, Persistence, Evasion, etc.)
        threat_rows: list[list[str]] = []
        for event in generic_events:
            category = event.get("category", "N/A")
            desc = event.get("description", "N/A")
            threat_rows.append([category, desc])

        threat_table = self._format_as_table(headers=["Category", "Observation"], rows=threat_rows)

        # 2. Key API Statistics (Aggregation)
        api_rows: list[list[str]] = []
        for pid, stats in apistats.items():
            for api, count in stats.items():
                if self._is_notable_api(api):
                    api_rows.append([str(pid), api, str(count)])

        api_table = self._format_as_table(
            headers=["PID", "Sensitive API", "Call Count"], rows=api_rows
        )

        # 3. Network Indicators (C2 / Exfiltration)
        net_rows: list[list[str]] = []
        # Every row: the analyst reads the whole observed network, not its
        # first ten of each kind.
        for dns in place(raw_data, "network.dns", []):
            req = dns_row_name(dns) or "N/A"
            net_rows.append(["DNS", str(req), "—"])
        for http in place(raw_data, "network.http", []):
            host = http.get("host", "N/A")
            uri = http.get("uri", "/")
            net_rows.append(["HTTP", f"{host}{uri}", str(http.get("status", "?"))])
        for tcp in place(raw_data, "network.tcp", []):
            dst = tcp.get("dst", "N/A")
            dport = tcp.get("dport", "?")
            net_rows.append(["TCP", f"{dst}:{dport}", "—"])
        for host in place(raw_data, "network.hosts", []):
            net_rows.append(["HOST", str(host), "—"])
        for domain in place(raw_data, "network.domains", []):
            net_rows.append(["DOMAIN", str(domain), "—"])

        net_table = self._format_as_table(headers=["Type", "Indicator", "Status"], rows=net_rows)

        return (
            "### Sandbox Behavioral Summary\n\n"
            "#### Detected High-Value Behaviors:\n"
            f"{threat_table}\n\n"
            "#### Re-grouped API Metrics (Noise Filtered):\n"
            f"{api_table}\n\n"
            "#### Network Indicators (C2 / Exfiltration):\n"
            f"{net_table}"
        )

    def _is_notable_api(self, api_name: str) -> bool:
        """Filters out noise and keeps sensitive WinAPI calls."""
        sensitive_keywords = [
            "RegSetValue",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "HttpSendRequest",
            "CryptAcquire",
            "CreateProcess",
            "ShellExecute",
        ]
        return any(kw in api_name for kw in sensitive_keywords)
