from typing import Any

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.registry import register_parser


@register_parser("dynamic")
class DynamicParser(BaseParser):
    """Sandbox (CAPEv2/Cuckoo) JSON Refinement Engine."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through behavioral JSON for high-severity threat indicators."""
        if not isinstance(raw_data, dict):
            return "Invalid sandbox data format."

        behavior = raw_data.get("behavior", {})
        generic_events = behavior.get("generic", [])
        apistats = behavior.get("apistats", {})

        # DYN-SAND-01 (2026-05-19 audit): when the sandbox reports completion
        # but produced zero behavioral events AND zero network indicators,
        # this is itself a strong signal — likely T1497 anti-sandbox evasion,
        # a platform mismatch (an ELF in a Windows VM), or a zero-byte sample. The
        # analyst LLM previously saw an empty-rows table and emitted a
        # meta-claim ("no dynamic data available") which the judge then
        # treated as a 1.0-confidence claim. Surfacing this structured hint
        # lets the analyst emit a concrete T1497 claim instead.
        _network_root = raw_data.get("network", {}) or {}
        _net_total = sum(
            len(_network_root.get(k, []) or [])
            for k in ("dns", "http", "tcp", "hosts", "domains", "udp")
        )
        _signatures = raw_data.get("signatures") or []
        if not generic_events and not apistats and not _signatures and _net_total == 0:
            return (
                "### Sandbox Behavioral Summary\n\n"
                "**SANDBOX COMPLETED WITH ZERO OBSERVED EVENTS.**\n\n"
                "The sandbox report parsed successfully, but every section "
                "(behavior.generic, behavior.apistats, network.*, signatures) "
                "is empty. This is itself a behavioural observation — the "
                "absence of any activity in a sandbox that reported "
                "successful completion strongly suggests one of:\n\n"
                "- **T1497 Virtualization/Sandbox Evasion** — the sample "
                "detected the sandbox and aborted.\n"
                "- **Platform mismatch** — e.g. a Linux ELF submitted to a "
                "Windows VM (or vice versa) that cannot execute it.\n"
                "- **Zero-byte / corrupted sample** — nothing to run.\n\n"
                "You SHOULD emit at least one structured claim covering "
                "this observation (typical confidence 0.30-0.50) rather "
                "than treating it as missing data. Do NOT report 'no "
                "behaviour available' — the absence IS the evidence.\n"
            )

        # 1. Behavioral Signatures (Injection, Persistence, Evasion, etc.)
        threat_rows: list[list[str]] = []
        for event in generic_events:
            category = event.get("category", "N/A")
            desc = event.get("description", "N/A")
            severity = self._calculate_severity(category, desc)
            threat_rows.append([category, desc, severity])

        threat_table = self._format_as_table(
            headers=["Category", "Observation", "Severity"], rows=threat_rows
        )

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
        network = raw_data.get("network", {})
        net_rows: list[list[str]] = []
        for dns in network.get("dns", [])[:10]:
            req = dns.get("request", dns.get("query", "N/A"))
            net_rows.append(["DNS", str(req), "—"])
        for http in network.get("http", [])[:10]:
            host = http.get("host", "N/A")
            uri = http.get("uri", "/")
            net_rows.append(["HTTP", f"{host}{uri}", str(http.get("status", "?"))])
        for tcp in network.get("tcp", [])[:10]:
            dst = tcp.get("dst", "N/A")
            dport = tcp.get("dport", "?")
            net_rows.append(["TCP", f"{dst}:{dport}", "—"])
        for host in network.get("hosts", [])[:10]:
            net_rows.append(["HOST", str(host), "—"])
        for domain in network.get("domains", [])[:10]:
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

    def _calculate_severity(self, category: str, description: str) -> str:
        """Determines event severity based on keywords."""
        high_threats = ["persistence", "evasion", "injection", "crypto"]
        if any(
            threat in category.lower() or threat in description.lower() for threat in high_threats
        ):
            return "[HIGH]"
        return "[MEDIUM]"

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
