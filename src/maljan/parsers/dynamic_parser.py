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

        return (
            "### Sandbox Behavioral Summary\n\n"
            "#### Detected High-Value Behaviors:\n"
            f"{threat_table}\n\n"
            "#### Re-grouped API Metrics (Noise Filtered):\n"
            f"{api_table}"
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
