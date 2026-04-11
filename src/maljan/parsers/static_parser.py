from typing import Any

from maljan.parsers.base_parser import BaseParser


class StaticParser(BaseParser):
    """Static Code & PE Header Refinement Engine."""

    def parse(self, raw_data: Any) -> str:
        """Sifts through static analysis JSON for persistent and code-based indicators."""
        if not isinstance(raw_data, list) or not raw_data:
            return "Invalid static data format."

        # Ghidra and string analytics
        entry = raw_data[0]
        summary = entry.get("decompiled_summary", "N/A")

        # 1. PE Section Overview
        pe_header = entry.get("pe_header", {})
        sections = pe_header.get("sections", [])

        section_table = self._format_as_table(
            headers=["Field", "Value"],
            rows=[
                ["Entry Point", pe_header.get("entry_point", "N/A")],
                ["Sections", ", ".join(sections)],
            ],
        )

        # 2. Suspicious Strings (IOCs)
        ioc_rows: list[list[str]] = []
        for string in entry.get("strings", []):
            ioc_rows.append([string, "🚩 IOC/Hardcoded"])

        ioc_table = self._format_as_table(
            headers=["String Value", "Potential Impact"], rows=ioc_rows
        )

        return (
            f"### 🔍 Static Analysis Summary for {entry.get('file', 'Unknown')}\n\n"
            f"**Code Overview:** {summary}\n\n"
            "#### PE Structure:\n"
            f"{section_table}\n\n"
            "#### Detected Suspicious Strings:\n"
            f"{ioc_table}"
        )
