from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract base for data pre-processing and noise reduction."""

    @abstractmethod
    def parse(self, raw_data: Any) -> str:
        """Transforms raw tool output into a refined Markdown summary."""
        pass

    def _format_as_table(self, headers: list[str], rows: list[list[Any]]) -> str:
        """Helper to create a Markdown table from a list of rows."""
        if not rows:
            return "No significant events detected."

        header_str = " | ".join(headers)
        separator_str = " | ".join(["---"] * len(headers))
        body_str = "\n".join([" | ".join(map(str, row)) for row in rows])

        return f"| {header_str} |\n| {separator_str} |\n| {body_str} |"
