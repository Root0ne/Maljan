import re
from abc import ABC, abstractmethod
from typing import Any

from maljan.utils.written_forms import sample_written_out

_BACKSLASHES_BEFORE_A_PIPE = re.compile(r"\\++(?=\|)")


def table_cell(value: Any) -> str:
    """One table cell's text, written so it cannot break the table it stands in.

    A cell holds what a sandbox recorded, which the sample controls: its
    control characters (a newline that would end the row, or the table, and
    let the value write a heading of its own), its ledger-id shapes and
    run-state markers are written out as a line holds a sample's text
    (``sample_written_out``), and a pipe, which would add a column, is
    escaped. A backslash right before a pipe is escaped first, so the value's
    own ``\\|`` cannot read as an escaped pipe followed by a bare one; every
    other backslash, a Windows path's, stays as written. Linear in the value.
    """
    return _BACKSLASHES_BEFORE_A_PIPE.sub(
        lambda m: m.group() * 2, sample_written_out(str(value))
    ).replace("|", "\\|")


class BaseParser(ABC):
    """Abstract base for data pre-processing and noise reduction."""

    @abstractmethod
    def parse(self, raw_data: Any) -> str:
        """Transforms raw tool output into a refined Markdown summary."""
        pass

    def _format_as_table(self, headers: list[str], rows: list[list[Any]]) -> str:
        """Helper to create a Markdown table from a list of rows, each cell written out."""
        if not rows:
            return "No significant events detected."

        header_str = " | ".join(table_cell(h) for h in headers)
        separator_str = " | ".join(["---"] * len(headers))
        body_str = "\n".join([" | ".join(table_cell(c) for c in row) for row in rows])

        return f"| {header_str} |\n| {separator_str} |\n| {body_str} |"
