"""Fixtures of the API tests."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

TABLE = Path(__file__).resolve().parents[2] / "fixtures" / "a_shipped_server_tool_table.json"


@pytest.fixture
def a_built_in_server_ships_a_tool_table() -> Iterator[None]:
    """The built-in ``virustotal`` block ships a table of its tools, as a release once did.

    No built-in server block ships a tool table now (the platform's own
    sidecars declare theirs, and a reputation service's tools are read from
    its listing), but a stored map of changes over one, and the migration that
    wrote such maps, still read against what a block ships. The tests of that
    mechanism give one block the table it shipped before
    (``tests/fixtures/a_shipped_server_tool_table.json``).
    """
    from maljan.core import builtin_declarations, declared_reading
    from maljan.core import settings_overrides as so
    from maljan.core.tool_declarations import bump_declaration_version

    def _clear() -> None:
        so._shipped_dump.cache_clear()
        declared_reading._shipped_tools_by_source.cache_clear()
        bump_declaration_version()

    blocks = builtin_declarations._SERVER_BLOCKS
    held = blocks.get("virustotal")
    blocks["virustotal"] = {"tool_facts": json.loads(TABLE.read_text("utf-8"))}
    _clear()
    yield
    if held is None:
        blocks.pop("virustotal", None)
    else:
        blocks["virustotal"] = held
    _clear()
