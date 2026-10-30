"""A stored change naming no kind of its own rides along an edit of the other tools.

The console's tool declarations box keeps such a change as it is while the
operator edits the other tools of the box (``readToolFacts``'s ``held``), and
sends it back unchanged: the save keeps it as stored, and checks the tools
the edit adds or changes in full.
"""

from __future__ import annotations

import pytest

from app.services.server_map import ServerMapError, validate_server_map
from maljan.core.config import Settings
from maljan.core.tool_declarations import with_mark

RANKED = {"reputation": {"rank": 30}}


def _block() -> dict:
    entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
    entry.pop("auth_token", None)
    return entry


def test_an_edit_of_another_tool_keeps_the_stored_change() -> None:
    stored = {"virustotal": {**_block(), "tool_facts": with_mark({"get_file_report": RANKED})}}
    facts = with_mark({"get_file_report": RANKED, "added_tool": {"kind": "strings"}})
    saved = validate_server_map({"virustotal": {**_block(), "tool_facts": facts}}, stored=stored)
    held = saved["virustotal"]["tool_facts"]
    assert held["get_file_report"] == RANKED
    assert held["added_tool"]["kind"] == "strings"


def test_an_edit_of_the_stored_change_itself_is_checked_in_full() -> None:
    stored = {"virustotal": {**_block(), "tool_facts": with_mark({"get_file_report": RANKED})}}
    facts = with_mark({"get_file_report": {"reputation": {"rank": 31}}})
    with pytest.raises(ServerMapError) as refused:
        validate_server_map({"virustotal": {**_block(), "tool_facts": facts}}, stored=stored)
    assert any(key.startswith("virustotal.tool_facts") for key in refused.value.errors)
