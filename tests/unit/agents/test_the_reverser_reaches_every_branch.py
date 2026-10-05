"""The reverser is told to reach every branch of a dispatcher it finds.

A reverser decompiled the dispatcher, named every command id's handler, and
decompiled four of them no further, so what those commands do stayed a call to
an unread function. Its prompt now asks, of a switch or a table over command or
message ids, for each branch's handler to be decompiled or listed as not
reached with the reason, one line per id with the handler's address. The
example team document seeds the same text (``test_the_all_tools_team_document``
holds the two equal), and the leak test reads both.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.agents.prompts import REVERSER_PROMPT

TEAM = Path(__file__).resolve().parents[3] / "docs" / "examples" / "profiles" / "all-tools.json"


def test_the_prompt_asks_for_every_branch_or_the_reason_it_was_not_reached() -> None:
    text = " ".join(REVERSER_PROMPT.split())
    assert "a switch or a table over command or message ids" in text
    assert "decompile each branch's handler, or list the branch as not reached and say why" in text
    assert "one line per id with the handler's address" in text


def test_the_team_document_s_reverser_carries_it() -> None:
    definitions = json.loads(TEAM.read_text(encoding="utf-8"))["values"]["core.agents.definitions"]
    assert definitions["all_tools_reverser_ghidra"]["prompt"] == REVERSER_PROMPT
