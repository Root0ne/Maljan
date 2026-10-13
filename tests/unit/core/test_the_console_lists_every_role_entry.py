"""The console's list of roles with a model entry only is the backend's.

``apps/web/src/app/(app)/settings/configuration/roleEntries.ts`` restates
``config.ROLE_ENTRY_KEYS`` so the Agents page can offer each role's model
fields and refuse an agent named after one. A key added on one side and not
the other would leave a role the console cannot configure, and an agent name
the console lets through that the settings model then renames on read.
"""

from __future__ import annotations

import re
from pathlib import Path

from maljan.core.config import ROLE_ENTRY_KEYS

ROLE_ENTRIES_TS = (
    Path(__file__).resolve().parents[3]
    / "apps"
    / "web"
    / "src"
    / "app"
    / "(app)"
    / "settings"
    / "configuration"
    / "roleEntries.ts"
)


def _console_keys() -> list[str]:
    text = ROLE_ENTRIES_TS.read_text(encoding="utf-8")
    listed = text[text.index("export const ROLE_ENTRIES") :]
    listed = listed[: listed.index("];")]
    return re.findall(r'^\s*key:\s*"([^"]+)"', listed, flags=re.MULTILINE)


def test_the_console_lists_the_backends_role_keys_in_its_order() -> None:
    assert _console_keys() == list(ROLE_ENTRY_KEYS)
