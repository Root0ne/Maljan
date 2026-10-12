"""The console's copy of the mark a map of tool-declaration changes carries is the API's.

The console keeps the mark on what it stages and never reads it as a tool
(``toolFactsChanges.ts``); a drift between its copy and
``tool_declarations.CHANGES_MARK`` / ``CHANGES_FORM`` would make every staged
map read whole.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from maljan.core.tool_declarations import CHANGES_FORM, CHANGES_MARK

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "apps/web/src/app/(app)/settings/configuration/toolFactsChanges.ts"
)


def _constant(name: str) -> str:
    found = re.search(rf'^export const {name} = ("[^"\n]*");$', SOURCE.read_text(), re.M)
    assert found, name
    value: str = json.loads(found.group(1))
    return value


def test_the_typescript_mark_is_the_python_mark() -> None:
    assert _constant("CHANGES_MARK") == CHANGES_MARK
    assert _constant("CHANGES_FORM") == CHANGES_FORM
