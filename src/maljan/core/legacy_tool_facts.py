"""LEGACY READING: the facts a stored entry with no source and no facts is read by, frozen.

An entry written before entries recorded the source their tool is declared
under (``LedgerEntry.source``) and the facts it declared (``LedgerEntry.facts``)
is read by its bare tool name. That reading once looked the name up in the
declarations the platform ships (``declared_reading.shipped_by_name``) and in
the consumers' ``legacy_names`` (``builtin_declarations.CONSUMER_KINDS``), so
any change to a shipped declaration changed how every stored run read.

What those tables gave is frozen here instead, in one versioned data file
(:data:`SNAPSHOT_PATH`): each shipped tool's facts as the tables declared them
(every field the declaration set) and each consumer's legacy names. The file
is pinned by its digest (:data:`SNAPSHOT_SHA256`): a file that changed is
refused, never read. Nothing new is added to it: a new reading is a
declaration, recorded on the entry when it is written.

Only ``core.declared_reading`` imports this module (a guard holds every other
reader to that gateway). ``tests/unit/core/
test_a_stored_entry_is_read_from_the_frozen_snapshot.py`` held the snapshot
equal to the shipped tables, tool by tool and field by field, when it was cut.

The snapshot is never regenerated. Once a later change makes a shipped table
diverge from it, the tests that hold the two equal are deleted, never updated:
the snapshot stays as it was cut, and so does every stored run's reading.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from functools import cache
from typing import Any

from maljan.core.tool_declarations import STRICT_DECLARATIONS, ToolFacts

SNAPSHOT_PATH = "data/legacy_tool_facts_v1.json"
SNAPSHOT_SCHEMA = "maljan-legacy-tool-facts/v1"
# The sha256 of the snapshot's UTF-8 text, as it was cut (the file's bytes:
# the file is UTF-8 with LF line ends).
SNAPSHOT_SHA256 = "3cf4058ce94d31eb67c1cc877a609df2596129994bb8cf2e39e4fdd172c4b221"


@cache
def _document() -> Mapping[str, Any]:
    """The snapshot, read once; a file whose digest or schema is not the pinned one is refused.

    The file is read as text, as every data table is, and the digest taken
    over that text encoded as UTF-8; for the file as cut that is its bytes.
    """
    from maljan.core.paths import resolve_data

    text = resolve_data(SNAPSHOT_PATH).read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != SNAPSHOT_SHA256:
        raise ValueError(
            f"{SNAPSHOT_PATH} is not the frozen snapshot (sha256 {digest}, "
            f"pinned {SNAPSHOT_SHA256}); a stored run would read differently."
        )
    document = json.loads(text)
    if document.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError(f"{SNAPSHOT_PATH} is not of the schema {SNAPSHOT_SCHEMA}.")
    return document  # type: ignore[no-any-return]


@cache
def facts_by_name() -> Mapping[str, ToolFacts]:
    """Each bare tool name's frozen facts, in the order the shipped tables gave them.

    Read as a declaration already accepted is read (leniently), so a field
    this version would refuse in an operator's edit never costs a stored run
    its reading.
    """
    token = STRICT_DECLARATIONS.set(False)
    try:
        return {
            str(name): ToolFacts.model_validate(record)
            for name, record in (_document().get("tools") or {}).items()
        }
    finally:
        STRICT_DECLARATIONS.reset(token)


@cache
def legacy_names(consumer: str) -> frozenset[str]:
    """The names a consumer's table held that no built-in tool has, frozen; empty for none.

    A consumer the platform does not name (``builtin_declarations.
    CONSUMER_KINDS``) is refused, as it always was.
    """
    from maljan.core.builtin_declarations import CONSUMER_KINDS

    if consumer not in CONSUMER_KINDS:
        raise KeyError(consumer)
    held = (_document().get("legacy_names") or {}).get(consumer) or ()
    return frozenset(str(name) for name in held)
