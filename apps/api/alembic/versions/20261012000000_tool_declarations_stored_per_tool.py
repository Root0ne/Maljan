"""Store each built-in block's tool declarations as its changes over what it ships, per tool.

A save used to store a built-in block's tool declarations (``tool_facts``)
whole: the server's entry in ``core.mcp.servers``, or a provider block's
``core.<block>.tool_facts`` leaf. From then on no correction a later release
shipped for any tool of that block reached a run. They are now stored one tool
at a time, as what the operator changed: only the fields that differ from the
shipped declaration of that tool, ``null`` for a shipped tool the operator
removed, the whole declaration of a tool the block does not ship. This revision
rewrites each map stored whole into that form, once.

Each map is read against the declarations of the release that wrote it. That
release is not recorded, so it is inferred from the frozen record of what
every release since tool declarations existed shipped
(``20261012000000_shipped_tool_declarations.json``, beside this file): the
release under which the stored map says least of its own (fewest tools changed
plus shipped tools missing) wrote it. Against that release a tool stored as it
shipped is not the operator's and is dropped, so it follows the shipped
declaration from now on; a tool stored otherwise keeps exactly the fields the
operator changed; a shipped tool the map lacks stays removed. When releases tie
and would give different answers, the release is not known, and the stored map
is kept whole as the operator's: every tool it holds is kept as stored, and
every tool any release shipped that it lacks stays removed. Either way every
map reads today as it read before this revision, except that a tool the
operator never changed takes the declaration shipped now.

A block nothing ever shipped tool declarations for (a server an operator
added) keeps its map as it is: its whole map is its changes over nothing. A
secret row is left alone. One line is logged when anything was rewritten.

Downgrade writes each block's map whole again, with the declarations the
release before this revision shipped (the last state in the record) under the
changes.

Revision ID: 20261012000000
Revises: 20261011000000
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261012000000"
down_revision = "20261011000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

SERVER_MAP_KEY = "core.mcp.servers"
CORE_PREFIX = "core."
TOOL_FACTS_SUFFIX = ".tool_facts"
SERVER_BLOCK_PREFIX = "mcp.servers."
RECORD = Path(__file__).with_name("20261012000000_shipped_tool_declarations.json")
REWRITTEN = (
    "runtime_settings: stored tool declarations of the built-in blocks were rewritten "
    "as per-tool changes over the shipped declarations"
)

_UPDATE_PG = sa.text("UPDATE runtime_settings SET value = CAST(:v AS JSONB) WHERE key = :k")
_UPDATE_OTHER = sa.text("UPDATE runtime_settings SET value = :v WHERE key = :k")


def _record() -> dict[str, Any]:
    record: dict[str, Any] = json.loads(RECORD.read_text(encoding="utf-8"))
    return record


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _normal(entry: Any, defaults: dict[str, Any]) -> Any:
    """A declaration with every field at its default left out, as the record holds them."""
    if not isinstance(entry, dict):
        return entry
    return {
        key: value
        for key, value in entry.items()
        if key not in defaults or _canon(value) != _canon(defaults[key])
    }


def _states(block: dict[str, Any]) -> list[dict[str, dict[str, Any]]]:
    """Each distinct shipped state of one block, in release order: tool -> declaration."""
    versions = block["versions"]
    return [
        {tool: versions[tool][index] for tool, index in state.items()} for state in block["states"]
    ]


def _field_changes(
    stored: dict[str, Any], shipped: dict[str, Any], defaults: dict[str, Any]
) -> dict[str, Any]:
    """The fields of a whole stored declaration that differ from the shipped one.

    A field the stored declaration leaves out was at its default when it was
    read whole, so where the shipped one sets it, the default is the change.
    """
    out: dict[str, Any] = {}
    for key, value in stored.items():
        if _canon(value) != _canon(shipped.get(key, defaults.get(key))):
            out[key] = value
    for key, value in shipped.items():
        if key not in stored and key in defaults and _canon(value) != _canon(defaults[key]):
            out[key] = defaults[key]
    return out


def per_tool_changes(
    whole: dict[str, Any], block: dict[str, Any], defaults: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    """A map stored whole as its changes per tool, and whether its release was known.

    Linear in the map and the record for each shipped state (a block has a
    handful).
    """
    normal = {tool: _normal(entry, defaults) for tool, entry in whole.items()}
    scored: list[tuple[int, str, dict[str, Any]]] = []
    for state in _states(block):
        changes: dict[str, Any] = {}
        for tool, entry in whole.items():
            shipped = state.get(tool)
            if shipped is not None and _canon(normal[tool]) == _canon(shipped):
                continue
            if shipped is not None and isinstance(entry, dict):
                fields = _field_changes(entry, shipped, defaults)
                if fields:
                    changes[tool] = fields
            else:
                changes[tool] = entry
        removed = [tool for tool in state if tool not in whole]
        for tool in removed:
            changes[tool] = None
        score = sum(1 for tool in whole if tool in changes) + len(removed)
        scored.append((score, _canon(changes), changes))
    best = min(score for score, _text, _changes in scored)
    answers = {text: changes for score, text, changes in scored if score == best}
    if len(answers) == 1:
        return next(iter(answers.values())), True
    every_shipped = {tool for state in _states(block) for tool in state}
    kept = dict(whole)
    for tool in sorted(every_shipped - set(whole)):
        kept[tool] = None
    return kept, False


def whole_map(changes: dict[str, Any], block: dict[str, Any]) -> dict[str, Any]:
    """A block's changes written whole over the last shipped state in the record."""
    last = _states(block)[-1]
    out: dict[str, Any] = {}
    for tool, shipped in last.items():
        if tool not in changes:
            out[tool] = dict(shipped)
        elif isinstance(changes[tool], dict):
            out[tool] = {**shipped, **changes[tool]}
        elif changes[tool] is not None:
            out[tool] = changes[tool]
    for tool, change in changes.items():
        if tool not in last and change is not None:
            out[tool] = change
    return out


def _rows(conn: sa.engine.Connection) -> list[tuple[str, Any]]:
    """Every stored row that may hold a block's tool declarations, decoded; never a secret."""
    result = conn.execute(sa.text("SELECT key, value, is_secret FROM runtime_settings")).fetchall()
    out = []
    for key, value, secret in result:
        if secret:
            continue
        if key != SERVER_MAP_KEY and not (
            key.startswith(CORE_PREFIX) and key.endswith(TOOL_FACTS_SUFFIX)
        ):
            continue
        out.append((key, json.loads(value) if isinstance(value, str) else value))
    return out


def _store(conn: sa.engine.Connection, key: str, value: Any) -> None:
    statement = _UPDATE_PG if conn.dialect.name == "postgresql" else _UPDATE_OTHER
    conn.execute(statement, {"k": key, "v": json.dumps(value)})


def _rewrite(convert: Any) -> bool:
    """Every stored block map passed through ``convert(map, block)``; whether any changed."""
    conn = op.get_bind()
    record = _record()
    blocks = record["blocks"]
    changed = False
    for key, value in _rows(conn):
        if key == SERVER_MAP_KEY:
            if not isinstance(value, dict):
                continue
            servers = dict(value)
            for name, entry in value.items():
                block = blocks.get(f"{SERVER_BLOCK_PREFIX}{name}")
                if block is None or not isinstance(entry, dict):
                    continue
                facts = entry.get("tool_facts")
                if not isinstance(facts, dict):
                    continue
                converted = convert(facts, block)
                # No change of any tool reads as the shipped declarations, as
                # an entry that never set them does.
                servers[name] = (
                    {**entry, "tool_facts": converted}
                    if converted
                    else {k: v for k, v in entry.items() if k != "tool_facts"}
                )
            if servers != value:
                _store(conn, key, servers)
                changed = True
            continue
        block = blocks.get(key[len(CORE_PREFIX) : -len(TOOL_FACTS_SUFFIX)])
        if block is None or not isinstance(value, dict):
            continue
        converted = convert(value, block)
        if converted != value:
            _store(conn, key, converted)
            changed = True
    return changed


def upgrade() -> None:
    defaults = _record()["defaults"]

    def convert(whole: dict[str, Any], block: dict[str, Any]) -> dict[str, Any]:
        # A map naming a removed tool (``null``) was written in the new form
        # already, by a process that ran before this revision: it is kept.
        if any(entry is None for entry in whole.values()):
            return whole
        return per_tool_changes(whole, block, defaults)[0]

    if _rewrite(convert):
        logger.info(REWRITTEN)


def downgrade() -> None:
    _rewrite(whole_map)
