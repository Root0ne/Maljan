"""Every stored agent definition declares the category its role and tools fit.

An agent definition now names what the agent does (``category``: a code
reader, static, dynamic, network, intel or other), separate from the code its
role runs, and the platform offers an agent its own steps by it. The settings
API refuses a new definition without one. A definition stored before the field
existed names none; the settings model reads the category it fits on every
load, and this revision writes that value into the stored document once, so the
console shows it and an operator who changes it keeps the change.

The rule reads the role, the kinds of the tool references and the input slices
a definition names, never its name or the name of a tool or server:

* ``static`` (a class that reads its provider's decompiled functions) is a code
  reader; ``dynamic`` and ``network`` are their own; ``judge`` and ``report``
  are ``other``;
* a ``generic`` or ``lead`` definition holding a ``provider`` reference reads
  code, one holding a ``sandbox`` reference is ``dynamic``, one whose input
  slices are all the sandbox's network capture is ``network`` and one with any
  other sandbox slice ``dynamic``, and one whose tools are only reputation
  capabilities (asks of other agents aside) is ``intel``;
* anything else is ``other``, which is exactly the behaviour it had: the
  platform works its steps out from the agent's tools and what they returned.
  Each such definition is named in the log, so an operator can pick one.

A stored entry under a built-in key is left as it is: the settings model reads
a built-in's category from its seed, and writing one here could only make it
differ. An entry that is not an object, or that names a role this release does
not know, cannot be fitted; it is left as it is and named in the log, and the
settings model refuses it at that key as it did before. A category already
stored is kept, and one that is not a category is named in the log as well. Only the definitions row is written, and only when a category
was added; ``is_secret`` rows are never read. Running it again writes nothing.

The rule is restated here rather than imported from
``maljan.core.agent_category``, as every revision restates what it acts on.

The downgrade writes nothing: the earlier release ignores the field.

Revision ID: 20261103000000
Revises: 20261102000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261103000000"
down_revision = "20261102000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

DEFINITIONS_KEY = "core.agents.definitions"
# How long the row write waits for a lock before the migration fails instead.
LOCK_TIMEOUT = "5s"

# The keys seeded as built-ins on the day this revision ran.
BUILTIN_KEYS = frozenset(
    {
        "static",
        "dynamic",
        "network",
        "judge",
        "reporter",
        "triage",
        "android_static",
        "reverser",
        "lead",
    }
)
CATEGORIES = ("code_reader", "static", "dynamic", "network", "intel", "other")
ROLE_CATEGORIES = {
    "static": "code_reader",
    "dynamic": "dynamic",
    "network": "network",
    "judge": "other",
    "report": "other",
}
TOOL_ROLES = ("generic", "lead")
REPUTATION = "reputation"

_UPSERT_JSON_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, CAST(:v AS JSONB), false) "
    "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB)"
)
_UPSERT_JSON_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, :v, false) "
    "ON CONFLICT (key) DO UPDATE SET value = :v"
)


def _plain_value(conn: sa.engine.Connection, key: str) -> Any:
    """The stored value for ``key``, or ``None``. A secret row is left alone."""
    row = conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None or row[1]:
        return None
    value = row[0]
    return json.loads(value) if isinstance(value, str) else value


def _store(conn: sa.engine.Connection, key: str, value: Any) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": key, "v": json.dumps(value)})


def fitting_category(entry: dict) -> tuple[str | None, bool]:
    """The category ``entry`` fits and whether its role and tools told it.

    ``(None, False)`` for a role this release does not know: it cannot be fitted.
    """
    role = str(entry.get("role") or "")
    if role in ROLE_CATEGORIES:
        return ROLE_CATEGORIES[role], True
    if role not in TOOL_ROLES:
        return None, False
    tools = entry.get("tools")
    refs = [ref for ref in tools if isinstance(ref, dict)] if isinstance(tools, list) else []
    kinds = [str(ref.get("kind") or "") for ref in refs]
    if "provider" in kinds:
        return "code_reader", True
    if "sandbox" in kinds:
        return "dynamic", True
    sources = entry.get("data_sources")
    named = [str(s) for s in sources] if isinstance(sources, list) else []
    if named and all(s == "sandbox.network" for s in named):
        return "network", True
    if any(s.startswith("sandbox.") for s in named):
        return "dynamic", True
    own = [ref for ref in refs if ref.get("kind") != "agent"]
    if own and all(
        ref.get("kind") == "capability" and ref.get("capability") == REPUTATION for ref in own
    ):
        return "intel", True
    return "other", False


def fitted(definitions: dict) -> tuple[dict, list, list, list]:
    """The definitions with a category on each that can be fitted, and what was done.

    Returns the document, the keys given a category, the keys given ``other``
    because nothing told one, and the keys that could not be fitted.
    """
    out: dict = {}
    added: list = []
    untold: list = []
    unfitted: list = []
    for name, entry in definitions.items():
        if name in BUILTIN_KEYS:
            out[name] = entry
            continue
        if not isinstance(entry, dict):
            unfitted.append(str(name))
            out[name] = entry
            continue
        if entry.get("category") is not None:
            # Kept as stored; one that is not a category is named, not replaced.
            if entry["category"] not in CATEGORIES:
                unfitted.append(str(name))
            out[name] = entry
            continue
        category, told = fitting_category(entry)
        if category is None:
            unfitted.append(str(name))
            out[name] = entry
            continue
        out[name] = {**entry, "category": category}
        added.append(str(name))
        if not told:
            untold.append(str(name))
    return out, added, untold, unfitted


def upgrade() -> None:
    conn = op.get_bind()
    definitions = _plain_value(conn, DEFINITIONS_KEY)
    if not isinstance(definitions, dict):
        return
    if conn.dialect.name == "postgresql":
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    document, added, untold, unfitted = fitted(definitions)
    if unfitted:
        logger.warning(
            "runtime_settings: no category could be fitted to the agent definition(s) %s: "
            "the entry is not an object, names a role this release does not know or "
            "a category that is not one. "
            "They are left as they are; fix them in Settings.",
            ", ".join(sorted(unfitted)),
        )
    if not added:
        return
    _store(conn, DEFINITIONS_KEY, document)
    logger.warning(
        "runtime_settings: agent definitions now declare a category: %s.",
        "; ".join(f"{name} -> {document[name]['category']}" for name in sorted(added)),
    )
    if untold:
        logger.warning(
            "runtime_settings: the role and tools of %s tell no category, so each is Other, "
            "which keeps the steps it had. Pick the category that fits in Settings.",
            ", ".join(sorted(untold)),
        )


def downgrade() -> None:
    """Nothing to undo: the earlier release ignores the field."""
