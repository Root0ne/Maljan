"""Give the mediator and the summariser their ``llm.agents`` keys in the stored settings.

Two repairs, both written down once.

The function summariser's model is now ``llm.agents.summarizer``, read through
the path every other entry takes. The two settings that claimed to choose it,
``preprocessing.summarizer_provider`` and ``preprocessing.summarizer_model``,
never reached a model: the summariser ran on the global expert model whatever
they held. Their rows are deleted, and no entry is made from them, because an
entry would move a summariser that has always run on the expert model onto a
model it has never called. A stored override naming a setting the catalogue no
longer knows would otherwise be refused on the next import; building the
settings from the store ignores it either way.

``mediator`` and ``summarizer`` are now role keys of ``llm.agents``. An
operator's own agent definition under either name had its model entry under
the same key, which the role would now read as its own. Such a definition is
renamed to ``<key>_custom`` and every reference moves with it, its
``llm.agents`` entry included, exactly as revision 20260917000000 does for a
name a seed took; the rewriting is that revision's, loaded from its file. The
settings model performs the same rename on read, so a database that never
runs this still loads.

An ``llm.agents`` entry under either key with no definition beside it was
left by an agent since deleted: no role read the key before this revision.
It moves to ``<key>_custom`` as well, so the role does not adopt a model the
operator never gave it. Only this revision can tell such an entry from a role
entry, because every entry under the key written after it is the role's.

Downgrade puts a renamed definition or entry back when nothing has since taken
the old name, in the definitions or in ``llm.agents``. The deleted rows are not
restored: they chose nothing.

Revision ID: 20261009000000
Revises: 20261008000000
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import sqlalchemy as sa
from alembic import op

revision = "20261009000000"
down_revision = "20261008000000"
branch_labels = None
depends_on = None

RETIRED_KEYS = (
    "core.preprocessing.summarizer_provider",
    "core.preprocessing.summarizer_model",
)
# Restated rather than imported, as every revision restates what it acts on.
ROLE_KEYS = ("mediator", "summarizer")

_EARLIER = Path(__file__).with_name("20260917000000_rename_colliding_agent_keys.py")


def _rename_revision() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rename_colliding_agent_keys_20260917", _EARLIER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_EARLIER.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": list(RETIRED_KEYS)},
    )

    earlier = _rename_revision()
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    agent_renames = earlier._rename_map(definitions, ROLE_KEYS, set())
    if agent_renames:
        earlier._apply(conn, agent_renames, {})
    moved = {f"agent {old}": new for old, new in agent_renames.items()}
    moved.update(_move_left_behind_entries(earlier, conn))
    if not moved:
        return
    earlier.logger.warning(
        "runtime_settings: renamed off a key a model-calling role now reads: %s. "
        "Find them under the new names in Settings.",
        "; ".join(f"{old} -> {new}" for old, new in sorted(moved.items())),
    )


def _move_left_behind_entries(earlier: ModuleType, conn: sa.engine.Connection) -> dict:
    """Move an entry under a role key that no definition holds, and say where it went.

    Such an entry was left by an agent since deleted: no role read that key
    before this revision, so it is never the role's, and it moves off the key
    as its agent would have. Its new name is free in the definitions and in
    the entries alike.
    """
    llm_agents = earlier._plain_value(conn, earlier.LLM_AGENTS_KEY)
    if not isinstance(llm_agents, dict):
        return {}
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    taken = set(llm_agents) | set(definitions if isinstance(definitions, dict) else {})
    taken |= set(ROLE_KEYS)
    left_behind = {}
    for key in ROLE_KEYS:
        if key in llm_agents:
            new_key = earlier.free_key(key, taken)
            taken.add(new_key)
            left_behind[key] = new_key
    if left_behind:
        earlier._store(conn, earlier.LLM_AGENTS_KEY, earlier._rekey(llm_agents, left_behind))
    return {f"entry {old}": new for old, new in left_behind.items()}


def downgrade() -> None:
    """Put a renamed definition back, when nothing has since taken the old name."""
    earlier = _rename_revision()
    conn = op.get_bind()
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    llm_agents = earlier._plain_value(conn, earlier.LLM_AGENTS_KEY)
    taken = set(llm_agents) if isinstance(llm_agents, dict) else set()

    agent_renames = {}
    if isinstance(definitions, dict):
        for original in ROLE_KEYS:
            renamed = f"{original}{earlier.RENAME_SUFFIX}"
            if renamed in definitions and original not in definitions and original not in taken:
                agent_renames[renamed] = original
    if agent_renames:
        earlier._apply(conn, agent_renames, {})

    # An entry this revision moved on its own, with no definition beside it.
    llm_agents = earlier._plain_value(conn, earlier.LLM_AGENTS_KEY)
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    held = set(definitions) if isinstance(definitions, dict) else set()
    if isinstance(llm_agents, dict):
        back = {}
        for original in ROLE_KEYS:
            renamed = f"{original}{earlier.RENAME_SUFFIX}"
            if renamed in llm_agents and renamed not in held and original not in llm_agents:
                back[renamed] = original
        if back:
            earlier._store(conn, earlier.LLM_AGENTS_KEY, earlier._rekey(llm_agents, back))
