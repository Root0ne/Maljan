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

Downgrade puts a renamed definition back when nothing has since taken the old
name, in the definitions or in ``llm.agents``. The deleted rows are not
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
    if not agent_renames:
        return
    earlier._apply(conn, agent_renames, {})
    earlier.logger.warning(
        "runtime_settings: renamed off a key a model-calling role now reads: %s. "
        "Find them under the new names in Settings.",
        "; ".join(f"agent {old} -> {new}" for old, new in sorted(agent_renames.items())),
    )


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
