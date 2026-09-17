"""Move an operator's own `lead` agent or `team_lead` team off the seeded names.

The same repair revision 20260917000000 made for `triage`, `android_static`,
`reverser`, `mobile` and `deep_static`, for the two names this release seeds:
the `lead` definition and the `team_lead` team. A stored entry under either
that is not the seed is renamed to `<key>_custom`, and every reference to the
old name moves with it, so a deployment whose operator had a `lead` of their
own upgrades into a service that starts and a console that shows the agent
under its new name.

The settings model performs the same rename on read, so a database that never
runs this still loads; what this adds is that the rename is written down.

The rewriting itself is the earlier revision's, loaded from its file rather
than copied a second time. A revision file is immutable once it has run
anywhere, so this one cannot be broken by a change in the application the way
an import of ``maljan`` could break it.

Revision ID: 20260921000000
Revises: 20260920000000
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic import op

revision = "20260921000000"
down_revision = "20260920000000"
branch_labels = None
depends_on = None

SEEDED_DEFINITIONS = ("lead",)
SEEDED_PROFILES = ("team_lead",)

_EARLIER = Path(__file__).with_name("20260917000000_rename_colliding_agent_keys.py")


def _rename_revision() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rename_colliding_agent_keys_20260917", _EARLIER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_EARLIER.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upgrade() -> None:
    earlier = _rename_revision()
    conn = op.get_bind()
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    profiles = earlier._plain_value(conn, earlier.PROFILES_KEY)

    agent_renames = earlier._rename_map(definitions, SEEDED_DEFINITIONS, set())
    profile_renames = earlier._rename_map(profiles, SEEDED_PROFILES, set())
    if not agent_renames and not profile_renames:
        return

    earlier._apply(conn, agent_renames, profile_renames)
    described = "; ".join(
        [f"agent {old} -> {new}" for old, new in sorted(agent_renames.items())]
        + [f"team {old} -> {new}" for old, new in sorted(profile_renames.items())]
    )
    earlier.logger.warning(
        "runtime_settings: renamed off a key that is now built in: %s. "
        "Find them under the new names in Settings.",
        described,
    )


def downgrade() -> None:
    """Put a renamed key back, when nothing has since taken the old name."""
    earlier = _rename_revision()
    conn = op.get_bind()
    definitions = earlier._plain_value(conn, earlier.DEFINITIONS_KEY)
    profiles = earlier._plain_value(conn, earlier.PROFILES_KEY)

    agent_renames = {}
    if isinstance(definitions, dict):
        for original in SEEDED_DEFINITIONS:
            renamed = f"{original}{earlier.RENAME_SUFFIX}"
            if renamed in definitions and original not in definitions:
                agent_renames[renamed] = original

    profile_renames = {}
    if isinstance(profiles, dict):
        for original in SEEDED_PROFILES:
            renamed = f"{original}{earlier.RENAME_SUFFIX}"
            if renamed in profiles and original not in profiles:
                profile_renames[renamed] = original

    if not agent_renames and not profile_renames:
        return
    earlier._apply(conn, agent_renames, profile_renames)
