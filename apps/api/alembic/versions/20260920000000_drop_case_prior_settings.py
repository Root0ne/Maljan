"""Drop the retired preprocessing settings from the stored overrides.

``use_attck_case_rag``, ``attck_case_corpus_path``, ``attck_case_rag_top_k``,
``attck_case_rag_min_score`` and ``attck_case_rag_max_techniques`` gated an
in-process retrieval of ATT&CK techniques from similar prior cases, run
inside the judge node and the static analyst; both are gone, and prior cases
are reached through the knowledge tool ``similar_cases``, which an analyst
calls and cites. ``use_api_behaviour_map`` and ``api_behaviour_map_path``
gated the extractor's labelling of imports, which is gone too: the pack's
``api_capability`` entry reads the catalogue directly. This revision deletes
the seven flat rows. A stored override that names a setting the catalog no
longer knows would otherwise be refused by the settings service on the next
import.

Downgrade restores nothing: the values selected a retrieval that no longer
exists.

Revision ID: 20260920000000
Revises: 20260919000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260920000000"
down_revision = "20260919000000"
branch_labels = None
depends_on = None

_LEAVES = (
    "use_attck_case_rag",
    "attck_case_corpus_path",
    "attck_case_rag_top_k",
    "attck_case_rag_min_score",
    "attck_case_rag_max_techniques",
    "use_api_behaviour_map",
    "api_behaviour_map_path",
)
FLAT_KEYS = tuple(f"core.preprocessing.{name}" for name in _LEAVES)


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": list(FLAT_KEYS)},
    )


def downgrade() -> None:
    pass
