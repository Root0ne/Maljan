"""Make audit_log.user_id nullable so anonymous security events can be recorded.

Audit 2026-07-26 (K1). The ORM model declares
``user_id: Mapped[uuid.UUID | None] = mapped_column(..., nullable=True)``
(``app/models/audit.py``) and ``app/api/v1/auth.py`` deliberately writes
``user_id=None`` for the security events that have no authenticated principal:

    * ``auth.login.failure``          — a failed login for an unknown e-mail
    * ``auth.login.locked``           — a brute-force lockout
    * ``auth.refresh.invalid``        — an unparseable / wrong-type refresh token
    * ``auth.refresh.reuse_detected`` — a replayed refresh token (token theft)

The original schema (20250505000000) created the column ``NOT NULL``, so every
one of those INSERTs raised an IntegrityError and was rolled back. Combined with
the request-scoped session (fixed separately), the result was that the security
audit trail contained ONLY successful ``auth.login.success`` /``auth.register``
rows — a brute-force attempt left no trace at all. Verified live against the
database before this migration.

Aligning the column with the model is what makes the anonymous-event audit trail
actually persist.

Revision ID: 20260726000000
Revises: 20250524000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260726000000"
down_revision = "20250524000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "audit_log",
        "user_id",
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=True,
    )


def downgrade() -> None:
    # Anonymous rows must go before the NOT NULL constraint can be restored,
    # otherwise the ALTER fails on existing data.
    op.execute("DELETE FROM audit_log WHERE user_id IS NULL")
    op.alter_column(
        "audit_log",
        "user_id",
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=False,
    )
