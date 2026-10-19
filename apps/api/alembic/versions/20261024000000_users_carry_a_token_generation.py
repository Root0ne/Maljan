"""Users and API keys carry a token generation.

``users.token_generation`` is the generation every access and refresh token of
the account is minted under (claim ``gen``); ``api_keys.token_generation`` is
the generation a key was created under. A password change or a replayed
refresh token moves the account's generation on, and every token and key from
an earlier generation is refused from then on. Existing rows start at 0, which
is how a token minted before the claim existed reads, so the upgrade signs no
one out and disables no key.

Two added columns with a constant default: Postgres stores the default in the
catalogue and rewrites no row, so the only cost is the ACCESS EXCLUSIVE lock,
bounded by ``LOCK_TIMEOUT`` so a busy table fails the migration rather than
queueing every request behind it.

The downgrade is refused once any account's generation has moved: dropping the
columns would make every token and key revoked since then valid again.

Revision ID: 20261024000000
Revises: 20261023000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261024000000"
down_revision = "20261023000000"
branch_labels = None
depends_on = None

# How long the ALTERs wait for their lock before the migration fails instead.
# Both are catalogue-only changes that hold the lock for milliseconds once they
# have it; a wait longer than this means a long transaction holds the table,
# and the operator is better served by a failed migration to retry than by an
# API stalled behind the queued lock.
LOCK_TIMEOUT = "5s"


def upgrade() -> None:
    op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    op.add_column(
        "users",
        sa.Column("token_generation", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "api_keys",
        sa.Column("token_generation", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    moved = op.get_bind().execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM users WHERE token_generation > 0)")
    )
    if moved.scalar():
        raise RuntimeError(
            "Refusing to downgrade past 20261024000000: some accounts have revoked "
            "sessions or API keys (users.token_generation > 0), and dropping the "
            "column would make those tokens and keys valid again. Revoke them another "
            "way first (rotate JWT_SECRET_KEY and deactivate the keys), then set "
            "token_generation to 0 and retry."
        )
    op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    op.drop_column("api_keys", "token_generation")
    op.drop_column("users", "token_generation")
